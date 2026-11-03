// SPDX-License-Identifier: Apache-2.0
//! KryProbe-shaped standalone adapter over insertion/counter/loss primitives.
//!
//! NEW (CP11): reference-only; no donor lines copied. Each scenario composes
//! exact packaged `scopebase-capture` calls with this consumer's own fixed
//! script constants. Capture contract refusals are observed data encoded as
//! `refuse=<Variant>;`; only adapter-level failures (missing slot, unknown
//! operation, malformed script) become `CaseError`, as `InvalidOutput`
//! (S44; observation-bounds stays an operational `Refused`).
use scopebase_capture::{
    correction::{Correction, Revision, Versioned},
    counter::{sample_delta, CounterPolicy, Delta, DeltaUnknown, Sample},
    domain::{BindingId, CaptureId, ChannelId, ClockDomain, Epoch, Origin, ProducerId, SourceRef},
    holder::HolderPair,
    loss::{fold_capped_signals, LossFact, LossKind, LossMagnitude},
    provenance::{
        fold_insertion_identity, LaneIdentity, ProvenanceLane,
    },
    quantity::{Bytes, Count, Events},
    time::{TimeInterval, Timestamp},
    ContractError,
};
use scopebase_testkit::{
    BindingProvenance, CaseError, CaseErrorCategory, CaseErrorValues, CaseInvocation,
    ConformanceAdapter, ConsumerBinding, ConsumerBindingValues, Digest256, EffectBatch,
    EvidenceTier, FixtureAccess, HarnessError, Label, Observation, ObservationValues, RefusalCause,
    RefusalEvidence, RefusalEvidenceValues, RetireRequest, RetirementReport,
    RetirementReportValues, RunLimits, SubjectBinding, SubjectBindingValues,
};

const PACKAGE: &str = "capture-kryprobe-reference";
const CONSUMER: &str = "kryprobe-adapter";
const SCHEMA_ID: &str = "kryprobe-reference-v1";
const SCHEMA_REVISION: u32 = 1;
const FIXTURE_SCHEMA_ID: &str = "kryprobe-fixture-v1";
const FIXTURE_SCHEMA_REVISION: u32 = 1;
const SCRIPT_SCHEMA_ID: &str = "kryprobe-script";

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

/// KryProbe-shaped reference adapter: insertion folds, counter deltas,
/// capped signals, loss facts, feed presence and correction holders.
pub struct KryprobeReferenceAdapter {
    limits: RunLimits,
    subject: SubjectBinding,
    // RB4 (R02): fixed dialect labels parsed once at construction and
    // truncated per invocation ceiling at use. The per-invocation path
    // carries no Label::parse expect and honors the live ceiling,
    // never the adapter default.
    schema: Label,
    method_execute: Label,
    stage_schema: Label,
    stage_admission: Label,
    stage_collect: Label,
    slot_script: Label,
}

impl KryprobeReferenceAdapter {
    /// Build the adapter with its self-reported development subject binding.
    pub fn new() -> Result<Self, HarnessError> {
        let limits = RunLimits::default();
        let digest = Digest256::of_bytes(b"CP11 capture-kryprobe-reference subject v1");
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
            stage_schema: Label::parse("adapter-schema").expect("CP11:fixed stage parses"),
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

    // S44: missing/malformed operation data after dialect admission
    // is InvalidOutput (attempted step set, cause Unknown), never an
    // operational Refused. Operational refusals keep `refusal` below.
    fn invalid_output(
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
                stage: stage.truncate(l.label_bytes()),
                category: CaseErrorCategory::InvalidOutput,
                errno: None,
                diagnostic_bytes: fit_bytes(diagnostic.as_bytes(), l.diagnostic_bytes()),
                cause: self.cause(l),
                completed_steps: Vec::new(),
                partial_observation: None,
                effects: EffectBatch::empty(l),
            },
            l,
        )
        .expect("S44:pre-fitted invalid-output fits invocation limits")
    }

    // S34 (R33): dialect rejection before any slot read or effect.
    // Alien schemas, wrong arity/shape and unknown opcodes never
    // reach operation matching: UnsupportedSchema, like the Linux
    // reference adapters.
    fn unsupported(&self, invocation: &CaseInvocation, diagnostic: &str) -> CaseError {
        let l = invocation.limits();
        CaseError::new(
            CaseErrorValues {
                key: invocation.key().clone(),
                step_id: None,
                stage: self.stage_schema.truncate(l.label_bytes()),
                category: CaseErrorCategory::UnsupportedSchema,
                errno: None,
                diagnostic_bytes: fit_bytes(diagnostic.as_bytes(), l.diagnostic_bytes()),
                cause: self.cause(l),
                completed_steps: Vec::new(),
                partial_observation: None,
                effects: EffectBatch::empty(l),
            },
            l,
        )
        .expect("CP11:pre-fitted dialect rejection fits invocation limits")
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

impl ConformanceAdapter for KryprobeReferenceAdapter {
    fn subject(&self) -> SubjectBinding {
        self.subject.clone()
    }

    fn execute(
        &mut self,
        invocation: &CaseInvocation,
        fixture: &FixtureAccess<'_>,
    ) -> Result<Observation, CaseError> {
        // S34 (R33): entire-script preflight before any slot read
        // or effect. Schema, step count, parameters and declared
        // inputs validate here; malformed scripts stay InvalidOutput
        // below (S44), while dialect mismatches refuse above as
        // UnsupportedSchema.
        if invocation.observation_schema().id().as_str() != SCHEMA_ID
            || *invocation.observation_schema().revision() != SCHEMA_REVISION
        {
            return Err(self.unsupported(invocation, "CP11:unsupported observation schema"));
        }
        if invocation.fixture_schema().id().as_str() != FIXTURE_SCHEMA_ID
            || *invocation.fixture_schema().revision() != FIXTURE_SCHEMA_REVISION
        {
            return Err(self.unsupported(invocation, "CP11:unsupported fixture schema"));
        }
        if invocation.script().schema_id().as_str() != SCRIPT_SCHEMA_ID {
            return Err(self.unsupported(invocation, "CP11:unsupported script schema"));
        }
        let [step] = invocation.script().steps() else {
            return Err(self.unsupported(invocation, "CP11:exactly one step"));
        };
        if !step.parameters().is_empty() {
            return Err(self.unsupported(invocation, "CP11:step takes no parameters"));
        }
        let op = step.operation().as_str();
        if !is_known_op(op) {
            // S34: an unknown opcode is a dialect this adapter does
            // not speak: pre-read UnsupportedSchema, like an alien
            // script id — before any slot is touched.
            return Err(self.unsupported(invocation, "CP11:unknown operation"));
        }
        let mut declared: Vec<&str> = step.inputs().iter().map(|i| i.as_str()).collect();
        declared.sort_unstable();
        if declared != ["script"] {
            return Err(self.unsupported(invocation, "CP11:unsupported step shape"));
        }
        let Some(raw) = fixture.input(&self.slot_script) else {
            return Err(self.invalid_output(
                invocation,
                Some(step.step_id().clone()),
                &self.stage_admission,
                "CP11:missing script slot",
            ));
        };
        let Some(case) = parse_case(raw) else {
            return Err(self.invalid_output(
                invocation,
                Some(step.step_id().clone()),
                &self.stage_admission,
                "CP11:malformed script",
            ));
        };
        // S34: the operation admitted above, so a missing outcome
        // is unknown case data, never an unknown opcode.
        let Some(outcome) = run_scenario(op, case) else {
            return Err(self.invalid_output(
                invocation,
                Some(step.step_id().clone()),
                &self.stage_admission,
                "CP11:unknown case",
            ));
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
    matches!(
        op,
        "fold" | "bytes" | "feed" | "signals" | "delta" | "holder"
    )
}

fn parse_case(raw: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut parts = text.split(';');
    let name = parts.next()?.strip_prefix("case=")?;
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
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
        CaptureId::new([11; 16])?,
        ProducerId::new([12; 16])?,
        0,
    ))
}

fn source() -> Result<SourceRef, ContractError> {
    Ok(SourceRef::new(
        epoch()?,
        BindingId::new([13; 32])?,
        Origin::Synthetic,
    ))
}

fn lane(identity: LaneIdentity<u64>, count: u64) -> ProvenanceLane<u64, Events> {
    ProvenanceLane::new(identity, Count::new(count))
}

/// Run one operation/case scenario. `None` names an unknown operation or case.
pub fn run_scenario(op: &str, case: &str) -> Option<Result<String, ContractError>> {
    match (op, case) {
        ("fold", "ok") => Some(fold_ok()),
        ("fold", "duplicate-owner") => Some(fold_duplicate_owner()),
        ("fold", "saturated") => Some(fold_saturated()),
        ("fold", "missing-owner") => Some(fold_missing_owner()),
        ("bytes", "survive") => Some(bytes_survive()),
        ("feed", "missing") => Some(feed_case(false)),
        ("feed", "complete") => Some(feed_case(true)),
        ("signals", "fold") => Some(signals_fold()),
        ("signals", "over-cap") => Some(signals_over_cap()),
        ("delta", "ok") => Some(delta_ok()),
        ("delta", "missing-baseline") => Some(delta_missing_baseline()),
        ("delta", "decrease") => Some(delta_decrease()),
        ("delta", "overlap") => Some(delta_overlap()),
        ("holder", "agree") => Some(holder_agree()),
        ("holder", "dropped") => Some(holder_dropped()),
        ("holder", "stale") => Some(holder_stale()),
        _ => None,
    }
}

fn fold_ok() -> Result<String, ContractError> {
    let lanes = vec![
        lane(LaneIdentity::InsertionOwner(7), 6),
        lane(LaneIdentity::Secondary, 4),
    ];
    let fold = fold_insertion_identity(&lanes)?;
    Ok(format!(
        "total={};owner={};",
        fold.total().get(),
        fold.identity()
    ))
}

fn fold_duplicate_owner() -> Result<String, ContractError> {
    let lanes = vec![
        lane(LaneIdentity::InsertionOwner(7), 6),
        lane(LaneIdentity::InsertionOwner(8), 4),
    ];
    let fold = fold_insertion_identity(&lanes)?;
    Ok(format!("total={};", fold.total().get()))
}

fn fold_saturated() -> Result<String, ContractError> {
    let lanes = vec![
        ProvenanceLane::saturated(LaneIdentity::InsertionOwner(7)),
        lane(LaneIdentity::Secondary, 4),
    ];
    let fold = fold_insertion_identity(&lanes)?;
    Ok(format!("total={};", fold.total().get()))
}

fn fold_missing_owner() -> Result<String, ContractError> {
    let lanes = vec![
        lane(LaneIdentity::Secondary, 6),
        lane(LaneIdentity::Secondary, 4),
    ];
    let fold = fold_insertion_identity(&lanes)?;
    Ok(format!("total={};", fold.total().get()))
}

fn bytes_survive() -> Result<String, ContractError> {
    let bytes = Count::<Bytes>::new(5);
    let loss = LossFact::new(
        source()?,
        ChannelId::new(0),
        LossKind::Transport,
        LossMagnitude::<Events>::Unknown,
    )?;
    let magnitude = match loss.magnitude() {
        LossMagnitude::Unknown => "unknown",
        LossMagnitude::Exact(_) => "exact",
        LossMagnitude::AtLeast(_) => "at-least",
        _ => "other",
    };
    Ok(format!("bytes={};magnitude={magnitude};", bytes.get()))
}

fn feed_case(complete: bool) -> Result<String, ContractError> {
    use scopebase_capture::feeds::FeedRegistry;
    let mut registry = FeedRegistry::new(epoch()?, &[ChannelId::new(0), ChannelId::new(1)], 4)?;
    let src = source()?;
    let fact = |channel: u32| {
        LossFact::new(
            src.clone(),
            ChannelId::new(channel),
            LossKind::Transport,
            LossMagnitude::<Events>::Unknown,
        )
    };
    registry.feed(&fact(0)?)?;
    if complete {
        registry.feed(&fact(1)?)?;
    }
    registry.finish()?;
    Ok("feeds=complete;".to_string())
}

fn signals_fold() -> Result<String, ContractError> {
    Ok(format!("fold={};", fold_capped_signals(&[3, 4], 10)?))
}

fn signals_over_cap() -> Result<String, ContractError> {
    Ok(format!("fold={};", fold_capped_signals(&[11], 10)?))
}

fn sample(start: u64, end: u64, value: u64) -> Result<Sample<Events>, ContractError> {
    let clock = ClockDomain::new([14; 16])?;
    Sample::new(
        source()?,
        ChannelId::new(5),
        CounterPolicy::Monotonic,
        TimeInterval::new(Timestamp::new(clock, start), Timestamp::new(clock, end))?,
        Count::new(value),
    )
}

fn delta_name(delta: &Delta<Events>) -> String {
    match delta {
        Delta::Exact(count) => format!("exact:{}", count.get()),
        Delta::AtLeast(count) => format!("at-least:{}", count.get()),
        Delta::Unknown(reason) => format!("unknown:{}", delta_unknown_name(reason)),
        _ => "other".to_string(),
    }
}

fn delta_unknown_name(reason: &DeltaUnknown) -> &'static str {
    match reason {
        DeltaUnknown::MissingBaseline => "MissingBaseline",
        DeltaUnknown::ResetOrWrap => "ResetOrWrap",
        DeltaUnknown::PartialRead => "PartialRead",
        DeltaUnknown::Saturated => "Saturated",
        DeltaUnknown::UnboundedWrap => "UnboundedWrap",
        _ => "Other",
    }
}

fn delta_ok() -> Result<String, ContractError> {
    let baseline = sample(0, 1, 3)?;
    let current = sample(1, 2, 8)?;
    Ok(format!(
        "delta={};",
        delta_name(&sample_delta(Some(&baseline), &current, None)?)
    ))
}

fn delta_missing_baseline() -> Result<String, ContractError> {
    let current = sample(1, 2, 8)?;
    Ok(format!(
        "delta={};",
        delta_name(&sample_delta(None, &current, None)?)
    ))
}

fn delta_decrease() -> Result<String, ContractError> {
    let baseline = sample(0, 1, 8)?;
    let current = sample(1, 2, 3)?;
    Ok(format!(
        "delta={};",
        delta_name(&sample_delta(Some(&baseline), &current, None)?)
    ))
}

fn delta_overlap() -> Result<String, ContractError> {
    let baseline = sample(0, 2, 3)?;
    let current = sample(1, 3, 8)?;
    Ok(format!(
        "delta={};",
        delta_name(&sample_delta(Some(&baseline), &current, None)?)
    ))
}

fn holder_pair() -> Result<HolderPair<u64>, ContractError> {
    Ok(HolderPair::new(
        Versioned::new(epoch()?, 10u64),
        Versioned::new(epoch()?, 10u64),
    ))
}

fn is_rev1(revision: Revision) -> bool {
    revision == Revision::new(1)
}

fn holder_agree() -> Result<String, ContractError> {
    let mut pair = holder_pair()?;
    pair.apply_report(Correction::new(epoch()?, Revision::new(0), 7u64)?)?;
    pair.apply_export(Correction::new(epoch()?, Revision::new(0), 7u64)?)?;
    Ok(format!(
        "report_rev1={};export_rev1={};report_value={};export_value={};agree={};",
        is_rev1(pair.report().revision()),
        is_rev1(pair.export().revision()),
        pair.report().value(),
        pair.export().value(),
        pair.agree()
    ))
}

fn holder_dropped() -> Result<String, ContractError> {
    let mut pair = holder_pair()?;
    pair.apply_report(Correction::new(epoch()?, Revision::new(0), 7u64)?)?;
    Ok(format!(
        "report_rev1={};export_rev1={};report_value={};export_value={};agree={};diverged={};",
        is_rev1(pair.report().revision()),
        is_rev1(pair.export().revision()),
        pair.report().value(),
        pair.export().value(),
        pair.agree(),
        pair.divergence().is_some()
    ))
}

fn holder_stale() -> Result<String, ContractError> {
    let mut pair = holder_pair()?;
    pair.apply_report(Correction::new(epoch()?, Revision::new(0), 7u64)?)?;
    match pair.apply_report(Correction::new(epoch()?, Revision::new(0), 5u64)?) {
        Err(ContractError::StaleRevision) => Ok(format!(
            "refuse=StaleRevision;report_value={};",
            pair.report().value()
        )),
        Err(other) => Err(other),
        Ok(()) => Ok("unexpected-accept;".to_string()),
    }
}
