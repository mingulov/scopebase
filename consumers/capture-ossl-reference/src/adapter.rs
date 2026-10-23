// SPDX-License-Identifier: Apache-2.0
//! OSSL-shaped standalone adapter over alternative bounds and corrections.
//!
//! NEW (CP11): reference-only; no donor lines copied. Each scenario composes
//! exact packaged `scopebase-capture` calls with this consumer's own fixed
//! script constants. Capture contract refusals are observed data encoded as
//! `refuse=<Variant>;`; only adapter-level failures (missing slot, unknown
//! operation, malformed script) become `CaseError`.
use scopebase_capture::{
    bounds::{classify_alternatives, combine_disjoint_sites, CandidateCoverage, MatchClass, SiteCount},
    correction::{Correction, Revision, Versioned},
    domain::{
        BindingId, CaptureId, ChannelId, Epoch, Origin, PhysicalSiteId, ProducerId, SourceRef,
    },
    feeds::FeedRegistry,
    holder::HolderPair,
    loss::{LossFact, LossKind, LossMagnitude},
    neutral::{
        validate_v1, NeutralClaim, NeutralCorrection, NeutralCounter, NeutralLimits, NeutralLoss,
        NeutralLossKind, NeutralMagnitude, NeutralObservationV1, NeutralOrigin, NeutralPartition,
        NeutralPolicy, NeutralReason, NeutralSignal, NeutralSource, NeutralUnit,
    },
    quantity::{Count, CountBounds, Events},
    ContractError,
};
use scopebase_testkit::{
    BindingProvenance, CaseError, CaseErrorCategory, CaseErrorValues, CaseInvocation,
    ConformanceAdapter, ConsumerBinding, ConsumerBindingValues, Digest256, EffectBatch,
    EvidenceTier, FixtureAccess, HarnessError, Label, Observation, ObservationValues,
    RefusalCause, RefusalEvidence, RefusalEvidenceValues, RetireRequest, RetirementReport,
    RetirementReportValues, RunLimits, SubjectBinding, SubjectBindingValues,
};

const PACKAGE: &str = "capture-ossl-reference";
const CONSUMER: &str = "ossl-adapter";
const SCHEMA_ID: &str = "ossl-reference-v1";
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

/// OSSL-shaped reference adapter: alternative site bounds, neutral
/// validation with versioned late corrections, feed presence and
/// correction holders.
pub struct OsslReferenceAdapter {
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

impl OsslReferenceAdapter {
    /// Build the adapter with its self-reported development subject binding.
    pub fn new() -> Result<Self, HarnessError> {
        let limits = RunLimits::default();
        let digest = Digest256::of_bytes(b"CP11 capture-ossl-reference subject v1");
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

impl ConformanceAdapter for OsslReferenceAdapter {
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
    matches!(op, "bounds" | "neutral" | "feed" | "holder")
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
        CaptureId::new([31; 16])?,
        ProducerId::new([32; 16])?,
        5,
    ))
}

fn source() -> Result<SourceRef, ContractError> {
    Ok(SourceRef::new(
        epoch()?,
        BindingId::new([33; 32])?,
        Origin::Replayed,
    ))
}

/// Run one operation/case scenario. `None` names an unknown operation or case.
pub fn run_scenario(op: &str, case: &str) -> Option<Result<String, ContractError>> {
    match (op, case) {
        ("bounds", "shared") => Some(bounds_classes(&[
            MatchClass::Definite,
            MatchClass::Possible,
        ])),
        ("bounds", "definite") => Some(bounds_classes(&[
            MatchClass::Definite,
            MatchClass::Definite,
        ])),
        ("bounds", "excluded") => Some(bounds_classes(&[
            MatchClass::Excluded,
            MatchClass::Excluded,
        ])),
        ("bounds", "unknown") => Some(bounds_unknown(10)),
        ("bounds", "zero-unknown") => Some(bounds_unknown(0)),
        ("bounds", "alias-multiply") => Some(bounds_alias_multiply()),
        ("bounds", "combine") => Some(bounds_combine()),
        ("bounds", "empty-complete") => Some(bounds_empty_complete()),
        ("bounds", "class-mismatch") => Some(bounds_class_mismatch()),
        ("neutral", "ok") => Some(neutral_case(NeutralCase::Ok)),
        ("neutral", "bad-correction") => Some(neutral_case(NeutralCase::BadCorrection)),
        ("neutral", "dup-channel") => Some(neutral_case(NeutralCase::DupChannel)),
        ("neutral", "bad-partition") => Some(neutral_case(NeutralCase::BadPartition)),
        ("feed", "missing") => Some(feed_case(false)),
        ("feed", "complete") => Some(feed_case(true)),
        ("holder", "agree") => Some(holder_agree()),
        ("holder", "dropped") => Some(holder_dropped()),
        ("holder", "stale") => Some(holder_stale()),
        _ => None,
    }
}

fn site(site: u64, count: u64, candidates: Vec<u32>) -> Result<SiteCount<u32>, ContractError> {
    SiteCount::new(
        epoch()?,
        PhysicalSiteId::new(site),
        Count::new(count),
        CandidateCoverage::Complete(candidates),
        8,
    )
}

fn bound_text(bound: &CountBounds<Events>) -> String {
    let upper = bound
        .upper()
        .map(|count| count.get().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    format!("lower={};upper={upper};", bound.lower().get())
}

fn bounds_classes(classes: &[MatchClass]) -> Result<String, ContractError> {
    let site = site(9, 10, vec![11, 12])?;
    Ok(bound_text(&classify_alternatives(&site, classes)?))
}

fn bounds_unknown(count: u64) -> Result<String, ContractError> {
    let site: SiteCount<u32> = SiteCount::new(
        epoch()?,
        PhysicalSiteId::new(9),
        Count::new(count),
        CandidateCoverage::Unknown,
        8,
    )?;
    Ok(bound_text(&classify_alternatives(&site, &[])?))
}

fn bounds_alias_multiply() -> Result<String, ContractError> {
    let first = site(9, 10, vec![11])?;
    let second = site(9, 10, vec![12])?;
    let bound_first = classify_alternatives(&first, &[MatchClass::Definite])?;
    let bound_second = classify_alternatives(&second, &[MatchClass::Definite])?;
    let combined = combine_disjoint_sites(&[first, second], &[bound_first, bound_second])?;
    Ok(bound_text(&combined))
}

fn bounds_combine() -> Result<String, ContractError> {
    let shared = site(9, 10, vec![11])?;
    let owned = site(10, 10, vec![12])?;
    let bound_shared = classify_alternatives(&shared, &[MatchClass::Possible])?;
    let bound_owned = classify_alternatives(&owned, &[MatchClass::Definite])?;
    let combined = combine_disjoint_sites(&[shared, owned], &[bound_shared, bound_owned])?;
    Ok(bound_text(&combined))
}

fn bounds_empty_complete() -> Result<String, ContractError> {
    let site = site(9, 10, Vec::new())?;
    Ok(bound_text(&classify_alternatives(&site, &[])?))
}

fn bounds_class_mismatch() -> Result<String, ContractError> {
    let site = site(9, 10, vec![11, 12])?;
    Ok(bound_text(&classify_alternatives(
        &site,
        &[MatchClass::Definite],
    )?))
}

#[derive(Clone, Copy)]
enum NeutralCase {
    Ok,
    BadCorrection,
    DupChannel,
    BadPartition,
}

fn neutral_observation(case: NeutralCase) -> NeutralObservationV1 {
    let counter = |channel: u32| NeutralCounter {
        channel,
        policy: NeutralPolicy::Monotonic,
        clock: [34; 16],
        start: 0,
        end: 1,
        value: 5,
        unit: NeutralUnit::Events,
    };
    let counters = match case {
        NeutralCase::DupChannel => vec![counter(0), counter(0)],
        _ => vec![counter(0)],
    };
    let partitions = match case {
        NeutralCase::BadPartition => vec![NeutralPartition {
            total: 5,
            parts: vec![2, 2],
            unit: NeutralUnit::Events,
        }],
        _ => vec![NeutralPartition {
            total: 5,
            parts: vec![2, 3],
            unit: NeutralUnit::Events,
        }],
    };
    let corrections = match case {
        NeutralCase::BadCorrection => vec![NeutralCorrection { from: 1, to: 2 }],
        _ => vec![NeutralCorrection { from: 0, to: 1 }],
    };
    NeutralObservationV1 {
        source: NeutralSource {
            capture: [31; 16],
            producer: [32; 16],
            ordinal: 5,
            binding: [33; 32],
            origin: NeutralOrigin::Synthetic,
        },
        unit: NeutralUnit::Events,
        counters,
        losses: vec![NeutralLoss {
            channel: 1,
            kind: NeutralLossKind::Transport,
            magnitude: NeutralMagnitude::Exact(2),
            unit: NeutralUnit::Events,
        }],
        signals: vec![NeutralSignal {
            channel: 2,
            observed: 3,
            cap: 9,
            unit: NeutralUnit::DiagnosticSignals,
        }],
        claims: vec![NeutralClaim {
            claim: 1,
            reasons: vec![NeutralReason::ConsumedLoss],
        }],
        partitions,
        corrections,
    }
}

fn neutral_case(case: NeutralCase) -> Result<String, ContractError> {
    let validated = validate_v1(&neutral_observation(case), NeutralLimits::default())?;
    Ok(format!(
        "counters={};losses={};signals={};claims={};partitions={};corrections={};",
        validated.counters().len(),
        validated.losses().len(),
        validated.signals().len(),
        validated.claims().len(),
        validated.partition_count(),
        validated.correction_count()
    ))
}

fn feed_case(complete: bool) -> Result<String, ContractError> {
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

fn holder_pair() -> Result<HolderPair<CountBounds<Events>>, ContractError> {
    let initial = CountBounds::new(Count::new(0), Some(Count::new(10)))?;
    Ok(HolderPair::new(
        Versioned::new(epoch()?, initial.clone()),
        Versioned::new(epoch()?, initial),
    ))
}

fn corrected() -> Result<CountBounds<Events>, ContractError> {
    CountBounds::new(Count::new(10), Some(Count::new(10)))
}

fn is_rev1(revision: Revision) -> bool {
    revision == Revision::new(1)
}

fn bound_pair(bound: &CountBounds<Events>) -> String {
    let upper = bound
        .upper()
        .map(|count| count.get().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    format!("{}+{upper}", bound.lower().get())
}

fn holder_agree() -> Result<String, ContractError> {
    let mut pair = holder_pair()?;
    pair.apply_report(Correction::new(epoch()?, Revision::new(0), corrected()?)?)?;
    pair.apply_export(Correction::new(epoch()?, Revision::new(0), corrected()?)?)?;
    Ok(format!(
        "report_rev1={};export_rev1={};report={};export={};agree={};",
        is_rev1(pair.report().revision()),
        is_rev1(pair.export().revision()),
        bound_pair(pair.report().value()),
        bound_pair(pair.export().value()),
        pair.agree()
    ))
}

fn holder_dropped() -> Result<String, ContractError> {
    let mut pair = holder_pair()?;
    pair.apply_report(Correction::new(epoch()?, Revision::new(0), corrected()?)?)?;
    Ok(format!(
        "report_rev1={};export_rev1={};report={};export={};agree={};diverged={};",
        is_rev1(pair.report().revision()),
        is_rev1(pair.export().revision()),
        bound_pair(pair.report().value()),
        bound_pair(pair.export().value()),
        pair.agree(),
        pair.divergence().is_some()
    ))
}

fn holder_stale() -> Result<String, ContractError> {
    let mut pair = holder_pair()?;
    pair.apply_report(Correction::new(epoch()?, Revision::new(0), corrected()?)?)?;
    match pair.apply_report(Correction::new(epoch()?, Revision::new(0), corrected()?)?) {
        Err(ContractError::StaleRevision) => Ok(format!(
            "refuse=StaleRevision;report={};",
            bound_pair(pair.report().value())
        )),
        Err(other) => Err(other),
        Ok(()) => Ok("unexpected-accept;".to_string()),
    }
}
