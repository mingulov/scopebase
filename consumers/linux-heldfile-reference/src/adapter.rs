// SPDX-License-Identifier: Apache-2.0
//! Held-file inspector standalone adapter over file/procfs/walk surfaces.
//!
//! NEW (LX11): reference-only; no donor lines copied. Each scenario composes
//! exact packaged `scopebase-linux` calls with this consumer's own fixed
//! script constants. Linux contract refusals are observed data encoded as
//! `refuse=<Stage>:<Reason>[:line=N];` via the developer conformance API;
//! only adapter-level failures (missing slot, unknown operation, malformed
//! script, missing parameter) become `CaseError`.
use scopebase_linux::{
    conformance::{refusal_of, ExpectedLedger},
    control::{CancelToken, OperationControl},
    file::{HeldFile, ProcFdResolver, ReadLimits, SymlinkPolicy},
    procfs::{parse_maps, parse_mountinfo, ParseLimits},
    walk::{walk, HeldDirectory, WalkBudget, WalkEpoch, WalkLimits, WalkPolicy},
};
use scopebase_testkit::{
    BindingProvenance, CaseError, CaseErrorCategory, CaseErrorValues, CaseInvocation,
    ConformanceAdapter, ConsumerBinding, ConsumerBindingValues, Digest256, EffectBatch,
    EvidenceTier, FixtureAccess, HarnessError, Label, Observation, ObservationValues, RefusalCause,
    RefusalEvidence, RefusalEvidenceValues, RetireRequest, RetirementReport,
    RetirementReportValues, RunLimits, SubjectBinding, SubjectBindingValues,
};
use std::path::Path;

const PACKAGE: &str = "linux-heldfile-reference";
const CONSUMER: &str = "heldfile-adapter";
const SCHEMA_ID: &str = "heldfile-reference-v1";
const SCHEMA_REVISION: u32 = 1;
const FIXTURE_SCHEMA_ID: &str = "heldfile-fixture-v1";
const FIXTURE_SCHEMA_REVISION: u32 = 1;

/// F26: truncate a byte payload to an invocation byte ceiling.
fn fit_bytes(bytes: &[u8], ceiling: u64) -> Vec<u8> {
    let max = ceiling.min(usize::MAX as u64) as usize;
    bytes.iter().take(max).copied().collect()
}

/// F26: truncate a completed-step list to the invocation step ceiling.
fn fit_steps(steps: Vec<Label>, limits: &RunLimits) -> Vec<Label> {
    let max = limits
        .steps_per_invocation()
        .min(usize::MAX as u64) as usize;
    steps.into_iter().take(max).collect()
}

/// Held-file inspector reference adapter: real open/stat, bounded reads,
/// strict maps/mountinfo parses and bounded walks over explicit paths.
pub struct HeldfileReferenceAdapter {
    limits: RunLimits,
    subject: SubjectBinding,
    schema: Label,
    method_execute: Label,
    stage_dispatch: Label,
    stage_admission: Label,
    stage_collect: Label,
    stage_schema: Label,
    slot_script: Label,
    slot_body: Label,
}

impl HeldfileReferenceAdapter {
    /// Build the adapter with its self-reported development subject binding.
    pub fn new() -> Result<Self, HarnessError> {
        let limits = RunLimits::default();
        let digest = Digest256::of_bytes(b"LX11 linux-heldfile-reference subject v1");
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
                    reason: "LX11 standalone reference consumer; self-reported development binding"
                        .to_string(),
                },
            },
            &limits,
        )?;
        // F26: fixed dialect labels parse once at construction, so the
        // per-invocation path carries no Label::parse expect. These expects
        // can only fire on a mistyped constant (a programming error every
        // construction test exercises); Label::parse has no HarnessError
        // conversion, so a fallible parse here is inexpressible.
        Ok(Self {
            limits,
            subject,
            schema: Label::parse(SCHEMA_ID).expect("LX11:fixed schema parses"),
            method_execute: Label::parse("execute").expect("LX11:fixed label parses"),
            stage_dispatch: Label::parse("dispatch").expect("LX11:fixed stage parses"),
            stage_admission: Label::parse("admission").expect("LX11:fixed stage parses"),
            stage_collect: Label::parse("collect").expect("LX11:fixed stage parses"),
            stage_schema: Label::parse("adapter-schema").expect("LX11:fixed stage parses"),
            slot_script: Label::parse("script").expect("LX11:fixed slot parses"),
            slot_body: Label::parse("body").expect("LX11:fixed slot parses"),
        })
    }

    // F26: every response is built under the invocation's own limits with
    // pre-fitted payloads, never under the adapter's default limits.
    // RB4 (R07): the body travels whole; an over-ceiling body refuses at
    // collect instead of truncating. The schema id is identity (refuse
    // on over), not fitted metadata.
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

    // F27: envelope-shape rejection. The UnsupportedSchema validator
    // requires step None, no completed steps, no partial observation,
    // no errno and an Unknown cause; this constructor holds that shape.
    fn unsupported(&self, invocation: &CaseInvocation, diagnostic: &str) -> CaseError {
        let l = invocation.limits();
        CaseError::new(
            CaseErrorValues {
                key: invocation.key().clone(),
                step_id: None,
                // RB4 (R02): fitted stage tag (see cause).
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
        .expect("LX11:pre-fitted dialect rejection fits invocation limits")
    }
}

impl ConformanceAdapter for HeldfileReferenceAdapter {
    fn subject(&self) -> SubjectBinding {
        self.subject.clone()
    }

    fn execute(
        &mut self,
        invocation: &CaseInvocation,
        fixture: &FixtureAccess<'_>,
    ) -> Result<Observation, CaseError> {
        // F27: envelope preflight before any slot read or effect. Schema,
        // step count, parameters and declared inputs are validated here;
        // unknown operations and malformed scripts stay Refused below.
        if invocation.observation_schema().id().as_str() != SCHEMA_ID
            || *invocation.observation_schema().revision() != SCHEMA_REVISION
        {
            return Err(self.unsupported(invocation, "LX11:unsupported observation schema"));
        }
        if invocation.fixture_schema().id().as_str() != FIXTURE_SCHEMA_ID
            || *invocation.fixture_schema().revision() != FIXTURE_SCHEMA_REVISION
        {
            return Err(self.unsupported(invocation, "LX11:unsupported fixture schema"));
        }
        let [step] = invocation.script().steps() else {
            return Err(self.unsupported(invocation, "LX11:exactly one step"));
        };
        if !step.parameters().is_empty() {
            return Err(self.unsupported(invocation, "LX11:step takes no parameters"));
        }
        let op = step.operation().as_str();
        let mut declared: Vec<&str> = step.inputs().iter().map(|i| i.as_str()).collect();
        declared.sort_unstable();
        let mut required = vec!["script"];
        if op == "parse-maps" || op == "parse-mountinfo" {
            required.push("body");
        }
        required.sort_unstable();
        if !is_known_op(op) {
            return Err(self.refusal(
                invocation,
                Some(step.step_id().clone()),
                &self.stage_dispatch,
                "LX11:unknown operation",
            ));
        }
        if declared != required {
            return Err(self.unsupported(invocation, "LX11:unsupported step shape"));
        }
        let Some(raw) = fixture.input(&self.slot_script) else {
            return Err(self.refusal(
                invocation,
                Some(step.step_id().clone()),
                &self.stage_admission,
                "LX11:missing script slot",
            ));
        };
        let body = if op == "parse-maps" || op == "parse-mountinfo" {
            let Some(body) = fixture.input(&self.slot_body) else {
                return Err(self.refusal(
                    invocation,
                    Some(step.step_id().clone()),
                    &self.stage_admission,
                    "LX11:missing body slot",
                ));
            };
            Some(body)
        } else {
            None
        };
        let Some(text) = run_scenario(op, raw, body) else {
            return Err(self.refusal(
                invocation,
                Some(step.step_id().clone()),
                &self.stage_admission,
                "LX11:unknown case or parameter",
            ));
        };
        self.observed(invocation, step.step_id(), &text)
            .map_err(|_| {
                self.refusal(
                    invocation,
                    Some(step.step_id().clone()),
                    &self.stage_collect,
                    "LX11:observation bounds",
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
        "open" | "read" | "parse-maps" | "parse-mountinfo" | "walk"
    )
}

/// Parsed `case=<name>(;<key>=<value>)*;` script. Values may contain `=`
/// (paths do); only `;` separates pairs and the trailing `;` is required.
struct Script<'a> {
    case: &'a str,
    params: Vec<(&'a str, &'a str)>,
}

fn parse_script(raw: &[u8]) -> Option<Script<'_>> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut pieces = text.split(';').collect::<Vec<_>>();
    if pieces.pop() != Some("") {
        return None;
    }
    let head = *pieces.first()?;
    let case = head.strip_prefix("case=")?;
    if case.is_empty() || !case.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return None;
    }
    let mut params = Vec::new();
    for piece in pieces.into_iter().skip(1) {
        if piece.is_empty() {
            return None;
        }
        let (key, value) = piece.split_once('=')?;
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_lowercase()) || value.is_empty() {
            return None;
        }
        params.push((key, value));
    }
    Some(Script { case, params })
}

fn param<'a>(script: &'a Script<'_>, key: &str) -> Option<&'a str> {
    script
        .params
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| *v)
}

/// Run one operation/case scenario over explicit caller paths. `None` names
/// an unknown operation or case, a malformed script or a missing parameter;
/// every executed Linux contract refusal is a `Some(refuse=...;)` body.
/// F28: script values cannot carry the `;` frame delimiter. Callers pass
/// interpolated values through here and refuse them on `None` instead of
/// building a corrupted script that silently reselects another file.
pub fn script_value(value: &str) -> Option<&str> {
    if value.bytes().any(|b| b == b';') {
        None
    } else {
        Some(value)
    }
}

pub fn run_scenario(op: &str, script: &[u8], body: Option<&[u8]>) -> Option<String> {
    let script = parse_script(script)?;
    match (op, script.case) {
        ("open", "ok" | "missing" | "dir" | "symlink") => Some(open_case(param(&script, "path")?)),
        ("read", "ok" | "empty" | "tiny" | "cancelled") => {
            Some(read_case(script.case, param(&script, "path")?))
        }
        ("parse-maps", "ok" | "live" | "bad") => Some(maps_case(script.case, body?)),
        ("parse-mountinfo", "ok" | "bad") => Some(mounts_case(script.case, body?)),
        ("walk", "ok" | "tight" | "missing") => {
            Some(walk_case(script.case, param(&script, "root")?))
        }
        _ => None,
    }
}

fn open_case(path: &str) -> String {
    let resolver = match ProcFdResolver::open_self() {
        Ok(resolver) => resolver,
        Err(error) => return refusal_of(&error),
    };
    let held = match HeldFile::open(Path::new(path), &resolver, SymlinkPolicy::RejectFinal) {
        Ok(held) => held,
        Err(error) => return refusal_of(&error),
    };
    match held.stat() {
        Ok(stat) => {
            let mut ledger = ExpectedLedger::new();
            ledger.record("stat", &format!("len:{}", stat.len()));
            ledger.render()
        }
        Err(error) => refusal_of(&error),
    }
}

fn read_case(case: &str, path: &str) -> String {
    let resolver = match ProcFdResolver::open_self() {
        Ok(resolver) => resolver,
        Err(error) => return refusal_of(&error),
    };
    let held = match HeldFile::open(Path::new(path), &resolver, SymlinkPolicy::RejectFinal) {
        Ok(held) => held,
        Err(error) => return refusal_of(&error),
    };
    let limits = ReadLimits {
        max_bytes: if case == "tiny" { 2 } else { 1 << 20 },
        max_read_calls: 64,
        max_buffer_capacity: 1 << 20,
    };
    let control = if case == "cancelled" {
        let token = CancelToken::new();
        token.cancel();
        OperationControl::new(None, token)
    } else {
        OperationControl::unlimited()
    };
    match held.read_all(limits, &control) {
        Ok(read) => {
            let mut ledger = ExpectedLedger::new();
            ledger.record("bytes", &read.bytes().len().to_string());
            ledger.record("calls", &read.charges().read_calls().to_string());
            ledger.render()
        }
        Err(error) => refusal_of(&error),
    }
}

fn parse_limits() -> ParseLimits {
    ParseLimits {
        max_bytes: 1 << 20,
        max_entries: 4096,
        max_line_bytes: 1 << 16,
    }
}

fn maps_case(case: &str, body: &[u8]) -> String {
    match parse_maps(body, parse_limits()) {
        Ok(snapshot) => {
            let mut ledger = ExpectedLedger::new();
            ledger.record("entries", &snapshot.entries().len().to_string());
            if case != "live" {
                ledger.record(
                    "containing",
                    &snapshot.containing(0x1000).is_some().to_string(),
                );
            }
            ledger.render()
        }
        Err(error) => refusal_of(&error),
    }
}

fn mounts_case(case: &str, body: &[u8]) -> String {
    match parse_mountinfo(body, parse_limits()) {
        Ok(snapshot) => {
            let mut ledger = ExpectedLedger::new();
            ledger.record("entries", &snapshot.len().to_string());
            if case == "ok" {
                let first = snapshot
                    .entries()
                    .next()
                    .map(|entry| {
                        String::from_utf8_lossy(entry.mount_point().decoded()).into_owned()
                    })
                    .unwrap_or_default();
                ledger.record("first", &first);
            }
            ledger.render()
        }
        Err(error) => refusal_of(&error),
    }
}

fn walk_limits(entries: u64) -> WalkLimits {
    WalkLimits {
        max_entries_visited: entries,
        max_entries_queued: 256,
        max_depth: 16,
        max_path_bytes: 1 << 20,
        max_read_bytes: 1 << 20,
        max_output_bytes: 1 << 20,
        max_open_fds: 64,
        max_stat_calls: 4096,
        max_read_calls: 4096,
    }
}

fn walk_case(case: &str, root: &str) -> String {
    let per_round = walk_limits(if case == "tight" { 1 } else { 1024 });
    let epoch = WalkEpoch::new();
    let mut budget = match WalkBudget::new(per_round, per_round, &epoch) {
        Ok(budget) => budget,
        Err(error) => return refusal_of(&error),
    };
    let root = match HeldDirectory::open(Path::new(root), WalkPolicy::StayOnMount) {
        Ok(root) => root,
        Err(error) => return refusal_of(&error),
    };
    let control = OperationControl::unlimited();
    let mut paths = Vec::new();
    let mut done = false;
    for _ in 0..1024 {
        match walk(&root, &mut budget, &control) {
            Ok(batch) => {
                for entry in batch.entries() {
                    paths.push(entry.path().to_string_lossy().into_owned());
                }
                if batch.is_done() {
                    done = true;
                    break;
                }
            }
            Err(failure) => return refusal_of(failure.error()),
        }
    }
    let mut ledger = ExpectedLedger::new();
    ledger.record("entries", &paths.join(","));
    ledger.record("done", &done.to_string());
    ledger.render()
}
