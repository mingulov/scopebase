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

/// Held-file inspector reference adapter: real open/stat, bounded reads,
/// strict maps/mountinfo parses and bounded walks over explicit paths.
pub struct HeldfileReferenceAdapter {
    limits: RunLimits,
    subject: SubjectBinding,
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
        Ok(Self { limits, subject })
    }

    fn observed(
        &self,
        invocation: &CaseInvocation,
        step: &Label,
        body: &str,
    ) -> Result<Observation, HarnessError> {
        Observation::new(
            ObservationValues {
                key: invocation.key().clone(),
                schema_id: Label::parse(SCHEMA_ID).expect("LX11:fixed schema parses"),
                schema_revision: SCHEMA_REVISION,
                completed_steps: vec![step.clone()],
                bytes: body.as_bytes().to_vec(),
                effects: EffectBatch::empty(&self.limits),
            },
            &self.limits,
        )
    }

    fn refusal(
        &self,
        invocation: &CaseInvocation,
        step: Option<Label>,
        stage: &str,
        diagnostic: &str,
    ) -> CaseError {
        let cause = RefusalEvidence::new(
            RefusalEvidenceValues {
                cause: RefusalCause::Unknown,
                method: Label::parse("execute").expect("LX11:fixed label parses"),
                evidence_ids: Vec::new(),
                tier: EvidenceTier::T0,
            },
            &self.limits,
        )
        .expect("LX11:bounded refusal cause");
        CaseError::new(
            CaseErrorValues {
                key: invocation.key().clone(),
                step_id: step,
                stage: Label::parse(stage).expect("LX11:fixed stage parses"),
                category: CaseErrorCategory::Refused,
                errno: None,
                diagnostic_bytes: diagnostic.as_bytes().to_vec(),
                cause,
                completed_steps: Vec::new(),
                partial_observation: None,
                effects: EffectBatch::empty(&self.limits),
            },
            &self.limits,
        )
        .expect("LX11:bounded case error")
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
        let Some(step) = invocation.script().steps().first() else {
            return Err(self.refusal(invocation, None, "dispatch", "LX11:script has no steps"));
        };
        let op = step.operation().as_str();
        let slot = Label::parse("script").expect("LX11:fixed slot parses");
        let Some(raw) = fixture.input(&slot) else {
            return Err(self.refusal(
                invocation,
                Some(step.step_id().clone()),
                "admission",
                "LX11:missing script slot",
            ));
        };
        let body = if op == "parse-maps" || op == "parse-mountinfo" {
            let slot = Label::parse("body").expect("LX11:fixed slot parses");
            let Some(body) = fixture.input(&slot) else {
                return Err(self.refusal(
                    invocation,
                    Some(step.step_id().clone()),
                    "admission",
                    "LX11:missing body slot",
                ));
            };
            Some(body)
        } else {
            None
        };
        let Some(text) = run_scenario(op, raw, body) else {
            let known = is_known_op(op);
            let (stage, message) = if known {
                ("admission", "LX11:unknown case or parameter")
            } else {
                ("dispatch", "LX11:unknown operation")
            };
            return Err(self.refusal(invocation, Some(step.step_id().clone()), stage, message));
        };
        self.observed(invocation, step.step_id(), &text)
            .map_err(|_| {
                self.refusal(
                    invocation,
                    Some(step.step_id().clone()),
                    "collect",
                    "LX11:observation bounds",
                )
            })
    }

    fn retire(&mut self, request: &RetireRequest) -> RetirementReport {
        RetirementReport::new(
            RetirementReportValues {
                call_id: request.call_id(),
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
        .expect("LX11:bounded retirement report")
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
