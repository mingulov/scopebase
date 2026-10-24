// SPDX-License-Identifier: Apache-2.0
//! Owned-workload observer standalone adapter over process/mapping surfaces.
//!
//! NEW (LX11): reference-only; no donor lines copied. Each scenario composes
//! exact packaged `scopebase-linux` calls with this consumer's own fixed
//! script constants. Live observations assert relational facts (birth
//! equality, address containment, verdict kinds), never absolute counts, and
//! the TT03 stat oracle independently cross-checks every birth the Linux API
//! reports. Linux contract refusals are observed data encoded as
//! `refuse=<Stage>:<Reason>[:line=N];`; only adapter-level failures (missing
//! slot, unknown operation, malformed script, missing parameter) become
//! `CaseError`.
use scopebase_linux::{
    conformance::{refusal_of, ExpectedLedger},
    control::OperationControl,
    file::{HeldFile, ProcFdResolver, SymlinkPolicy},
    mapping::{
        observe_mapping, MapRange, MappingLimits, MappingOutcome, MappingPolicy, MappingPool,
        MappingPoolLimits,
    },
    process::{BirthStatus, ObserverEpoch, Pid, ProcLimits, ProcessObservation},
    procfs::ParseLimits,
};
use scopebase_testkit::{
    linux::{parse_stat_comm_state_starttime, stat_is_zombie},
    BindingProvenance, CaseError, CaseErrorCategory, CaseErrorValues, CaseInvocation,
    ConformanceAdapter, ConsumerBinding, ConsumerBindingValues, Digest256, EffectBatch,
    EvidenceTier, FixtureAccess, HarnessError, Label, Observation, ObservationValues, RefusalCause,
    RefusalEvidence, RefusalEvidenceValues, RetireRequest, RetirementReport,
    RetirementReportValues, RunLimits, SubjectBinding, SubjectBindingValues,
};
use std::{path::Path, process::Stdio, sync::Arc};

const PACKAGE: &str = "linux-observe-reference";
const CONSUMER: &str = "observe-adapter";
const SCHEMA_ID: &str = "observe-reference-v1";
const SCHEMA_REVISION: u32 = 1;
const FIXTURE_SCHEMA_ID: &str = "observe-fixture-v1";
const FIXTURE_SCHEMA_REVISION: u32 = 1;
/// R33: the only script dialect this adapter executes. Anything
/// else is pre-read UnsupportedSchema, before any slot is touched.
const SCRIPT_SCHEMA_ID: &str = "observe-script";

/// F26: truncate a byte payload to an invocation byte ceiling.
fn fit_bytes(bytes: &[u8], ceiling: u64) -> Vec<u8> {
    let max = ceiling.min(usize::MAX as u64) as usize;
    bytes.iter().take(max).copied().collect()
}

/// F26: truncate a completed-step list to the invocation step ceiling.
fn fit_steps(steps: Vec<Label>, limits: &RunLimits) -> Vec<Label> {
    let max = limits.steps_per_invocation().min(usize::MAX as u64) as usize;
    steps.into_iter().take(max).collect()
}

/// Kernel-space range no /proc maps line can name: 64 KiB aligned (hence
/// aligned for every supported page size) just below the top of u64.
const ABSURD_START: u64 = 0xFFFF_FFFF_FFFE_0000;
const ABSURD_END: u64 = 0xFFFF_FFFF_FFFF_0000;

/// Owned-workload observer reference adapter: real acquisition, birth
/// verification, maps/mountinfo observation and mapping verdicts.
pub struct ObserveReferenceAdapter {
    limits: RunLimits,
    subject: SubjectBinding,
    schema: Label,
    method_execute: Label,
    stage_admission: Label,
    stage_collect: Label,
    stage_schema: Label,
    slot_script: Label,
}

impl ObserveReferenceAdapter {
    /// Build the adapter with its self-reported development subject binding.
    pub fn new() -> Result<Self, HarnessError> {
        let limits = RunLimits::default();
        let digest = Digest256::of_bytes(b"LX11 linux-observe-reference subject v1");
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
            stage_admission: Label::parse("admission").expect("LX11:fixed stage parses"),
            stage_collect: Label::parse("collect").expect("LX11:fixed stage parses"),
            stage_schema: Label::parse("adapter-schema").expect("LX11:fixed stage parses"),
            slot_script: Label::parse("script").expect("LX11:fixed slot parses"),
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

    fn refusal(
        &self,
        invocation: &CaseInvocation,
        step: Option<Label>,
        stage: &Label,
        diagnostic: &str,
        errno: Option<i32>,
    ) -> CaseError {
        let l = invocation.limits();
        CaseError::new(
            CaseErrorValues {
                key: invocation.key().clone(),
                step_id: step,
                // RB4 (R02): fitted stage tag (see cause).
                stage: stage.truncate(l.label_bytes()),
                category: CaseErrorCategory::Refused,
                // S59: operational failures preserve the raw errno
                // (a spawn that failed after valid admission names
                // its errno instead of collapsing to InvalidOutput).
                errno,
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

impl ConformanceAdapter for ObserveReferenceAdapter {
    fn subject(&self) -> SubjectBinding {
        self.subject.clone()
    }

    fn execute(
        &mut self,
        invocation: &CaseInvocation,
        fixture: &FixtureAccess<'_>,
    ) -> Result<Observation, CaseError> {
        // F27: envelope preflight before any slot read or effect. Schema,
        // step count, parameters and declared inputs are validated here.
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
        // R33: the script dialect admits before dispatch: an alien
        // script never reaches operation matching or slot reads.
        if invocation.script().schema_id().as_str() != SCRIPT_SCHEMA_ID {
            return Err(self.unsupported(invocation, "LX11:unsupported script schema"));
        }
        let [step] = invocation.script().steps() else {
            return Err(self.unsupported(invocation, "LX11:exactly one step"));
        };
        if !step.parameters().is_empty() {
            return Err(self.unsupported(invocation, "LX11:step takes no parameters"));
        }
        let op = step.operation().as_str();
        if !is_known_op(op) {
            // R33: an unknown opcode is a dialect this adapter does
            // not speak: pre-read UnsupportedSchema, like an alien
            // script id — before any slot is touched.
            return Err(self.unsupported(invocation, "LX11:unknown operation"));
        }
        let mut declared: Vec<&str> = step.inputs().iter().map(|i| i.as_str()).collect();
        declared.sort_unstable();
        if declared != ["script"] {
            return Err(self.unsupported(invocation, "LX11:unsupported step shape"));
        }
        let Some(raw) = fixture.input(&self.slot_script) else {
            return Err(self.invalid_output(
                invocation,
                Some(step.step_id().clone()),
                &self.stage_admission,
                "LX11:missing script slot",
            ));
        };
        let text = match run_scenario(op, raw, None) {
            ScenarioOutcome::Output(text) => text,
            ScenarioOutcome::UnknownCaseOrParameter => {
                return Err(self.invalid_output(
                    invocation,
                    Some(step.step_id().clone()),
                    &self.stage_admission,
                    "LX11:unknown case or parameter",
                ));
            }
            // S59: valid input whose child would not start is an
            // operational refusal with the raw errno — never
            // InvalidOutput.
            ScenarioOutcome::SpawnFailed(error) => {
                let errno = error.raw_os_error();
                return Err(self.refusal(
                    invocation,
                    Some(step.step_id().clone()),
                    &self.stage_collect,
                    &format!("LX11:spawn failed: {error}"),
                    errno,
                ));
            }
        };
        self.observed(invocation, step.step_id(), &text)
            .map_err(|_| {
                self.refusal(
                    invocation,
                    Some(step.step_id().clone()),
                    &self.stage_collect,
                    "LX11:observation bounds",
                    None,
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
        "acquire-self" | "acquire" | "spawn-observe" | "maps-self" | "mounts-self" | "mapping"
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

fn proc_limits() -> ProcLimits {
    ProcLimits {
        parse: ParseLimits {
            max_bytes: 1 << 20,
            max_entries: 1 << 16,
            max_line_bytes: 1 << 16,
        },
        max_read_calls: 4096,
        max_metadata_bytes: 1 << 20,
    }
}

/// F28: script values cannot carry the `;` frame delimiter. Callers pass
/// interpolated values through here and refuse them on `None` instead of
/// building a corrupted script that silently reselects another target.
pub fn script_value(value: &str) -> Option<&str> {
    if value.bytes().any(|b| b == b';') {
        None
    } else {
        Some(value)
    }
}

/// S59: scenario outcome — parameter rejection stays separate from
/// operational failure, and the spawn error survives with its errno
/// instead of collapsing to "unknown case or parameter".
#[derive(Debug)]
pub enum ScenarioOutcome {
    /// Rendered observation body (executed Linux contract refusals
    /// are `refuse=...;` bodies).
    Output(String),
    /// Unknown operation or case, malformed script, or missing
    /// parameter: malformed operation data.
    UnknownCaseOrParameter,
    /// Valid input whose child would not spawn: operational failure
    /// with the underlying error preserved.
    SpawnFailed(std::io::Error),
}

/// Run one operation/case scenario over explicit caller parameters.
/// The reserved `body` slot stays `None`: live observations read the
/// real /proc, never fixture bytes.
pub fn run_scenario(op: &str, script: &[u8], _body: Option<&[u8]>) -> ScenarioOutcome {
    let Some(script) = parse_script(script) else {
        return ScenarioOutcome::UnknownCaseOrParameter;
    };
    match (op, script.case) {
        ("acquire-self", "self") => ScenarioOutcome::Output(acquire_self()),
        ("acquire", "dead") => ScenarioOutcome::Output(acquire_dead()),
        ("acquire", "pid") => match param(&script, "pid").and_then(acquire_pid) {
            Some(body) => ScenarioOutcome::Output(body),
            None => ScenarioOutcome::UnknownCaseOrParameter,
        },
        ("spawn-observe", "child") => match param(&script, "child") {
            Some(child) => match spawn_observe(child) {
                Ok(body) => ScenarioOutcome::Output(body),
                Err(error) => ScenarioOutcome::SpawnFailed(error),
            },
            None => ScenarioOutcome::UnknownCaseOrParameter,
        },
        ("maps-self", "self") => ScenarioOutcome::Output(maps_self()),
        ("mounts-self", "self") => ScenarioOutcome::Output(mounts_self()),
        ("mapping", "empty" | "unmapped" | "incoherent") => {
            match param(&script, "path") {
                Some(path) => ScenarioOutcome::Output(mapping_case(script.case, path)),
                None => ScenarioOutcome::UnknownCaseOrParameter,
            }
        }
        _ => ScenarioOutcome::UnknownCaseOrParameter,
    }
}

fn birth_name(status: BirthStatus) -> &'static str {
    match status {
        BirthStatus::AliveSameBirth => "AliveSameBirth",
        BirthStatus::Exited => "Exited",
        BirthStatus::Changed => "Changed",
        BirthStatus::Inconclusive => "Inconclusive",
        _ => "unknown",
    }
}

/// Independent TT03 oracle cross-check: the oracle's field-22 starttime from
/// a freshly read stat must equal the retained Linux birth ticks.
fn starttime_matches(pid: u32, birth_ticks: u64) -> bool {
    let path = format!("/proc/{pid}/stat");
    std::fs::read(&path)
        .ok()
        .and_then(|raw| parse_stat_comm_state_starttime(&raw).ok())
        .is_some_and(|(_, _, starttime)| starttime == birth_ticks)
}

fn acquire_pid_body(pid_raw: i32) -> String {
    let limits = proc_limits();
    let control = OperationControl::unlimited();
    let epoch = match ObserverEpoch::new(limits, &control) {
        Ok(epoch) => epoch,
        Err(error) => return refusal_of(&error),
    };
    let pid = match Pid::new(pid_raw) {
        Some(pid) => pid,
        // Unreachable for the fixed self/dead callers; the pid caller
        // validates before reaching here.
        None => return "refuse=ConfigureProcess:InvalidInput;".to_string(),
    };
    let observation = match ProcessObservation::acquire(pid, &epoch, limits, &control) {
        Ok(observation) => observation,
        Err(error) => return refusal_of(&error),
    };
    let birth = match observation.verify_birth(&control) {
        Ok(birth) => birth,
        Err(error) => return refusal_of(&error),
    };
    let stat = std::fs::read(format!("/proc/{}/stat", pid.as_raw())).unwrap_or_default();
    let zombie = stat_is_zombie(&stat).unwrap_or(true);
    let matched = starttime_matches(pid.as_raw() as u32, observation.birth().start_ticks());
    let mut ledger = ExpectedLedger::new();
    ledger.record("birth", birth_name(birth.status()));
    ledger.record("self_zombie", &zombie.to_string());
    ledger.record("starttime_match", &matched.to_string());
    ledger.render()
}

fn acquire_self() -> String {
    acquire_pid_body(std::process::id() as i32)
}

fn acquire_pid(text: &str) -> Option<String> {
    let pid = text.parse::<i32>().ok().filter(|pid| *pid >= 1)?;
    Some(acquire_pid_body(pid))
}

fn acquire_dead() -> String {
    // i32::MAX can never name a live process: the kernel caps pid_max at
    // PID_MAX_LIMIT (2^22 on 64-bit), far below i32::MAX.
    let limits = proc_limits();
    let control = OperationControl::unlimited();
    let epoch = match ObserverEpoch::new(limits, &control) {
        Ok(epoch) => epoch,
        Err(error) => return refusal_of(&error),
    };
    let pid = Pid::new(i32::MAX).expect("LX11:i32::MAX is a valid Pid");
    match ProcessObservation::acquire(pid, &epoch, limits, &control) {
        Ok(_) => "birth=unexpectedly-live;".to_string(),
        Err(error) => refusal_of(&error),
    }
}

fn spawn_observe(child: &str) -> Result<String, std::io::Error> {
    // S59: a spawn failure is operational (valid input, failed
    // effect) — the error returns typed instead of collapsing to
    // "unknown case or parameter".
    let mut spawned = std::process::Command::new(child)
        .arg("child")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid_raw = spawned.id() as i32;
    let outcome = observe_live_child(pid_raw);
    // SIGKILL then reap: the child is always in interruptible sleep.
    let _ = spawned.kill();
    let reaped = spawned.wait().is_ok();
    let gone = std::fs::metadata(format!("/proc/{pid_raw}")).is_err();
    Ok(match outcome {
        Ok(mut ledger) => {
            ledger.record("reaped", &reaped.to_string());
            ledger.record("gone", &gone.to_string());
            ledger.render()
        }
        // A typed Linux refusal still carries the reap/gone custody facts.
        Err(refusal) => format!("{refusal}reaped={reaped};gone={gone};"),
    })
}

/// Observe the live child before the caller reaps it. The typed Linux
/// refusal survives; the caller still reports reap/gone facts beside it.
fn observe_live_child(pid_raw: i32) -> Result<ExpectedLedger, String> {
    let limits = proc_limits();
    let control = OperationControl::unlimited();
    let epoch = ObserverEpoch::new(limits, &control).map_err(|error| refusal_of(&error))?;
    let pid =
        Pid::new(pid_raw).ok_or_else(|| "refuse=ConfigureProcess:InvalidInput;".to_string())?;
    let observation = ProcessObservation::acquire(pid, &epoch, limits, &control)
        .map_err(|error| refusal_of(&error))?;
    let birth = observation
        .verify_birth(&control)
        .map_err(|error| refusal_of(&error))?;
    let maps = observation
        .read_maps(limits, &control)
        .map_err(|error| refusal_of(&error))?;
    let matched = starttime_matches(pid.as_raw() as u32, observation.birth().start_ticks());
    let mut ledger = ExpectedLedger::new();
    ledger.record("birth", birth_name(birth.status()));
    ledger.record(
        "child_maps",
        &(maps.snapshot().entries().len() > 0).to_string(),
    );
    ledger.record("starttime_match", &matched.to_string());
    Ok(ledger)
}

fn maps_self() -> String {
    let limits = proc_limits();
    let control = OperationControl::unlimited();
    let epoch = match ObserverEpoch::new(limits, &control) {
        Ok(epoch) => epoch,
        Err(error) => return refusal_of(&error),
    };
    let pid = Pid::new(std::process::id() as i32).expect("LX11:own pid is valid");
    let observation = match ProcessObservation::acquire(pid, &epoch, limits, &control) {
        Ok(observation) => observation,
        Err(error) => return refusal_of(&error),
    };
    match observation.read_maps(limits, &control) {
        Ok(maps) => {
            let probe = 0u8;
            let addr = std::ptr::addr_of!(probe) as u64;
            let mut ledger = ExpectedLedger::new();
            ledger.record(
                "nonempty",
                &(maps.snapshot().entries().len() > 0).to_string(),
            );
            ledger.record(
                "self_containing",
                &maps.snapshot().containing(addr).is_some().to_string(),
            );
            ledger.render()
        }
        Err(error) => refusal_of(&error),
    }
}

fn mounts_self() -> String {
    let limits = proc_limits();
    let control = OperationControl::unlimited();
    let epoch = match ObserverEpoch::new(limits, &control) {
        Ok(epoch) => epoch,
        Err(error) => return refusal_of(&error),
    };
    let pid = Pid::new(std::process::id() as i32).expect("LX11:own pid is valid");
    let observation = match ProcessObservation::acquire(pid, &epoch, limits, &control) {
        Ok(observation) => observation,
        Err(error) => return refusal_of(&error),
    };
    match observation.read_mountinfo(limits, &control) {
        Ok(mounts) => {
            let mut ledger = ExpectedLedger::new();
            ledger.record("nonempty", &(mounts.snapshot().len() > 0).to_string());
            ledger.render()
        }
        Err(error) => refusal_of(&error),
    }
}

fn mapping_case(case: &str, path: &str) -> String {
    let proc = proc_limits();
    let control = OperationControl::unlimited();
    let resolver = match ProcFdResolver::open_self() {
        Ok(resolver) => resolver,
        Err(error) => return refusal_of(&error),
    };
    let held = match HeldFile::open(Path::new(path), &resolver, SymlinkPolicy::RejectFinal) {
        Ok(held) => held,
        Err(error) => return refusal_of(&error),
    };
    let epoch = match ObserverEpoch::new(proc, &control) {
        Ok(epoch) => epoch,
        Err(error) => return refusal_of(&error),
    };
    let pid = Pid::new(std::process::id() as i32).expect("LX11:own pid is valid");
    let observation = match ProcessObservation::acquire(pid, &epoch, proc, &control) {
        Ok(observation) => observation,
        Err(error) => return refusal_of(&error),
    };
    let pool = match MappingPool::new(MappingPoolLimits {
        max_mappings: 0,
        max_mapped_bytes: 0,
    }) {
        Ok(pool) => pool,
        Err(error) => return refusal_of(&error),
    };
    let range = match MapRange::new(ABSURD_START, ABSURD_END) {
        Ok(range) => range,
        Err(error) => return refusal_of(&error),
    };
    let request = scopebase_linux::mapping::MappingRequest {
        pool: &pool,
        held: Arc::new(held),
        process: &observation,
        range,
        policy: MappingPolicy::NoNewTargetMappings,
        retained: None,
        limits: MappingLimits {
            proc,
            max_mount_refreshes: 1,
            // Mirrors the ceiling the crate's own mapping-contract tests use.
            max_open_fds: 1024,
            max_live_mappings: if case == "incoherent" { 1 } else { 0 },
        },
    };
    match observe_mapping(request, &control) {
        Ok(outcome) => match outcome {
            MappingOutcome::ExactRange(_) => "verdict=exact;".to_string(),
            MappingOutcome::KeyCompatible(_) => "verdict=key-compatible;".to_string(),
            MappingOutcome::Mismatch(evidence) => {
                format!("verdict=mismatch:{:?};", evidence.kind())
            }
            MappingOutcome::Inconclusive(reason) => {
                format!("verdict=inconclusive:{:?};", reason.kind())
            }
            _ => "verdict=unknown;".to_string(),
        },
        Err(failure) => refusal_of(failure.error()),
    }
}
