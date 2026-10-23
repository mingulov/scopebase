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

/// Kernel-space range no /proc maps line can name: 64 KiB aligned (hence
/// aligned for every supported page size) just below the top of u64.
const ABSURD_START: u64 = 0xFFFF_FFFF_FFFE_0000;
const ABSURD_END: u64 = 0xFFFF_FFFF_FFFF_0000;

/// Owned-workload observer reference adapter: real acquisition, birth
/// verification, maps/mountinfo observation and mapping verdicts.
pub struct ObserveReferenceAdapter {
    limits: RunLimits,
    subject: SubjectBinding,
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

impl ConformanceAdapter for ObserveReferenceAdapter {
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
        let Some(text) = run_scenario(op, raw, None) else {
            let (stage, message) = if is_known_op(op) {
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

/// Run one operation/case scenario over explicit caller parameters. `None`
/// names an unknown operation or case, a malformed script or a missing
/// parameter; every executed Linux contract refusal is a
/// `Some(refuse=...;)` body. The reserved `body` slot stays `None`: live
/// observations read the real /proc, never fixture bytes.
pub fn run_scenario(op: &str, script: &[u8], _body: Option<&[u8]>) -> Option<String> {
    let script = parse_script(script)?;
    match (op, script.case) {
        ("acquire-self", "self") => Some(acquire_self()),
        ("acquire", "dead") => Some(acquire_dead()),
        ("acquire", "pid") => acquire_pid(param(&script, "pid")?),
        ("spawn-observe", "child") => spawn_observe(param(&script, "child")?),
        ("maps-self", "self") => Some(maps_self()),
        ("mounts-self", "self") => Some(mounts_self()),
        ("mapping", "empty" | "unmapped" | "incoherent") => {
            Some(mapping_case(script.case, param(&script, "path")?))
        }
        _ => None,
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

fn spawn_observe(child: &str) -> Option<String> {
    let mut spawned = std::process::Command::new(child)
        .arg("child")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let pid_raw = spawned.id() as i32;
    let outcome = observe_live_child(pid_raw);
    // SIGKILL then reap: the child is always in interruptible sleep.
    let _ = spawned.kill();
    let reaped = spawned.wait().is_ok();
    let gone = std::fs::metadata(format!("/proc/{pid_raw}")).is_err();
    Some(match outcome {
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
