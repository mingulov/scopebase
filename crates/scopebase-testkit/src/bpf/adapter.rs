// SPDX-License-Identifier: Apache-2.0
//! Closed one-step T0 adapter over the actual optional BPF dependency.
use crate::artifact::{he, BoundValue};
use crate::ids::{bp03_label_capacity, bp03_profile_capacity};
use crate::*;
use scopebase_bpf as b;
use std::mem::size_of;
pub fn profile_to_testkit(v: &b::ProfileId) -> Result<ProfileId, IdError> {
    ProfileId::parse(v.as_str())
}
pub fn profile_from_testkit(v: &ProfileId) -> Result<b::ProfileId, b::OperationError> {
    b::ProfileId::new(v.as_str())
}
pub struct BpfHostAdapter {
    subject: SubjectBinding,
    bpf: b::Limits,
    run: RunLimits,
    base: usize,
    reserve: usize,
    ceiling: usize,
}
fn admission() -> HarnessError {
    he(HarnessErrorKind::LimitExceeded, "bp03 adapter admission")
}
fn checked_add(a: usize, b: usize) -> Result<usize, b::OperationError> {
    a.checked_add(b)
        .ok_or_else(|| failure(b::ErrorKind::Overflow, None))
}
fn failure(kind: b::ErrorKind, n: Option<usize>) -> b::OperationError {
    let e = b::OperationError::new(kind, b::Stage::Admission, None, None);
    match n {
        Some(n) => e.with_required_size(n),
        None => e,
    }
}
/// Scalar operation refusal. It carries only the finished error fields;
/// the admitted key and metadata stay owned by the prepared response and
/// are moved into the exact finisher by the consuming call.
struct OpRefusal {
    category: CaseErrorCategory,
    stage: OneStepResponseStage,
    diagnostic: OneStepDiagnostic,
    attempted_step: bool,
    errno: Option<i32>,
}
fn footprint(s: &SubjectBinding) -> Option<usize> {
    let mut n = size_of::<BpfHostAdapter>();
    for c in [
        s.package_name().capacity(),
        s.package_version().capacity(),
        s.host().capacity(),
        s.target().capacity(),
        s.consumer().name().capacity(),
    ] {
        n = n.checked_add(c)?;
    }
    n = n.checked_add(s.features().capacity().checked_mul(size_of::<String>())?)?;
    for f in s.features() {
        n = n.checked_add(f.capacity())?;
    }
    n = n.checked_add(
        s.objects()
            .capacity()
            .checked_mul(size_of::<ArtifactBinding>())?,
    )?;
    for o in s.objects() {
        n = n.checked_add(bp03_label_capacity(o.id()))?;
    }
    if let Some(b) = s.backend() {
        n = n
            .checked_add(b.name().capacity())?
            .checked_add(b.version().capacity())?;
    }
    if let BindingProvenance::SelfReported { reason } = s.provenance() {
        n = n.checked_add(reason.capacity())?;
    }
    Some(n)
}
impl BpfHostAdapter {
    pub fn new(
        subject: SubjectBinding,
        bpf_limits: b::Limits,
        run_limits: RunLimits,
    ) -> Result<Self, HarnessError> {
        subject.check_bounds(&run_limits)?;
        bpf_limits.validate().map_err(|_| admission())?;
        if run_limits.name_bytes() < 256
            || run_limits.label_bytes() < 32
            || run_limits.diagnostic_bytes() < 128
            || run_limits.observation_bytes() < 128
            || run_limits.input_slots() < 2
            || run_limits.steps_per_invocation() < 1
        {
            return Err(admission());
        }
        let base = footprint(&subject).ok_or_else(admission)?;
        let reserve = 8192usize
            .checked_add(
                size_of::<CaseError>()
                    .max(size_of::<Observation>())
                    .max(size_of::<RetirementReport>()),
            )
            .ok_or_else(admission)?;
        let available = usize::try_from(run_limits.retained_bytes())
            .ok()
            .and_then(|v| v.checked_sub(base))
            .and_then(|v| v.checked_sub(reserve))
            .ok_or_else(admission)?;
        let ceiling = available.min(bpf_limits.retained_bytes).min(262144);
        Ok(Self {
            subject,
            bpf: bpf_limits,
            run: run_limits,
            base,
            reserve,
            ceiling,
        })
    }
    /// Scalar operation refusal carried to the owned prepared finish.
    /// No key, diagnostic source or payload is cloned or allocated here;
    /// the admitted response context is moved by the caller.
    fn refusal(
        category: CaseErrorCategory,
        stage: OneStepResponseStage,
        diagnostic: &[u8],
        attempted_step: bool,
        errno: Option<i32>,
    ) -> OpRefusal {
        OpRefusal {
            category,
            stage,
            diagnostic: OneStepDiagnostic::new(diagnostic)
                .expect("fixed diagnostic fits admitted scratch"),
            attempted_step,
            errno,
        }
    }
    /// Fixed finite kind/stage token mapping retained from the legacy error
    /// path. Diagnostics are built into fixed stack scratch with decimal
    /// scalar demands only; no formatting allocation or untrusted text.
    fn library_refusal(e: b::OperationError) -> OpRefusal {
        let kind: &[u8] = match e.kind() {
            b::ErrorKind::InvalidInput => b"invalid_input",
            b::ErrorKind::Malformed => b"malformed",
            b::ErrorKind::Incompatible => b"incompatible",
            b::ErrorKind::Unsupported => b"unsupported",
            b::ErrorKind::Denied => b"denied",
            b::ErrorKind::Disappeared => b"disappeared",
            b::ErrorKind::Changed => b"changed",
            b::ErrorKind::LimitExceeded => b"limit_exceeded",
            b::ErrorKind::Overflow => b"overflow",
            b::ErrorKind::Backend => b"backend",
            b::ErrorKind::Poisoned => b"poisoned",
            _ => b"unsupported",
        };
        let (stage, stage_text): (OneStepResponseStage, &[u8]) = match e.stage() {
            b::Stage::Admission => (OneStepResponseStage::Admission, b"admission"),
            b::Stage::Metadata => (OneStepResponseStage::Metadata, b"metadata"),
            b::Stage::Allocate => (OneStepResponseStage::Allocate, b"allocate"),
            b::Stage::Read => (OneStepResponseStage::Read, b"read"),
            b::Stage::Attach => (OneStepResponseStage::Attach, b"attach"),
            b::Stage::Drain => (OneStepResponseStage::Drain, b"drain"),
            b::Stage::Retire => (OneStepResponseStage::Retire, b"retire"),
            b::Stage::BtfQuery => (OneStepResponseStage::BtfQuery, b"btf_query"),
            b::Stage::Compile => (OneStepResponseStage::Compile, b"compile"),
            b::Stage::Inspect => (OneStepResponseStage::Inspect, b"inspect"),
            b::Stage::Execute => (OneStepResponseStage::Execute, b"execute"),
            _ => (OneStepResponseStage::Inspect, b"inspect"),
        };
        let mut diagnostic =
            OneStepDiagnostic::new(b"bpf:").expect("fixed diagnostic fits admitted scratch");
        diagnostic
            .extend(kind)
            .expect("fixed diagnostic fits admitted scratch");
        diagnostic
            .extend(b"/")
            .expect("fixed diagnostic fits admitted scratch");
        diagnostic
            .extend(stage_text)
            .expect("fixed diagnostic fits admitted scratch");
        if let Some(n) = e.required_size() {
            diagnostic
                .extend(b";required=")
                .expect("fixed diagnostic fits admitted scratch");
            diagnostic
                .decimal(n)
                .expect("fixed diagnostic fits admitted scratch");
        }
        OpRefusal {
            category: CaseErrorCategory::Refused,
            stage,
            diagnostic,
            attempted_step: true,
            errno: e.raw_os_error(),
        }
    }
    /// Prepared-path source-domain failure classification. Only grammar
    /// failures (`InvalidInput` at `Admission`, the length/charset
    /// rejection documented for the source domain) keep the specified pure
    /// `source-id-error` value. Capacity (`LimitExceeded`) and allocation
    /// (`Backend`, `Overflow`) failures are exact refused library-stage
    /// outcomes preserving the original kind+stage.
    fn is_source_grammar_failure(e: &b::OperationError) -> bool {
        e.kind() == b::ErrorKind::InvalidInput && e.stage() == b::Stage::Admission
    }
    fn ledger(&self) -> Ledger {
        Ledger {
            ceiling: self.ceiling,
            run_ceiling: self.run.retained_bytes(),
            base: self.base,
            reserve: self.reserve,
            work: 0,
            work_cap: self.bpf.work_steps,
        }
    }
    fn output(
        &self,
        bytes: &[u8],
        ledger: &Ledger,
        live: usize,
    ) -> Result<Vec<u8>, b::OperationError> {
        if bytes.len() as u64 > self.run.observation_bytes() {
            return Err(failure(b::ErrorKind::LimitExceeded, Some(bytes.len())));
        }
        ledger.buffer(bytes.len(), live).map(|mut v| {
            v.extend_from_slice(bytes);
            v
        })
    }
    fn execute_operation(
        &self,
        script: &OperationScript,
        f: &FixtureAccess<'_>,
    ) -> Result<Vec<u8>, OpRefusal> {
        // The closed dialect preflight admits exactly one step before any
        // operation entry, so index 0 is the admitted sole step here.
        let step = &script.steps()[0];
        let op = step.operation().as_str();
        let mut inputs: [&[u8]; 2] = [&[], &[]];
        for (n, slot) in step.inputs().iter().enumerate() {
            input_access();
            inputs[n] = f.input(slot).ok_or_else(|| {
                Self::refusal(
                    CaseErrorCategory::InvalidOutput,
                    OneStepResponseStage::Input,
                    b"missing-input",
                    true,
                    None,
                )
            })?;
        }
        let mut ledger = self.ledger();
        let mut total = 0usize;
        let hard = match op {
            "assess-filter" => 84,
            "to-testkit-profile" | "from-testkit-profile" => 130,
            _ => 65536,
        };
        for bytes in inputs.iter().take(step.inputs().len()) {
            if bytes.len() > hard || bytes.len() as u64 > self.run.vector_bytes() {
                return Err(Self::library_refusal(failure(
                    b::ErrorKind::LimitExceeded,
                    Some(bytes.len()),
                )));
            }
            total = checked_add(total, bytes.len()).map_err(Self::library_refusal)?;
        }
        let total_hard = if op == "context-applies" {
            131072
        } else {
            hard
        };
        if total > total_hard
            || total > self.bpf.input_bytes
            || total as u64 > self.run.input_bytes()
        {
            return Err(Self::library_refusal(failure(
                b::ErrorKind::LimitExceeded,
                Some(total),
            )));
        }
        let mut operation = || -> Result<Vec<u8>, b::OperationError> {
            let t = u64::try_from(total).map_err(|_| failure(b::ErrorKind::Overflow, None))?;
            let mut known = t
                .checked_mul(4)
                .and_then(|n| n.checked_add(64))
                .ok_or_else(|| failure(b::ErrorKind::Overflow, None))?;
            let extra = match op {
                "assess-filter" => 64,
                "to-testkit-profile" | "from-testkit-profile" => 678,
                "import-observation" => decode_work(inputs[0].len())?,
                "context-applies" => decode_work(inputs[0].len())?
                    .checked_add(decode_work(inputs[1].len())?)
                    .and_then(|n| n.checked_add(1024))
                    .ok_or_else(|| failure(b::ErrorKind::Overflow, None))?,
                _ => unreachable!(),
            };
            known = known
                .checked_add(extra)
                .ok_or_else(|| failure(b::ErrorKind::Overflow, None))?;
            ledger.prepay(known)?;
            match op {
                "assess-filter" => {
                    ledger.check(size_of::<Vec<u8>>() + 12)?;
                    let values = counts(inputs[0]).ok_or_else(|| {
                        b::OperationError::new(
                            b::ErrorKind::InvalidInput,
                            b::Stage::Read,
                            None,
                            None,
                        )
                    })?;
                    operation_entry();
                    let state = b::assess_filter_probe(&b::ProbePopulation {
                        expected_owned_hits: values[0],
                        observed_owned_hits: values[1],
                        independently_executed_excluded: values[2],
                        observed_excluded_hits: values[3],
                    })?;
                    let result = match state {
                        b::CapabilityState::Supported => &b"supported"[..],
                        b::CapabilityState::Incompatible => b"incompatible",
                        _ => b"unknown",
                    };
                    self.output(result, &ledger, 0)
                }
                "to-testkit-profile" | "from-testkit-profile" => {
                    let minimum = size_of::<b::ProfileId>() + 128 + size_of::<ProfileId>() + 64;
                    ledger.check(checked_add(minimum, size_of::<Vec<u8>>() + 67)?)?;
                    let text = profile_line(inputs[0]).ok_or_else(|| {
                        b::OperationError::new(
                            b::ErrorKind::InvalidInput,
                            b::Stage::Read,
                            None,
                            None,
                        )
                    })?;
                    operation_entry();
                    if op == "to-testkit-profile" {
                        match b::ProfileId::new(text) {
                            Err(e) if !Self::is_source_grammar_failure(&e) => return Err(e),
                            Err(_) => self.output(b"source-id-error", &ledger, 0),
                            Ok(source) => match profile_to_testkit(&source) {
                                Err(_) => self.output(
                                    b"receiving-id-error",
                                    &ledger,
                                    size_of::<b::ProfileId>() + 128,
                                ),
                                Ok(received) => {
                                    let capacity = bp03_profile_capacity(&received);
                                    if capacity > 64 {
                                        return Err(b::OperationError::new(
                                            b::ErrorKind::LimitExceeded,
                                            b::Stage::Allocate,
                                            None,
                                            None,
                                        )
                                        .with_required_size(capacity));
                                    }
                                    let live = size_of::<b::ProfileId>()
                                        + 128
                                        + size_of::<ProfileId>()
                                        + capacity;
                                    let n = 3 + received.as_str().len();
                                    if n as u64 > self.run.observation_bytes() {
                                        return Err(failure(b::ErrorKind::LimitExceeded, Some(n)));
                                    }
                                    let mut bytes = ledger.buffer(n, live)?;
                                    bytes.extend_from_slice(b"ok:");
                                    bytes.extend_from_slice(received.as_str().as_bytes());
                                    Ok(bytes)
                                }
                            },
                        }
                    } else {
                        match ProfileId::parse(text) {
                            Err(_) => self.output(b"source-id-error", &ledger, 0),
                            Ok(source) => {
                                let capacity = bp03_profile_capacity(&source);
                                if capacity > 64 {
                                    return Err(b::OperationError::new(
                                        b::ErrorKind::LimitExceeded,
                                        b::Stage::Allocate,
                                        None,
                                        None,
                                    )
                                    .with_required_size(capacity));
                                }
                                match profile_from_testkit(&source) {
                                    Err(_) => self.output(
                                        b"receiving-id-error",
                                        &ledger,
                                        size_of::<ProfileId>() + capacity,
                                    ),
                                    Ok(received) => {
                                        let live = size_of::<b::ProfileId>()
                                            + 128
                                            + size_of::<ProfileId>()
                                            + capacity;
                                        let n = 3 + received.as_str().len();
                                        if n as u64 > self.run.observation_bytes() {
                                            return Err(failure(
                                                b::ErrorKind::LimitExceeded,
                                                Some(n),
                                            ));
                                        }
                                        let mut bytes = ledger.buffer(n, live)?;
                                        bytes.extend_from_slice(b"ok:");
                                        bytes.extend_from_slice(received.as_str().as_bytes());
                                        Ok(bytes)
                                    }
                                }
                            }
                        }
                    }
                }
                #[cfg(feature = "bpf-host-json")]
                "context-applies" => {
                    let mut result = ledger.buffer(5, 0)?;
                    let result_charge = size_of::<Vec<u8>>() + result.capacity();
                    operation_entry();
                    let base = b::CapabilityObservation::from_json(
                        inputs[0],
                        &self.decode_limits(inputs[0].len(), ledger.remaining(result_charge)?),
                    )?;
                    let base_live = checked_add(result_charge, base.retained_bytes())?;
                    ledger.check(base_live)?;
                    operation_entry();
                    let candidate = b::CapabilityObservation::from_json(
                        inputs[1],
                        &self.decode_limits(inputs[1].len(), ledger.remaining(base_live)?),
                    )?;
                    let peak = checked_add(base_live, candidate.retained_bytes())?;
                    ledger.check(peak)?;
                    let applies = base.applies_to(
                        candidate.object(),
                        candidate.profile(),
                        candidate.context(),
                    );
                    result.extend_from_slice(if applies { b"true" } else { b"false" });
                    drop(candidate);
                    drop(base);
                    Ok(result)
                }
                #[cfg(feature = "bpf-host-json")]
                "import-observation" => {
                    operation_entry();
                    let value = b::CapabilityObservation::from_json(
                        inputs[0],
                        &self.decode_limits(inputs[0].len(), ledger.remaining(0)?),
                    )?;
                    ledger.check(value.retained_bytes())?;
                    let e = encoded_length(&value)?;
                    let prefixed = checked_add(e, 9)?;
                    if prefixed as u64 > self.run.observation_bytes() {
                        return Err(failure(b::ErrorKind::LimitExceeded, Some(prefixed)));
                    }
                    let encode_work = decode_work(e)?;
                    let prefix_work = u64::try_from(prefixed)
                        .map_err(|_| failure(b::ErrorKind::Overflow, None))?
                        .checked_mul(2)
                        .and_then(|n| n.checked_add(32))
                        .ok_or_else(|| failure(b::ErrorKind::Overflow, None))?;
                    ledger.prepay(
                        encode_work
                            .checked_add(prefix_work)
                            .ok_or_else(|| failure(b::ErrorKind::Overflow, None))?,
                    )?;
                    let future = checked_add(size_of::<Vec<u8>>(), prefixed)?;
                    let peak = checked_add(
                        checked_add(
                            value.retained_bytes(),
                            checked_add(size_of::<Vec<u8>>(), e)?,
                        )?,
                        future,
                    )?;
                    ledger.check(peak)?;
                    let local_retained = ledger.remaining(future)?.min(131072);
                    let json = value.to_json(&b::Limits {
                        retained_bytes: local_retained,
                        work_steps: encode_work,
                        ..self.bpf
                    })?;
                    if json.len() != e {
                        return Err(b::OperationError::new(
                            b::ErrorKind::Backend,
                            b::Stage::Inspect,
                            None,
                            None,
                        ));
                    }
                    let live = checked_add(
                        value.retained_bytes(),
                        checked_add(size_of::<Vec<u8>>(), json.capacity())?,
                    )?;
                    ledger.check(checked_add(live, future)?)?;
                    let mut result = ledger.buffer(prefixed, live)?;
                    result.extend_from_slice(b"imported\n");
                    result.extend_from_slice(&json);
                    drop(json);
                    drop(value);
                    Ok(result)
                }
                _ => unreachable!("preflight closed vocabulary"),
            }
        };
        operation().map_err(|e| {
            if e.kind() == b::ErrorKind::InvalidInput && e.stage() == b::Stage::Read {
                Self::refusal(
                    CaseErrorCategory::InvalidOutput,
                    OneStepResponseStage::Input,
                    b"invalid-input",
                    true,
                    None,
                )
            } else {
                Self::library_refusal(e)
            }
        })
    }
    #[cfg(feature = "bpf-host-json")]
    fn decode_limits(&self, len: usize, remaining: usize) -> b::Limits {
        b::Limits {
            retained_bytes: remaining.min(131072),
            work_steps: decode_work(len).expect("length admitted"),
            ..self.bpf
        }
    }
}
struct Ledger {
    ceiling: usize,
    run_ceiling: u64,
    base: usize,
    reserve: usize,
    work: u64,
    work_cap: u64,
}
impl Ledger {
    fn check(&self, live: usize) -> Result<(), b::OperationError> {
        let joint = checked_add(checked_add(self.base, self.reserve)?, live)?;
        if live > self.ceiling
            || u64::try_from(joint).map_err(|_| failure(b::ErrorKind::Overflow, None))?
                > self.run_ceiling
        {
            Err(failure(b::ErrorKind::LimitExceeded, Some(joint)))
        } else {
            Ok(())
        }
    }
    fn remaining(&self, live: usize) -> Result<usize, b::OperationError> {
        self.check(live)?;
        self.ceiling
            .checked_sub(live)
            .ok_or_else(|| failure(b::ErrorKind::Overflow, None))
    }
    fn prepay(&mut self, charge: u64) -> Result<(), b::OperationError> {
        self.work = self
            .work
            .checked_add(charge)
            .ok_or_else(|| failure(b::ErrorKind::Overflow, None))?;
        if self.work > self.work_cap {
            Err(failure(b::ErrorKind::LimitExceeded, None))
        } else {
            Ok(())
        }
    }
    fn buffer(&self, n: usize, live: usize) -> Result<Vec<u8>, b::OperationError> {
        self.check(checked_add(live, checked_add(size_of::<Vec<u8>>(), n)?)?)?;
        let mut v = Vec::new();
        #[cfg(test)]
        let n = {
            if BUFFER_FAIL.with(std::cell::Cell::get) {
                return Err(b::OperationError::new(
                    b::ErrorKind::Backend,
                    b::Stage::Allocate,
                    None,
                    None,
                ));
            }
            n.checked_add(BUFFER_EXCESS.with(std::cell::Cell::get))
                .ok_or_else(|| {
                    b::OperationError::new(b::ErrorKind::Overflow, b::Stage::Allocate, None, None)
                })?
        };
        v.try_reserve_exact(n).map_err(|_| {
            b::OperationError::new(b::ErrorKind::Backend, b::Stage::Allocate, None, None)
        })?;
        let actual = live
            .checked_add(size_of::<Vec<u8>>())
            .and_then(|n| n.checked_add(v.capacity()))
            .ok_or_else(|| {
                b::OperationError::new(b::ErrorKind::Overflow, b::Stage::Allocate, None, None)
            })?;
        self.check(actual).map_err(|e| {
            b::OperationError::new(e.kind(), b::Stage::Allocate, None, None)
                .with_required_size(actual)
        })?;
        Ok(v)
    }
}
fn decode_work(n: usize) -> Result<u64, b::OperationError> {
    u64::try_from(n)
        .ok()
        .and_then(|n| n.checked_mul(32))
        .and_then(|n| n.checked_add(1024))
        .ok_or_else(|| failure(b::ErrorKind::Overflow, None))
}
fn counts(bytes: &[u8]) -> Option<[u64; 4]> {
    input_scan();
    let mut numbers = [0; 4];
    let mut lines = bytes.strip_suffix(b"\n")?.split(|b| *b == b'\n');
    for n in &mut numbers {
        let line = lines.next()?;
        if line.is_empty() || line.len() > 20 || line.len() > 1 && line[0] == b'0' {
            return None;
        }
        let mut value = 0u64;
        for b in line {
            if !b.is_ascii_digit() {
                return None;
            }
            value = value.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
        }
        *n = value;
    }
    if lines.next().is_some() {
        None
    } else {
        Some(numbers)
    }
}
fn profile_line(bytes: &[u8]) -> Option<&str> {
    input_scan();
    let bytes = bytes.strip_suffix(b"\n")?;
    if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}
/// Closed whole-script dialect preflight. Reads only the immutable script;
/// no fixture byte, public BPF operation or effect is available here.
fn dialect_ok(i: &CaseInvocation) -> bool {
    let schema = i.script().schema_id().as_str();
    let core = schema == "bp03-host-v1";
    let json = cfg!(feature = "bpf-host-json") && schema == "bp03-host-json-v1";
    (core || json)
        && i.script().steps().len() == 1
        && !i.script().steps().iter().any(|s| {
            let arity = match s.operation().as_str() {
                "assess-filter" | "to-testkit-profile" | "from-testkit-profile" => 1,
                "import-observation" if json => 1,
                "context-applies" if json => 2,
                _ => return true,
            };
            s.inputs().len() != arity || !s.parameters().is_empty()
        })
}
/// Opaque consuming prepared call. It borrows the exact adapter and the exact
/// immutable invocation, owns measured response storage, and consumes itself
/// on execution. No public fields, Clone, Copy, Default or unchecked
/// constructor: a call cannot be reused, moved to another invocation, or
/// executed twice.
pub struct BpfPreparedCall<'a> {
    adapter: &'a mut BpfHostAdapter,
    invocation: &'a CaseInvocation,
    ready: PreparedBranch,
}
enum PreparedBranch {
    Ready(OneStepResponse),
    Binding(OneStepErrorResponse),
    Dialect(OneStepErrorResponse),
}
/// Map a refused publication back onto the exact error finish. `admit_output`
/// and `finish_observation` apply the same checks, so this branch is only
/// reached if joint allowance changed between the two checks; the original
/// admitted context is still moved into the error finisher, never dropped.
fn finish_output_refusal(response: OneStepResponse, failure: OneStepOutputFailure) -> CaseError {
    let mut diagnostic = OneStepDiagnostic::new(b"bpf:limit_exceeded/admission")
        .expect("fixed diagnostic fits admitted scratch");
    let required = match failure {
        OneStepOutputFailure::Length { required } => Some(required),
        OneStepOutputFailure::Capacity { required } => Some(required),
        OneStepOutputFailure::Overflow => None,
    };
    if let Some(n) = required {
        diagnostic
            .extend(b";required=")
            .expect("fixed diagnostic fits admitted scratch");
        diagnostic
            .decimal(n)
            .expect("fixed diagnostic fits admitted scratch");
    }
    response.finish_error(
        CaseErrorCategory::Refused,
        OneStepResponseStage::Admission,
        diagnostic,
        true,
        None,
    )
}
impl PreparedExecution for BpfPreparedCall<'_> {
    fn execute(self, fixture: &FixtureAccess<'_>) -> Result<Observation, CaseError> {
        let BpfPreparedCall {
            adapter,
            invocation,
            ready,
        } = self;
        match ready {
            PreparedBranch::Binding(response) => Err(response.finish_error(
                CaseErrorCategory::InvalidOutput,
                OneStepResponseStage::Binding,
                OneStepDiagnostic::new(b"run-limits-mismatch")
                    .expect("fixed diagnostic fits admitted scratch"),
            )),
            PreparedBranch::Dialect(response) => Err(response.finish_error(
                CaseErrorCategory::UnsupportedSchema,
                OneStepResponseStage::Preflight,
                OneStepDiagnostic::new(b"unsupported-dialect")
                    .expect("fixed diagnostic fits admitted scratch"),
            )),
            PreparedBranch::Ready(response) => {
                let bytes = match adapter.execute_operation(invocation.script(), fixture) {
                    Ok(bytes) => bytes,
                    Err(op) => {
                        return Err(response.finish_error(
                            op.category,
                            op.stage,
                            op.diagnostic,
                            op.attempted_step,
                            op.errno,
                        ));
                    }
                };
                // Only the returned bytes are operation-owned here: fixture
                // inputs are borrows, and every operation temporary except the
                // moved output (JSON paths drop their records before return)
                // has retired. The joint allowance is the stored ceiling.
                let ceiling = adapter.ceiling;
                let output = match response.admit_output(bytes, ceiling) {
                    Ok(output) => output,
                    Err(failure) => return Err(finish_output_refusal(response, failure)),
                };
                match response.finish_observation(output, ceiling) {
                    Ok(observation) => Ok(observation),
                    Err((response, failure)) => Err(finish_output_refusal(response, failure)),
                }
            }
        }
    }
}
impl ResponsePreparedAdapter for BpfHostAdapter {
    fn subject(&self) -> SubjectBinding {
        self.subject.clone()
    }
    type Prepared<'a>
        = BpfPreparedCall<'a>
    where
        Self: 'a;
    fn prepare_response<'a>(
        &'a mut self,
        invocation: &'a CaseInvocation,
    ) -> Result<Self::Prepared<'a>, ResponsePreparationFailure> {
        // The complete opaque call inline, including enum storage and both
        // borrows, is the outer basis. Replacing the component inline avoids
        // double counting.
        const CALL_INLINE: usize = size_of::<BpfPreparedCall<'_>>();
        if invocation.limits() != &self.run {
            let error_only = OneStepErrorResponse::prepare(
                invocation.key(),
                &self.run,
                self.reserve,
                CALL_INLINE,
            )?;
            return Ok(BpfPreparedCall {
                adapter: self,
                invocation,
                ready: PreparedBranch::Binding(error_only),
            });
        }
        if !dialect_ok(invocation) {
            let error_only = OneStepErrorResponse::prepare(
                invocation.key(),
                &self.run,
                self.reserve,
                CALL_INLINE,
            )?;
            return Ok(BpfPreparedCall {
                adapter: self,
                invocation,
                ready: PreparedBranch::Dialect(error_only),
            });
        }
        let step = &invocation.script().steps()[0];
        let response = OneStepResponse::prepare(
            invocation.key(),
            invocation.observation_schema(),
            step.step_id(),
            &self.run,
            self.reserve,
            CALL_INLINE,
        )?;
        Ok(BpfPreparedCall {
            adapter: self,
            invocation,
            ready: PreparedBranch::Ready(response),
        })
    }
    fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
        RetirementReport::new(
            RetirementReportValues {
                call_id: r.call_id(),
                owner: r.owner(),
                scope: r.scope().clone(),
                discovered: vec![],
                transitions: vec![],
                pending_snapshot: r.known_pending().to_vec(),
                complete: r.known_pending().is_empty() && r.uncertainty_ids().is_empty(),
                diagnostic: None,
            },
            &self.run,
        )
        .expect("existing request fits stored ceiling")
    }
}

#[cfg(feature = "bpf-host-json")]
fn encoded_length(v: &b::CapabilityObservation) -> Result<usize, b::OperationError> {
    // The frozen metadata algebra is implemented over public getters. Expected
    // lengths remain independently authored packaged literals, not this routine.
    fn text(n: usize) -> Result<usize, b::OperationError> {
        checked_add(n, 2)
    }
    fn hex(n: usize) -> Result<usize, b::OperationError> {
        text(
            n.checked_mul(2)
                .ok_or_else(|| failure(b::ErrorKind::Overflow, None))?,
        )
    }
    fn digits(mut n: u64) -> usize {
        let mut d = 1;
        while n >= 10 {
            n /= 10;
            d += 1;
        }
        d
    }
    fn object(fields: &[(&str, usize)]) -> Result<usize, b::OperationError> {
        let mut n = checked_add(2, fields.len() - 1)?;
        for (key, len) in fields {
            n = checked_add(n, checked_add(3 + key.len(), *len)?)?;
        }
        Ok(n)
    }
    fn kind_len(k: b::ErrorKind) -> Result<usize, b::OperationError> {
        Ok(match k {
            b::ErrorKind::InvalidInput => 13,
            b::ErrorKind::Malformed => 9,
            b::ErrorKind::Incompatible => 12,
            b::ErrorKind::Unsupported => 11,
            b::ErrorKind::Denied => 6,
            b::ErrorKind::Disappeared => 11,
            b::ErrorKind::Changed => 7,
            b::ErrorKind::LimitExceeded => 14,
            b::ErrorKind::Overflow => 8,
            b::ErrorKind::Backend => 7,
            b::ErrorKind::Poisoned => 8,
            _ => return Err(failure(b::ErrorKind::Unsupported, None)),
        })
    }
    fn stage_len(s: b::Stage) -> Result<usize, b::OperationError> {
        Ok(match s {
            b::Stage::Admission => 9,
            b::Stage::Metadata => 8,
            b::Stage::Allocate => 8,
            b::Stage::Read => 4,
            b::Stage::Attach => 6,
            b::Stage::Drain => 5,
            b::Stage::Retire => 6,
            b::Stage::BtfQuery => 9,
            b::Stage::Compile => 7,
            b::Stage::Inspect => 7,
            b::Stage::Execute => 7,
            _ => return Err(failure(b::ErrorKind::Unsupported, None)),
        })
    }
    let context = object(&[
        ("kernel_build", 66),
        ("btf", if v.context().btf.is_some() { 66 } else { 4 }),
        ("architecture", text(v.context().architecture.len())?),
        ("namespace_context", 66),
        ("security_context", 66),
        ("topology", 66),
    ])?;
    let error = if let Some(e) = v.operation_error() {
        object(&[
            ("kind", text(kind_len(e.kind())?)?),
            ("stage", text(stage_len(e.stage())?)?),
            (
                "raw_errno",
                if let Some(n) = e.raw_os_error() {
                    digits(u64::from(n.unsigned_abs())) + usize::from(n < 0)
                } else {
                    4
                },
            ),
            (
                "required_size",
                if let Some(n) = e.required_size() {
                    text(digits(
                        u64::try_from(n).map_err(|_| failure(b::ErrorKind::Overflow, None))?,
                    ))?
                } else {
                    4
                },
            ),
        ])?
    } else {
        4
    };
    let mut ids = 2;
    if !v.cause_evidence_ids().is_empty() {
        ids = checked_add(ids, v.cause_evidence_ids().len() - 1)?;
    }
    for id in v.cause_evidence_ids() {
        ids = checked_add(ids, text(id.len())?)?;
    }
    let cause_len = match v.cause() {
        b::DescribedCause::Permission => 10,
        b::DescribedCause::Verifier => 8,
        b::DescribedCause::License => 7,
        b::DescribedCause::UnsupportedOperation => 21,
        b::DescribedCause::Unknown => 7,
        _ => return Err(failure(b::ErrorKind::Unsupported, None)),
    };
    let cause = object(&[
        ("kind", text(cause_len)?),
        ("method", text(v.cause_method().len())?),
        ("evidence_ids", ids),
    ])?;
    let state = match v.state() {
        b::CapabilityState::Supported => 9,
        b::CapabilityState::Unsupported => 11,
        b::CapabilityState::Denied => 6,
        b::CapabilityState::Unknown => 7,
        b::CapabilityState::Incompatible => 12,
        _ => return Err(failure(b::ErrorKind::Unsupported, None)),
    };
    let stage = match v.stage() {
        b::EvidenceStage::Metadata => 8,
        b::EvidenceStage::Object => 6,
        b::EvidenceStage::Load => 4,
        b::EvidenceStage::Attach => 6,
        b::EvidenceStage::Behavior => 8,
        _ => return Err(failure(b::ErrorKind::Unsupported, None)),
    };
    let hazard = match v.hazard() {
        None => 4,
        Some(b::HazardState::Clean) => text(5)?,
        Some(b::HazardState::Affected) => text(8)?,
        Some(b::HazardState::Unknown) => text(7)?,
        _ => return Err(failure(b::ErrorKind::Unsupported, None)),
    };
    let origin = match v.claimed_origin() {
        b::ObservationOrigin::CallerDescribed => 16,
        b::ObservationOrigin::Imported => 8,
        _ => return Err(failure(b::ErrorKind::Unsupported, None)),
    };
    let outcome = match v.outcome() {
        b::ObservationOutcome::Completed => 9,
        b::ObservationOutcome::Refused => 7,
        b::ObservationOutcome::Incomplete => 10,
        _ => return Err(failure(b::ErrorKind::Unsupported, None)),
    };
    object(&[
        ("schema_version", 1),
        ("kind", text("scopebase-bpf-capability-observation".len())?),
        ("schema_revision", 1),
        ("claimed_origin", text(origin)?),
        ("object", 66),
        ("profile", text(v.profile().as_str().len())?),
        ("context", context),
        ("state", text(state)?),
        ("stage", text(stage)?),
        ("hazard", hazard),
        ("operation", text(v.operation().len())?),
        (
            "step_id",
            match v.step_id() {
                Some(s) => text(s.len())?,
                None => 4,
            },
        ),
        ("outcome", text(outcome)?),
        ("error", error),
        ("reason", hex(v.reason().len())?),
        ("diagnostic", hex(v.diagnostic().len())?),
        ("cause", cause),
    ])
}

#[cfg(test)]
thread_local! {static ENTRIES:std::cell::Cell<(usize,usize,usize)>=const{std::cell::Cell::new((0,0,0))};static BUFFER_EXCESS:std::cell::Cell<usize>=const{std::cell::Cell::new(0)};static BUFFER_FAIL:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};}
fn input_access() {
    #[cfg(test)]
    ENTRIES.with(|n| {
        let (a, b, c) = n.get();
        n.set((a + 1, b, c));
    });
}
fn input_scan() {
    #[cfg(test)]
    ENTRIES.with(|n| {
        let (a, b, c) = n.get();
        n.set((a, b + 1, c));
    });
}
fn operation_entry() {
    #[cfg(test)]
    ENTRIES.with(|n| {
        let (a, b, c) = n.get();
        n.set((a, b, c + 1));
    });
}
#[cfg(test)]
mod tests {
    use super::*;
    fn label(s: &str) -> Label {
        Label::parse(s).unwrap()
    }
    fn limits() -> b::Limits {
        b::Limits {
            input_bytes: 131072,
            retained_bytes: 262144,
            work_steps: 8388608,
            sites: 0,
            live_links: 0,
            pending_retirements: 0,
        }
    }
    fn subject(l: &RunLimits, capacity: usize) -> SubjectBinding {
        let mut name = String::with_capacity(capacity);
        name.push_str("scopebase-bpf");
        let d = Digest256::of_bytes(b"BP03 private model test");
        SubjectBinding::new(
            SubjectBindingValues {
                package_name: name,
                package_version: "0.1.0".into(),
                source_sha256: d,
                build_inputs_sha256: d,
                features: vec!["bpf-host".into()],
                backend: Some(
                    BackendBinding::new(
                        BackendBindingValues {
                            name: "descriptive-model".into(),
                            version: "1".into(),
                            source_sha256: d,
                        },
                        l,
                    )
                    .unwrap(),
                ),
                host: "x86_64-unknown-linux-gnu".into(),
                target: "x86_64-unknown-linux-gnu".into(),
                consumer: ConsumerBinding::new(
                    ConsumerBindingValues {
                        name: "bp03-test".into(),
                        build_inputs_sha256: d,
                        executable_sha256: d,
                    },
                    l,
                )
                .unwrap(),
                objects: vec![ArtifactBinding::new(
                    ArtifactBindingValues {
                        id: label("fixture-object"),
                        revision: 1,
                        role: ArtifactRole::FixtureInput,
                        length: 1,
                        sha256: d,
                    },
                    l,
                )
                .unwrap()],
                provenance: BindingProvenance::SelfReported {
                    reason: "private unit model".into(),
                },
            },
            l,
        )
        .unwrap()
    }
    fn invocation(l: &RunLimits, schema: &str, op: &str, slots: &[&str]) -> CaseInvocation {
        invocation_cell(l, schema, op, slots, "model", 1)
    }
    fn invocation_cell(
        l: &RunLimits,
        schema: &str,
        op: &str,
        slots: &[&str],
        cell: &str,
        attempt: u32,
    ) -> CaseInvocation {
        let script = serde_json::json!({"schema_version":1,"kind":"steps-v1","schema_id":schema,"steps":[{"step_id":"only-step","operation":op,"inputs":slots,"parameters":[]}]});
        let key = InvocationKey::new(
            InvocationKeyValues {
                run_id: RunId::parse("0123456789abcdef0123456789abcdef").unwrap(),
                case_key: CaseKey::new(
                    CaseKeyValues {
                        case_id: CaseId::parse("H22.model-filter").unwrap(),
                        case_version: 1,
                        cell_id: cell.into(),
                    },
                    l,
                )
                .unwrap(),
                attempt,
                operation_id: 1,
            },
            l,
        )
        .unwrap();
        CaseInvocation::new(
            CaseInvocationValues {
                key,
                observation_schema: SchemaBinding::new(
                    SchemaBindingValues {
                        id: label("bp03-result"),
                        revision: 1,
                    },
                    l,
                )
                .unwrap(),
                fixture_schema: SchemaBinding::new(
                    SchemaBindingValues {
                        id: label("bp03-fixture"),
                        revision: 1,
                    },
                    l,
                )
                .unwrap(),
                script: OperationScript::load(&serde_json::to_vec(&script).unwrap(), l).unwrap(),
                limits: l.clone(),
            },
            l,
        )
        .unwrap()
    }
    /// Drive the actual public prepared route: fallible admission first,
    /// then the consuming whole-call execution. Scalar preparation failure
    /// is a test defect here; tests that expect scalar failure call
    /// `prepare_response` directly.
    fn prepared(
        a: &mut BpfHostAdapter,
        i: &CaseInvocation,
        f: &FixtureAccess<'_>,
    ) -> Result<Observation, CaseError> {
        a.prepare_response(i).unwrap().execute(f)
    }
    /// Finish a scalar operation refusal through an actually admitted Ready
    /// response, exactly as the consuming call does. No fresh metadata copy.
    fn finish_refusal(a: &mut BpfHostAdapter, i: &CaseInvocation, refusal: OpRefusal) -> CaseError {
        let call = a.prepare_response(i).unwrap();
        match call.ready {
            PreparedBranch::Ready(response) => response.finish_error(
                refusal.category,
                refusal.stage,
                refusal.diagnostic,
                refusal.attempted_step,
                refusal.errno,
            ),
            _ => panic!("refusal finish needs an admitted Ready response"),
        }
    }
    fn full_error(
        e: &CaseError,
        i: &CaseInvocation,
        category: CaseErrorCategory,
        stage: &str,
        step: bool,
    ) {
        assert_eq!(e.key(), i.key());
        assert_eq!(*e.category(), category);
        assert_eq!(e.stage().as_str(), stage);
        assert_eq!(
            e.step_id().as_ref(),
            if step {
                Some(i.script().steps()[0].step_id())
            } else {
                None
            }
        );
        assert_eq!(*e.errno(), None);
        assert_eq!(*e.cause().cause(), RefusalCause::Unknown);
        assert_eq!(e.cause().method().as_str(), "bp03-model");
        assert_eq!(*e.cause().tier(), EvidenceTier::T0);
        assert!(e.cause().evidence_ids().is_empty());
        assert!(e.completed_steps().is_empty());
        assert!(e.partial_observation().is_none());
        assert!(e.effects().registrations().is_empty());
        assert!(*e.effects().complete());
    }
    #[test]
    fn stored_footprint_and_exact_response_reservation() {
        let l = RunLimits::default();
        let s = subject(&l, 70000);
        let independent = size_of::<BpfHostAdapter>()
            + s.package_name().capacity()
            + s.package_version().capacity()
            + s.host().capacity()
            + s.target().capacity()
            + s.consumer().name().capacity()
            + s.features().capacity() * size_of::<String>()
            + s.features().iter().map(String::capacity).sum::<usize>()
            + s.objects().capacity() * size_of::<ArtifactBinding>()
            + s.objects()
                .iter()
                .map(|a| bp03_label_capacity(a.id()))
                .sum::<usize>()
            + s.backend()
                .as_ref()
                .map(|v| v.name().capacity() + v.version().capacity())
                .unwrap()
            + match s.provenance() {
                BindingProvenance::SelfReported { reason } => reason.capacity(),
                _ => 0,
            };
        let f = 8192
            + size_of::<CaseError>()
                .max(size_of::<Observation>())
                .max(size_of::<RetirementReport>());
        let a = BpfHostAdapter::new(s, limits(), l.clone()).unwrap();
        assert_eq!(a.base, independent, "adapter.stored-actual-capacities");
        assert_eq!(a.reserve, f);
        for delta in [0, 1] {
            let s = subject(&l, 70000);
            let mut v = l.values();
            v.retained_bytes = (independent + f - delta) as u64;
            v.input_bytes = 4096;
            v.observation_bytes = 4096;
            v.vector_bytes = 4096;
            v.receipt_bytes = 4096;
            v.diagnostic_bytes = 128;
            let selected = RunLimits::new(v).unwrap();
            let result = BpfHostAdapter::new(s, limits(), selected);
            if delta == 0 {
                assert!(result.is_ok());
            } else {
                let e = match result {
                    Ok(_) => panic!("adapter B+F-1 admitted"),
                    Err(e) => e,
                };
                assert_eq!(e.kind(), HarnessErrorKind::LimitExceeded);
                assert_eq!(e.diagnostic(), "bp03 adapter admission");
            }
        }
    }
    #[test]
    fn zero_work_and_binding_have_no_payload_entry() {
        let l = RunLimits::default();
        let i = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
        let input = [FixtureInput::new(label("counts"), b"2\n2\n1\n0\n")];
        let fixture = FixtureAccess::new(&input, &[], EffectBatch::empty(&l), &l).unwrap();
        let mut a = BpfHostAdapter::new(
            subject(&l, 16),
            b::Limits {
                work_steps: 0,
                ..limits()
            },
            l.clone(),
        )
        .unwrap();
        ENTRIES.with(|c| c.set((0, 0, 0)));
        let e = prepared(&mut a, &i, &fixture).expect_err("adapter.work-before-scan");
        full_error(&e, &i, CaseErrorCategory::Refused, "admission", true);
        assert_eq!(
            ENTRIES.with(std::cell::Cell::get),
            (1, 0, 0),
            "adapter.work-before-scan"
        );
        let mut v = l.values();
        v.execution_ms -= 1;
        let changed = RunLimits::new(v).unwrap();
        let i = invocation(&changed, "wrong", "wrong", &[]);
        ENTRIES.with(|c| c.set((0, 0, 0)));
        let e = prepared(&mut a, &i, &fixture).unwrap_err();
        assert_eq!(
            (e.stage().as_str(), e.diagnostic_bytes().as_slice()),
            ("binding", b"run-limits-mismatch".as_slice()),
            "adapter.limit-binding-error"
        );
        full_error(&e, &i, CaseErrorCategory::InvalidOutput, "binding", false);
        assert_eq!(
            ENTRIES.with(std::cell::Cell::get),
            (0, 0, 0),
            "adapter.limit-binding"
        );
    }
    #[test]
    fn checked_composition_and_error_reserve() {
        let e = checked_add(usize::MAX, 1).unwrap_err();
        assert_eq!(
            (e.kind(), e.stage(), e.required_size()),
            (b::ErrorKind::Overflow, b::Stage::Admission, None)
        );
        let l = RunLimits::default();
        let mut a = BpfHostAdapter::new(subject(&l, 16), limits(), l.clone()).unwrap();
        let i = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
        let e = finish_refusal(&mut a, &i, BpfHostAdapter::library_refusal(e));
        full_error(&e, &i, CaseErrorCategory::Refused, "admission", true);
        assert_eq!(e.diagnostic_bytes(), b"bpf:overflow/admission");
        let e = finish_refusal(
            &mut a,
            &i,
            BpfHostAdapter::library_refusal(b::OperationError::new(
                b::ErrorKind::Backend,
                b::Stage::Allocate,
                None,
                None,
            )),
        );
        full_error(&e, &i, CaseErrorCategory::Refused, "allocate", true);
        assert_eq!(
            e.diagnostic_bytes(),
            b"bpf:backend/allocate",
            "codec.error-stage"
        );
    }
    #[test]
    fn prepared_source_profile_capacity_failure_is_exact_refusal() {
        let l = RunLimits::default();
        let mut a = BpfHostAdapter::new(subject(&l, 16), limits(), l.clone()).unwrap();
        let i = invocation(&l, "bp03-host-v1", "to-testkit-profile", &["profile"]);
        // Grammar twin: source-domain length/charset failures keep the
        // specified pure value on the prepared path, before and after the
        // exact-refusal fix.
        let grammar = b::ProfileId::new("Abc").unwrap_err();
        assert_eq!(
            (grammar.kind(), grammar.stage()),
            (b::ErrorKind::InvalidInput, b::Stage::Admission)
        );
        assert!(
            BpfHostAdapter::is_source_grammar_failure(&grammar),
            "adapter.source-grammar-twin"
        );
        let overlong = b::ProfileId::new(&"a".repeat(129)).unwrap_err();
        assert!(
            BpfHostAdapter::is_source_grammar_failure(&overlong),
            "adapter.source-length-is-grammar"
        );
        let input = [FixtureInput::new(label("profile"), b"Abc\n")];
        let fixture = FixtureAccess::new(&input, &[], EffectBatch::empty(&l), &l).unwrap();
        let v = prepared(&mut a, &i, &fixture).unwrap();
        assert_eq!(
            v.bytes(),
            b"source-id-error",
            "adapter.source-grammar-value"
        );
        // Over-capacity and allocation failures documented for the source
        // domain constructor route exactly, preserving kind+stage.
        let over_capacity =
            b::OperationError::new(b::ErrorKind::LimitExceeded, b::Stage::Allocate, None, None)
                .with_required_size(129);
        assert!(
            !BpfHostAdapter::is_source_grammar_failure(&over_capacity),
            "adapter.source-capacity-is-exact"
        );
        let e = finish_refusal(&mut a, &i, BpfHostAdapter::library_refusal(over_capacity));
        full_error(&e, &i, CaseErrorCategory::Refused, "allocate", true);
        assert_eq!(
            e.diagnostic_bytes(),
            b"bpf:limit_exceeded/allocate;required=129",
            "adapter.source-capacity-diagnostic"
        );
        let alloc_failure =
            b::OperationError::new(b::ErrorKind::Backend, b::Stage::Allocate, None, None);
        assert!(
            !BpfHostAdapter::is_source_grammar_failure(&alloc_failure),
            "adapter.source-allocation-is-exact"
        );
        let e = finish_refusal(&mut a, &i, BpfHostAdapter::library_refusal(alloc_failure));
        full_error(&e, &i, CaseErrorCategory::Refused, "allocate", true);
        assert_eq!(
            e.diagnostic_bytes(),
            b"bpf:backend/allocate",
            "adapter.source-allocation-diagnostic"
        );
    }
    #[test]
    fn retirement_retains_unexpected_custody() {
        use std::time::{Duration, Instant};
        let l = RunLimits::default();
        let mut a = BpfHostAdapter::new(subject(&l, 16), limits(), l.clone()).unwrap();
        let i = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
        for pending in [false, true] {
            for uncertainty in [false, true] {
                let refs = if pending {
                    vec![PendingEffectRef::new(
                        PendingEffectRefValues {
                            resource_id: label("unexpected"),
                            owner: Owner::Adapter,
                            origin: i.key().clone(),
                            identity_sha256: Digest256::of_bytes(b"unexpected native custody"),
                        },
                        &l,
                    )
                    .unwrap()]
                } else {
                    vec![]
                };
                let request = RetireRequest {
                    call_id: 1,
                    owner: Owner::Adapter,
                    scope: CleanupScope::Case(i.key().clone()),
                    deadline: Instant::now() + Duration::from_secs(1),
                    remaining: Duration::from_secs(1),
                    known_pending: refs,
                    uncertainty_ids: if uncertainty {
                        vec![label("uncertain")]
                    } else {
                        vec![]
                    },
                    remaining_records: 0,
                    remaining_retained_bytes: 0,
                };
                let report = a.retire(&request);
                assert_eq!(*report.call_id(), 1);
                assert_eq!(*report.owner(), Owner::Adapter);
                assert_eq!(report.scope(), request.scope());
                assert_eq!(report.pending_snapshot(), request.known_pending());
                assert_eq!(*report.complete(), !pending && !uncertainty);
                assert!(report.discovered().is_empty() && report.transitions().is_empty());
            }
        }
    }
    #[cfg(feature = "bpf-host-json")]
    fn independently_measure_d(v: &b::CapabilityObservation) -> usize {
        fn capacity(s: &[u8]) -> usize {
            let mut owned = Vec::<u8>::new();
            owned.try_reserve_exact(s.len()).unwrap();
            owned.capacity()
        }
        let mut n = size_of::<b::CapabilityObservation>();
        for bytes in [
            v.profile().as_str().as_bytes(),
            v.context().architecture.as_bytes(),
            v.operation().as_bytes(),
            v.step_id().unwrap_or("").as_bytes(),
            v.cause_method().as_bytes(),
            v.reason(),
            v.diagnostic(),
        ] {
            n += capacity(bytes);
        }
        let mut slots = Vec::<String>::new();
        slots
            .try_reserve_exact(v.cause_evidence_ids().len())
            .unwrap();
        n += slots.capacity() * size_of::<String>();
        for id in v.cause_evidence_ids() {
            n += capacity(id.as_bytes());
        }
        n
    }
    #[cfg(feature = "bpf-host-json")]
    #[test]
    fn joint_and_prefix_peaks_with_restored_twins() {
        let l = RunLimits::default();
        let raw = literal_input::OBSERVATION_INPUT;
        let direct = b::CapabilityObservation::from_json(raw, &limits()).unwrap();
        let d = independently_measure_d(&direct);
        assert_eq!(direct.retained_bytes(), d, "adapter.independent-D");
        assert_eq!(encoded_length(&direct).unwrap(), 1026);
        let mut result = Vec::<u8>::new();
        result.try_reserve_exact(5).unwrap();
        let joint = 2 * d + size_of::<Vec<u8>>() + result.capacity();
        let json = direct.to_json(&limits()).unwrap();
        let mut prefix = Vec::<u8>::new();
        prefix.try_reserve_exact(1035).unwrap();
        let prefixed = d + 2 * size_of::<Vec<u8>>() + json.capacity() + prefix.capacity();
        for (op, slots, peak) in [
            ("context-applies", vec!["base", "candidate"], joint),
            ("import-observation", vec!["record"], prefixed),
        ] {
            for delta in [1, 0] {
                let cap = peak - delta;
                let bp = b::Limits {
                    retained_bytes: cap,
                    ..limits()
                };
                assert!(b::CapabilityObservation::from_json(raw, &bp).is_ok());
                if op == "import-observation" {
                    assert!(direct.to_json(&bp).is_ok());
                }
                let mut a = BpfHostAdapter::new(subject(&l, 16), bp, l.clone()).unwrap();
                let i = invocation(&l, "bp03-host-json-v1", op, &slots);
                let inputs = slots
                    .iter()
                    .map(|s| FixtureInput::new(label(s), raw))
                    .collect::<Vec<_>>();
                let fixture = FixtureAccess::new(&inputs, &[], EffectBatch::empty(&l), &l).unwrap();
                match prepared(&mut a, &i, &fixture) {
                    Err(e) => {
                        assert_eq!(delta, 1);
                        assert_eq!(*e.category(), CaseErrorCategory::Refused);
                        assert!(
                            e.partial_observation().is_none() && e.completed_steps().is_empty()
                        );
                        assert_eq!(*e.cause().cause(), RefusalCause::Unknown);
                    }
                    Ok(v) => {
                        assert_eq!(delta, 0, "adapter.joint-retained / adapter.prefix-retained");
                        if op == "context-applies" {
                            assert_eq!(v.bytes(), b"true");
                        } else {
                            assert_eq!(&v.bytes()[..9], b"imported\n");
                            assert_eq!(&v.bytes()[9..], raw);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn actual_buffer_overgrant_and_allocation_errors() {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                BUFFER_EXCESS.with(|v| v.set(0));
                BUFFER_FAIL.with(|v| v.set(false));
            }
        }
        let l = RunLimits::default();
        let i = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
        let inputs = [FixtureInput::new(label("counts"), b"2\n2\n1\n0\n")];
        let fixture = FixtureAccess::new(&inputs, &[], EffectBatch::empty(&l), &l).unwrap();
        {
            let _reset = Reset;
            let mut a = BpfHostAdapter::new(
                subject(&l, 16),
                b::Limits {
                    retained_bytes: size_of::<Vec<u8>>() + 12,
                    ..limits()
                },
                l.clone(),
            )
            .unwrap();
            BUFFER_EXCESS.with(|v| v.set(32));
            let e = prepared(&mut a, &i, &fixture).unwrap_err();
            full_error(&e, &i, CaseErrorCategory::Refused, "allocate", true);
            assert!(std::str::from_utf8(e.diagnostic_bytes())
                .unwrap()
                .starts_with("bpf:limit_exceeded/allocate;required="));
        }
        {
            let _reset = Reset;
            let mut a = BpfHostAdapter::new(subject(&l, 16), limits(), l.clone()).unwrap();
            BUFFER_FAIL.with(|v| v.set(true));
            let e = prepared(&mut a, &i, &fixture).unwrap_err();
            full_error(&e, &i, CaseErrorCategory::Refused, "allocate", true);
            assert_eq!(e.diagnostic_bytes(), b"bpf:backend/allocate");
        }
    }
    #[test]
    fn prp01_actual_bpf_prepared_outer_charge() {
        use crate::observation::rsp01_test_support;
        let l = RunLimits::default();
        let mut a = BpfHostAdapter::new(subject(&l, 16), limits(), l.clone()).unwrap();
        let f = a.reserve;
        let base = a.base;
        let i = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
        let call = a.prepare_response(&i).unwrap();
        let admitted = match &call.ready {
            PreparedBranch::Ready(response) => response.admitted_bytes(),
            _ => panic!("valid dialect must prepare Ready"),
        };
        // Independent oracle: the owned buffers read back from the actual
        // response, with the measured complete-carrier basis replacing the
        // component inline term once. Never the recorded budget counter.
        let carrier = size_of::<BpfPreparedCall<'_>>();
        let basis = carrier
            .max(size_of::<OneStepResponse>())
            .max(size_of::<Observation>())
            .max(size_of::<CaseError>());
        let ready = match &call.ready {
            PreparedBranch::Ready(response) => response,
            _ => unreachable!(),
        };
        let inspected = rsp01_test_support::context_bytes(ready);
        let component_inline = size_of::<OneStepResponse>()
            .max(size_of::<Observation>())
            .max(size_of::<CaseError>());
        assert_eq!(
            admitted,
            inspected - component_inline + basis,
            "adapter.R independent carrier-basis charge"
        );
        assert!(admitted <= f, "adapter.R<=F: {admitted} <= {f}");
        let input = [FixtureInput::new(label("counts"), b"2\n2\n1\n0\n")];
        let fixture = FixtureAccess::new(&input, &[], EffectBatch::empty(&l), &l).unwrap();
        let v = call.execute(&fixture).unwrap();
        assert_eq!(v.key(), i.key());
        assert_eq!(v.schema_id().as_str(), "bp03-result");
        assert_eq!(*v.schema_revision(), 1);
        assert_eq!(v.completed_steps(), &[label("only-step")]);
        assert_eq!(v.bytes(), b"supported");
        assert!(v.effects().registrations().is_empty());
        let header = rsp01_test_support::observation_bytes(&v);
        assert!(header <= admitted, "adapter.Q<=R: {header} <= {admitted}");
        let demand = size_of::<Vec<u8>>() + v.bytes().capacity();
        let joint = (base + f + demand) as u64;
        assert!(
            joint <= l.retained_bytes(),
            "adapter.B+F+J<=retained: {joint}"
        );
    }
    #[test]
    fn prp01_actual_bpf_error_only_outer_charge() {
        use crate::observation::rsp01_test_support;
        let l = RunLimits::default();
        let i = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
        // Binding refusal branch: stored limits differ from invocation limits.
        let mut changed = l.values();
        changed.execution_ms -= 1;
        let mismatched = RunLimits::new(changed).unwrap();
        let mut bound = BpfHostAdapter::new(subject(&l, 16), limits(), mismatched).unwrap();
        let binding_call = bound.prepare_response(&i).unwrap();
        let binding = match &binding_call.ready {
            PreparedBranch::Binding(response) => response,
            _ => panic!("limits mismatch must prepare binding refusal"),
        };
        let binding_charge = binding.admitted_bytes();
        // Independent byte-exact oracle: the owned buffers read back from
        // the actual error response, with the measured complete-carrier
        // basis replacing the error component inline term once. Never the
        // recorded budget counter.
        let error_inspected = rsp01_test_support::error_context_bytes(binding);
        let error_component_inline = size_of::<OneStepErrorResponse>()
            .max(size_of::<Observation>())
            .max(size_of::<CaseError>());
        let error_basis = size_of::<BpfPreparedCall<'_>>()
            .max(size_of::<OneStepErrorResponse>())
            .max(size_of::<Observation>())
            .max(size_of::<CaseError>());
        assert_eq!(
            binding_charge,
            error_inspected - error_component_inline + error_basis,
            "error-only R independent carrier-basis charge"
        );
        // Deterministic: identical bytes admit identically.
        let repeat = match bound.prepare_response(&i).unwrap().ready {
            PreparedBranch::Binding(response) => response.admitted_bytes(),
            _ => unreachable!(),
        };
        assert_eq!(binding_charge, repeat, "error-only charge deterministic");
        assert!(
            binding_charge <= bound.reserve,
            "error R<=F: {binding_charge}"
        );
        // Dialect refusal branch admits under the same ceiling.
        let bad = invocation(&l, "wrong", "wrong", &[]);
        let mut a = BpfHostAdapter::new(subject(&l, 16), limits(), l.clone()).unwrap();
        let dialect = match a.prepare_response(&bad).unwrap().ready {
            PreparedBranch::Dialect(response) => response.admitted_bytes(),
            _ => panic!("unknown schema must prepare dialect refusal"),
        };
        assert!(dialect <= a.reserve, "dialect R<=F: {dialect}");
        // Key sensitivity: the maximum valid cell admits strictly more
        // storage than the short cell under identical limits.
        let maxed = invocation_cell(
            &l,
            "bp03-host-v1",
            "assess-filter",
            &["counts"],
            &"c".repeat(256),
            1,
        );
        let maxed_charge = match bound.prepare_response(&maxed).unwrap().ready {
            PreparedBranch::Binding(response) => response.admitted_bytes(),
            _ => unreachable!(),
        };
        assert!(
            maxed_charge > binding_charge,
            "longer valid cell admits more: {maxed_charge} > {binding_charge}"
        );
        assert!(
            maxed_charge <= bound.reserve,
            "maxed error R<=F: {maxed_charge}"
        );
        // Ready admits strictly more than error-only for the same key: schema
        // and step storage are simultaneous alternatives, never double
        // counted, never omitted from the Ready charge.
        let mut ready_adapter = BpfHostAdapter::new(subject(&l, 16), limits(), l.clone()).unwrap();
        let ready_charge = match ready_adapter.prepare_response(&i).unwrap().ready {
            PreparedBranch::Ready(response) => response.admitted_bytes(),
            _ => unreachable!(),
        };
        assert!(
            ready_charge > binding_charge,
            "Ready carries schema+step beyond error-only: {ready_charge}"
        );
    }
    #[test]
    fn prp02_bpf_repeated_copy_excess_no_fallback() {
        use crate::prepared::{ResponseBudget, ResponsePreparationComponent as Part};
        use crate::ResponsePreparationFailureKind as Kind;
        let l = RunLimits::default();
        let i = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
        // Every attempted key copy boundary rejects real overgrant with one
        // finite attempt and no fresh-fallback key, in copy order.
        for (excess_at, component) in [(0, Part::RunId), (1, Part::CaseId), (2, Part::CellId)] {
            let mut attempts = 0;
            let mut capacities = vec![];
            let mut allocate = |minimum: usize| {
                let mut text = String::new();
                let request = if attempts == excess_at {
                    minimum + 128
                } else {
                    minimum
                };
                text.try_reserve_exact(request).map_err(|_| ())?;
                capacities.push(text.capacity());
                attempts += 1;
                Ok(text)
            };
            let mut budget = ResponseBudget::new(0, 64).unwrap();
            let error = crate::ids::rsp01_copy_key_with(i.key(), &l, &mut budget, &mut allocate)
                .unwrap_err();
            assert_eq!(error.kind, Kind::CapacityExceeded);
            assert_eq!(error.component, component);
            assert_eq!(error.observed_bytes, Some(capacities.iter().sum()));
            assert_eq!(
                attempts,
                excess_at + 1,
                "capacity refusal must never attempt a fresh fallback key"
            );
        }
        // Adapter level: an armed overgrant seam fails every fresh attempt
        // identically; the disarmed restored twin admits identical bytes.
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                BUFFER_EXCESS.with(|v| v.set(0));
            }
        }
        let _reset = Reset;
        let inputs = [FixtureInput::new(label("counts"), b"2\n2\n1\n0\n")];
        let fixture = FixtureAccess::new(&inputs, &[], EffectBatch::empty(&l), &l).unwrap();
        let mut a = BpfHostAdapter::new(
            subject(&l, 16),
            b::Limits {
                retained_bytes: size_of::<Vec<u8>>() + 12,
                ..limits()
            },
            l.clone(),
        )
        .unwrap();
        BUFFER_EXCESS.with(|v| v.set(32));
        for attempt in 0..2 {
            let e = prepared(&mut a, &i, &fixture).unwrap_err();
            full_error(&e, &i, CaseErrorCategory::Refused, "allocate", true);
            assert!(
                std::str::from_utf8(e.diagnostic_bytes())
                    .unwrap()
                    .starts_with("bpf:limit_exceeded/allocate;required="),
                "repeated overgrant attempt {attempt} keeps exact demand"
            );
        }
        BUFFER_EXCESS.with(|v| v.set(0));
        let v = prepared(&mut a, &i, &fixture).unwrap();
        assert_eq!(
            v.bytes(),
            b"supported",
            "restored twin admits identical bytes"
        );
    }
    #[test]
    fn prp03_bpf_preparation_failure_and_overflow_are_scalar() {
        use crate::prepared::{ResponseBudget, ResponsePreparationComponent as Part};
        use crate::ResponsePreparationFailureKind as Kind;
        let l = RunLimits::default();
        let i = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
        // Fallible allocation at the first copy boundary is scalar: no key,
        // diagnostic source or partial context escapes.
        let mut budget = ResponseBudget::new(0, 4096).unwrap();
        let error = crate::ids::rsp01_copy_key_with(i.key(), &l, &mut budget, &mut |_| Err(()))
            .unwrap_err();
        assert_eq!(error.kind, Kind::Allocation);
        assert_eq!(error.component, Part::RunId);
        assert_eq!(error.requested_bytes, Some(32));
        assert_eq!(error.observed_bytes, None);
        // Checked composition overflow is scalar with exact component.
        let mut budget = ResponseBudget::new(usize::MAX - 1, usize::MAX).unwrap();
        let error = budget.reserve_minimum(2, Part::Total).unwrap_err();
        assert_eq!(error.kind, Kind::Overflow);
        assert_eq!(error.component, Part::Total);
        assert_eq!(error.requested_bytes, Some(2));
        assert_eq!(error.observed_bytes, None);
        // Adapter level: the response ceiling can never be exceeded through
        // public construction. Name/label maxima (256/96) bound every actual
        // copy far below F, and the constructor's B+F reservation admits the
        // maximum valid invocation: even the largest valid key, schema and
        // step prepare Ready. Scalar CapacityExceeded therefore stays a
        // defensive seam-level property, proved exact above.
        let maxed = invocation_cell(
            &l,
            "bp03-host-v1",
            "assess-filter",
            &["counts"],
            &"c".repeat(256),
            1,
        );
        let mut maxed_adapter = BpfHostAdapter::new(subject(&l, 16), limits(), l.clone()).unwrap();
        let maxed_ready = match maxed_adapter.prepare_response(&maxed) {
            Ok(call) => call,
            Err(error) => panic!(
                "maximum valid invocation must admit: {:?}/{:?}",
                error.kind, error.component
            ),
        };
        match maxed_ready.ready {
            PreparedBranch::Ready(_) => {}
            _ => panic!("maximum valid invocation must prepare Ready"),
        }
        // Restored twin with the same bytes shape minus the excess admits.
        let input = [FixtureInput::new(label("counts"), b"2\n2\n1\n0\n")];
        let fixture = FixtureAccess::new(&input, &[], EffectBatch::empty(&l), &l).unwrap();
        let mut fitting = BpfHostAdapter::new(subject(&l, 16), limits(), l.clone()).unwrap();
        let v = prepared(&mut fitting, &i, &fixture).unwrap();
        assert_eq!(v.bytes(), b"supported");
    }
    #[test]
    fn prp05_bpf_call_identity_and_borrows() {
        let l = RunLimits::default();
        let mut a = BpfHostAdapter::new(subject(&l, 16), limits(), l.clone()).unwrap();
        let first = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
        let input = [FixtureInput::new(label("counts"), b"2\n2\n1\n0\n")];
        let fixture = FixtureAccess::new(&input, &[], EffectBatch::empty(&l), &l).unwrap();
        // Distinct invocations admit distinct contexts; each result carries
        // its own key.
        let second = invocation_cell(
            &l,
            "bp03-host-v1",
            "to-testkit-profile",
            &["profile"],
            "model-2",
            2,
        );
        let profile_input = [FixtureInput::new(label("profile"), b"a\n")];
        let profile_fixture =
            FixtureAccess::new(&profile_input, &[], EffectBatch::empty(&l), &l).unwrap();
        let v1 = prepared(&mut a, &first, &fixture).unwrap();
        assert_eq!(v1.key(), first.key());
        let v2 = prepared(&mut a, &second, &profile_fixture).unwrap();
        assert_eq!(v2.key(), second.key());
        assert_ne!(v1.key(), v2.key());
        assert_eq!(v2.bytes(), b"ok:a");
        // Dropping a Ready call before execution releases pure metadata only:
        // no participation is recorded and the adapter serves the next call.
        let pending = a.prepare_response(&first).unwrap();
        drop(pending);
        let request = RetireRequest {
            call_id: 1,
            owner: Owner::Adapter,
            scope: CleanupScope::Case(first.key().clone()),
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(1),
            remaining: std::time::Duration::from_secs(1),
            known_pending: vec![],
            uncertainty_ids: vec![],
            remaining_records: 0,
            remaining_retained_bytes: 0,
        };
        let report = a.retire(&request);
        assert!(*report.complete());
        let v3 = prepared(&mut a, &first, &fixture).unwrap();
        assert_eq!(v3.bytes(), b"supported");
    }
    #[test]
    fn prp07_bpf_exact_prepared_success_and_error_fields() {
        let l = RunLimits::default();
        let mut a = BpfHostAdapter::new(subject(&l, 16), limits(), l.clone()).unwrap();
        // Exact success fields through the consuming call.
        let i = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
        let input = [FixtureInput::new(label("counts"), b"2\n2\n1\n0\n")];
        let fixture = FixtureAccess::new(&input, &[], EffectBatch::empty(&l), &l).unwrap();
        let v = prepared(&mut a, &i, &fixture).unwrap();
        assert_eq!(v.key(), i.key());
        assert_eq!(v.schema_id(), i.observation_schema().id());
        assert_eq!(v.schema_revision(), i.observation_schema().revision());
        assert_eq!(v.completed_steps(), &[label("only-step")]);
        assert_eq!(v.bytes(), b"supported");
        assert!(v.effects().registrations().is_empty());
        assert!(*v.effects().complete());
        // Exact error fields: missing fixture slot finishes the same admitted
        // key with the input refusal and no completed step.
        let missing = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
        let empty = FixtureAccess::new(&[], &[], EffectBatch::empty(&l), &l).unwrap();
        let e = prepared(&mut a, &missing, &empty).unwrap_err();
        full_error(
            &e,
            &missing,
            CaseErrorCategory::InvalidOutput,
            "input",
            true,
        );
        assert_eq!(e.diagnostic_bytes(), b"missing-input");
        assert_eq!(*e.errno(), None);
    }
    #[test]
    fn prp07_bpf_profile_resource_error_not_domain_error() {
        let l = RunLimits::default();
        let i = invocation(&l, "bp03-host-v1", "to-testkit-profile", &["profile"]);
        let input = [FixtureInput::new(label("profile"), b"a\n")];
        let fixture = FixtureAccess::new(&input, &[], EffectBatch::empty(&l), &l).unwrap();
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                BUFFER_FAIL.with(|v| v.set(false));
            }
        }
        let _reset = Reset;
        let mut a = BpfHostAdapter::new(subject(&l, 16), limits(), l.clone()).unwrap();
        // Valid grammar with a failing output allocation stays Refused with
        // the actual allocate stage and errno shape: a resource error is
        // never disguised as a domain receiving-id-error literal.
        BUFFER_FAIL.with(|v| v.set(true));
        let e = prepared(&mut a, &i, &fixture).unwrap_err();
        full_error(&e, &i, CaseErrorCategory::Refused, "allocate", true);
        assert_eq!(e.diagnostic_bytes(), b"bpf:backend/allocate");
        // Restored twin with identical bytes returns the domain literal.
        BUFFER_FAIL.with(|v| v.set(false));
        let v = prepared(&mut a, &i, &fixture).unwrap();
        assert_eq!(v.bytes(), b"ok:a");
        assert_eq!(v.completed_steps(), &[label("only-step")]);
        // Invalid receiving grammar without resource pressure keeps the pure
        // literal receiving-id-error result, not a Refused outcome.
        let bad = [FixtureInput::new(label("profile"), b"a/b\n")];
        let bad_fixture = FixtureAccess::new(&bad, &[], EffectBatch::empty(&l), &l).unwrap();
        let v = prepared(&mut a, &i, &bad_fixture).unwrap();
        assert_eq!(v.bytes(), b"receiving-id-error");
    }
    #[test]
    fn prp08_actual_bpf_prepared_joint_handoff() {
        let l = RunLimits::default();
        // Exact joint allowance: the operation's conservative entry live
        // bound (Vec inline plus its minimum reservation) fits the ceiling
        // precisely; minus one refuses before publication with no partial
        // payload or completed step. The final output demand is counted once
        // inside that same allowance.
        let exact = size_of::<Vec<u8>>() + 12;
        for (retained, fits) in [(exact, true), (exact - 1, false)] {
            let mut a = BpfHostAdapter::new(
                subject(&l, 16),
                b::Limits {
                    retained_bytes: retained,
                    ..limits()
                },
                l.clone(),
            )
            .unwrap();
            let i = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
            let input = [FixtureInput::new(label("counts"), b"2\n2\n1\n0\n")];
            let fixture = FixtureAccess::new(&input, &[], EffectBatch::empty(&l), &l).unwrap();
            match prepared(&mut a, &i, &fixture) {
                Ok(v) => {
                    assert!(fits, "joint minus-one must refuse");
                    assert_eq!(v.bytes(), b"supported");
                    let demand = size_of::<Vec<u8>>() + v.bytes().capacity();
                    assert!(
                        demand <= retained,
                        "output counted once in J: {demand} <= {retained}"
                    );
                }
                Err(e) => {
                    assert!(
                        !fits,
                        "exact joint allowance must admit: {}/{:?}/{:?}",
                        e.diagnostic_bytes().escape_ascii(),
                        e.category(),
                        e.stage()
                    );
                    assert_eq!(*e.category(), CaseErrorCategory::Refused);
                    assert!(e.partial_observation().is_none());
                    assert!(e.completed_steps().is_empty());
                    assert_eq!(
                        e.diagnostic_bytes(),
                        format!(
                            "bpf:limit_exceeded/admission;required={}",
                            a.base + a.reserve + exact
                        )
                        .as_bytes(),
                        "minus-one carries the exact joint demand"
                    );
                }
            }
        }
    }
    #[test]
    fn prp09_bpf_preparation_has_no_payload_entry() {
        let l = RunLimits::default();
        let mut a = BpfHostAdapter::new(subject(&l, 16), limits(), l.clone()).unwrap();
        // Preparation alone never touches fixture inputs or operation entry,
        // on any branch. The admitted call is dropped before execution.
        for i in [
            invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]),
            invocation(&l, "wrong", "wrong", &[]),
        ] {
            ENTRIES.with(|c| c.set((0, 0, 0)));
            let call = a.prepare_response(&i).unwrap();
            drop(call);
            assert_eq!(
                ENTRIES.with(std::cell::Cell::get),
                (0, 0, 0),
                "preparation performs no payload entry"
            );
        }
        let mut values = l.values();
        values.execution_ms -= 1;
        let changed = RunLimits::new(values).unwrap();
        let mismatched = invocation(&changed, "wrong", "wrong", &[]);
        ENTRIES.with(|c| c.set((0, 0, 0)));
        let call = a.prepare_response(&mismatched).unwrap();
        drop(call);
        assert_eq!(
            ENTRIES.with(std::cell::Cell::get),
            (0, 0, 0),
            "binding preparation performs no payload entry"
        );
    }
    #[test]
    fn prp11_bpf_prepared_scalar_failure_keeps_primary_cause() {
        use crate::ResponsePreparationComponent as Part;
        use crate::ResponsePreparationFailureKind as Kind;
        // A scalar preparation failure carries no keyed outcome: kind,
        // component and exact byte demands only. Through the real adapter it
        // is unreachable by public construction (name/label maxima keep every
        // actual copy below F), so the typed failure is supplied directly and
        // the dual-error policy is proved against the real engine error path.
        let failure = crate::ResponsePreparationFailure {
            kind: Kind::CapacityExceeded,
            component: Part::CellId,
            requested_bytes: Some(257),
            observed_bytes: Some(4096),
        };
        assert_eq!(failure.kind, Kind::CapacityExceeded);
        assert_eq!(failure.component, Part::CellId);
        // The dual-error policy keeps the scalar cause and position primary
        // even when the engine reports followup harness failure: the typed
        // API never replaces the cause with a friendly diagnostic.
        let engine_error = crate::prepared::PreparedRunError::from_engine(
            Err(crate::artifact::he(
                crate::HarnessErrorKind::LimitExceeded,
                "followup",
            )),
            Some((3, failure)),
        )
        .unwrap_err();
        assert_eq!(engine_error.schedule_index(), Some(3));
        assert_eq!(
            engine_error.preparation_failure(),
            Some(&failure),
            "scalar cause retained"
        );
        assert!(engine_error.followup_harness_error().is_some());
        assert!(engine_error.partial_report().is_none());
    }
    // BP03_CONTROL_TEST_INSERT
}

#[cfg(all(test, feature = "bpf-host-json"))]
#[path = "../../tests/fixtures/bp03/controls.rs"]
mod literal_input;
