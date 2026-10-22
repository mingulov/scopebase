// SPDX-License-Identifier: Apache-2.0
//! Bounded descriptive values. These types confer no native observation authority.
//!
//! ADAPT: P/w003 bpf-multi lib.rs:591-605,1179-1192 (2c2713e6):
//! fixed own/excluded predicate and all original populations. Hazard/denial are
//! separated from P/uretprobe_hazard.rs:34-50; no application policy is ported.
//! NEW: generic contexts, four-count priority, checked storage and codec glue.
use crate::{ArtifactId, ErrorKind, Limits, OperationError, Stage};
use std::{fmt, mem::size_of};
macro_rules! value_enum {($name:ident{$($variant:ident),+})=>{#[non_exhaustive] #[derive(Debug,Clone,Copy,PartialEq,Eq)] pub enum $name{$($variant),+}}}
value_enum!(CapabilityState {
    Supported,
    Unsupported,
    Denied,
    Unknown,
    Incompatible
});
value_enum!(EvidenceStage {
    Metadata,
    Object,
    Load,
    Attach,
    Behavior
});
value_enum!(HazardState {
    Clean,
    Affected,
    Unknown
});
value_enum!(ObservationOrigin {
    CallerDescribed,
    Imported
});
value_enum!(ObservationOutcome {
    Completed,
    Refused,
    Incomplete
});
value_enum!(DescribedCause {
    Permission,
    Verifier,
    License,
    UnsupportedOperation,
    Unknown
});
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileId(String);
impl fmt::Debug for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProfileId(<redacted>)")
    }
}
impl ProfileId {
    pub fn new(value: &str) -> Result<Self, OperationError> {
        if !profile_valid(value) {
            return Err(error(ErrorKind::InvalidInput, Stage::Admission, None));
        }
        let mut s = String::new();
        reserve_string(&mut s, value.len())?;
        if s.capacity() > 128 {
            return Err(error(
                ErrorKind::LimitExceeded,
                Stage::Allocate,
                Some(s.capacity()),
            ));
        }
        s.push_str(value);
        Ok(Self(s))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
fn profile_valid(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && matches!(s.as_bytes()[0],b'a'..=b'z'|b'0'..=b'9')
        && s.bytes()
            .skip(1)
            .all(|b| matches!(b,b'a'..=b'z'|b'0'..=b'9'|b'.'|b'_'|b'/'|b'-'))
}
#[derive(Clone, PartialEq, Eq)]
pub struct ProbeContext {
    pub kernel_build: [u8; 32],
    pub btf: Option<ArtifactId>,
    pub architecture: String,
    pub namespace_context: [u8; 32],
    pub security_context: [u8; 32],
    pub topology: [u8; 32],
}
impl fmt::Debug for ProbeContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProbeContext(<redacted>)")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbePopulation {
    pub expected_owned_hits: u64,
    pub observed_owned_hits: u64,
    pub independently_executed_excluded: u64,
    pub observed_excluded_hits: u64,
}
pub fn assess_filter_probe(p: &ProbePopulation) -> Result<CapabilityState, OperationError> {
    if p.observed_excluded_hits > 0
        || (p.observed_owned_hits > 0 && p.observed_owned_hits != p.expected_owned_hits)
    {
        Ok(CapabilityState::Incompatible)
    } else if p.expected_owned_hits == 0
        || p.observed_owned_hits == 0
        || p.independently_executed_excluded == 0
    {
        Ok(CapabilityState::Unknown)
    } else {
        Ok(CapabilityState::Supported)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationErrorSnapshot {
    kind: ErrorKind,
    stage: Stage,
    raw_errno: Option<i32>,
    required_size: Option<usize>,
}
impl OperationErrorSnapshot {
    pub fn from_error(e: &OperationError) -> Self {
        Self {
            kind: e.kind(),
            stage: e.stage(),
            raw_errno: e.raw_os_error(),
            required_size: e.required_size(),
        }
    }
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
    pub fn stage(&self) -> Stage {
        self.stage
    }
    pub fn raw_os_error(&self) -> Option<i32> {
        self.raw_errno
    }
    pub fn required_size(&self) -> Option<usize> {
        self.required_size
    }
}
#[derive(Clone, Copy)]
pub struct CauseDescriptionInput<'a> {
    pub cause: DescribedCause,
    pub method: &'a str,
    pub evidence_ids: &'a [&'a str],
}
#[derive(Clone, Copy)]
pub struct CapabilityObservationInput<'a> {
    pub object: &'a ArtifactId,
    pub profile: &'a ProfileId,
    pub context: &'a ProbeContext,
    pub state: CapabilityState,
    pub stage: EvidenceStage,
    pub hazard: Option<HazardState>,
    pub operation: &'a str,
    pub step_id: Option<&'a str>,
    pub outcome: ObservationOutcome,
    pub error: Option<OperationErrorSnapshot>,
    pub reason: &'a [u8],
    pub diagnostic: &'a [u8],
    pub cause: CauseDescriptionInput<'a>,
}
/// Immutable descriptive payload; sharing through a caller's Arc is explicit.
pub struct CapabilityObservation {
    object: ArtifactId,
    profile: ProfileId,
    context: ProbeContext,
    state: CapabilityState,
    stage: EvidenceStage,
    hazard: Option<HazardState>,
    origin: ObservationOrigin,
    claimed_origin: ObservationOrigin,
    operation: String,
    step_id: Option<String>,
    outcome: ObservationOutcome,
    error: Option<OperationErrorSnapshot>,
    reason: Vec<u8>,
    diagnostic: Vec<u8>,
    cause: DescribedCause,
    cause_method: String,
    evidence_ids: Vec<String>,
    retained: usize,
}
impl PartialEq for CapabilityObservation {
    fn eq(&self, o: &Self) -> bool {
        self.object == o.object
            && self.profile == o.profile
            && self.context == o.context
            && self.state == o.state
            && self.stage == o.stage
            && self.hazard == o.hazard
            && self.origin == o.origin
            && self.claimed_origin == o.claimed_origin
            && self.operation == o.operation
            && self.step_id == o.step_id
            && self.outcome == o.outcome
            && self.error == o.error
            && self.reason == o.reason
            && self.diagnostic == o.diagnostic
            && self.cause == o.cause
            && self.cause_method == o.cause_method
            && self.evidence_ids == o.evidence_ids
    }
}
impl Eq for CapabilityObservation {}
impl fmt::Debug for CapabilityObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,"CapabilityObservation {{ state: {:?}, stage: {:?}, origin: {:?}, outcome: {:?}, payload_present: {} }}",self.state,self.stage,self.origin,self.outcome,!self.reason.is_empty()||!self.diagnostic.is_empty())
    }
}
fn error(kind: ErrorKind, stage: Stage, required: Option<usize>) -> OperationError {
    let e = OperationError::new(kind, stage, None, None);
    match required {
        Some(n) => e.with_required_size(n),
        None => e,
    }
}
fn add(a: usize, b: usize, stage: Stage) -> Result<usize, OperationError> {
    a.checked_add(b)
        .ok_or_else(|| error(ErrorKind::Overflow, stage, None))
}
fn multiply(a: usize, b: usize, stage: Stage) -> Result<usize, OperationError> {
    a.checked_mul(b)
        .ok_or_else(|| error(ErrorKind::Overflow, stage, None))
}
fn label_valid(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 96
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .skip(1)
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
fn architecture_valid(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .skip(1)
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
#[cfg(test)]
thread_local! {static ALLOCATION_FAILURE:std::cell::Cell<Option<usize>>=const{std::cell::Cell::new(None)};static ALLOCATION_EXCESS:std::cell::Cell<usize>=const{std::cell::Cell::new(0)};}
fn allocation_entry() -> Result<(), OperationError> {
    #[cfg(test)]
    {
        let denied = ALLOCATION_FAILURE.with(|v| match v.get() {
            Some(0) => true,
            Some(n) => {
                v.set(Some(n - 1));
                false
            }
            None => false,
        });
        if denied {
            return Err(error(ErrorKind::Backend, Stage::Allocate, None));
        }
    }
    Ok(())
}
fn reserve_string(s: &mut String, n: usize) -> Result<(), OperationError> {
    allocation_entry()?;
    #[cfg(test)]
    let n = n
        .checked_add(ALLOCATION_EXCESS.with(std::cell::Cell::get))
        .ok_or_else(|| error(ErrorKind::Overflow, Stage::Allocate, None))?;
    s.try_reserve_exact(n)
        .map_err(|_| error(ErrorKind::Backend, Stage::Allocate, None))
}
fn reserve_vec<T>(v: &mut Vec<T>, n: usize) -> Result<(), OperationError> {
    allocation_entry()?;
    #[cfg(test)]
    let n = n
        .checked_add(ALLOCATION_EXCESS.with(std::cell::Cell::get))
        .ok_or_else(|| error(ErrorKind::Overflow, Stage::Allocate, None))?;
    v.try_reserve_exact(n)
        .map_err(|_| error(ErrorKind::Backend, Stage::Allocate, None))
}
struct Charge {
    bytes: usize,
    cap: usize,
}
impl Charge {
    fn check(&self, stage: Stage) -> Result<(), OperationError> {
        if self.bytes > self.cap {
            Err(error(ErrorKind::LimitExceeded, stage, Some(self.bytes)))
        } else {
            Ok(())
        }
    }
    fn replace(&mut self, requested: usize, actual: usize) -> Result<(), OperationError> {
        self.bytes = self
            .bytes
            .checked_sub(requested)
            .and_then(|n| n.checked_add(actual))
            .ok_or_else(|| error(ErrorKind::Overflow, Stage::Allocate, None))?;
        self.check(Stage::Allocate)
    }
    fn string(&mut self, s: &str) -> Result<String, OperationError> {
        let mut v = String::new();
        reserve_string(&mut v, s.len())?;
        self.replace(s.len(), v.capacity())?;
        v.push_str(s);
        Ok(v)
    }
    fn bytes(&mut self, s: &[u8]) -> Result<Vec<u8>, OperationError> {
        let mut v = Vec::new();
        reserve_vec(&mut v, s.len())?;
        self.replace(s.len(), v.capacity())?;
        v.extend_from_slice(s);
        Ok(v)
    }
}
#[derive(Clone, Copy)]
enum Blob<'a> {
    Bytes(&'a [u8]),
    #[cfg(feature = "json")]
    Hex(&'a str),
}
impl Blob<'_> {
    fn len(self) -> usize {
        match self {
            Self::Bytes(b) => b.len(),
            #[cfg(feature = "json")]
            Self::Hex(s) => s.len() / 2,
        }
    }
}
#[derive(Clone, Copy)]
struct ContextParts<'a> {
    kernel_build: [u8; 32],
    btf: Option<ArtifactId>,
    architecture: &'a str,
    namespace_context: [u8; 32],
    security_context: [u8; 32],
    topology: [u8; 32],
}
struct Parts<'a> {
    object: &'a ArtifactId,
    profile: &'a str,
    context: ContextParts<'a>,
    state: CapabilityState,
    stage: EvidenceStage,
    hazard: Option<HazardState>,
    operation: &'a str,
    step_id: Option<&'a str>,
    outcome: ObservationOutcome,
    error: Option<OperationErrorSnapshot>,
    reason: Blob<'a>,
    diagnostic: Blob<'a>,
    cause: CauseDescriptionInput<'a>,
}
impl<'a> Parts<'a> {
    fn from_input(i: CapabilityObservationInput<'a>) -> Self {
        Self {
            object: i.object,
            profile: i.profile.as_str(),
            context: ContextParts {
                kernel_build: i.context.kernel_build,
                btf: i.context.btf,
                architecture: &i.context.architecture,
                namespace_context: i.context.namespace_context,
                security_context: i.context.security_context,
                topology: i.context.topology,
            },
            state: i.state,
            stage: i.stage,
            hazard: i.hazard,
            operation: i.operation,
            step_id: i.step_id,
            outcome: i.outcome,
            error: i.error,
            reason: Blob::Bytes(i.reason),
            diagnostic: Blob::Bytes(i.diagnostic),
            cause: i.cause,
        }
    }
}
impl Charge {
    fn blob(&mut self, source: Blob<'_>) -> Result<Vec<u8>, OperationError> {
        match source {
            Blob::Bytes(b) => self.bytes(b),
            #[cfg(feature = "json")]
            Blob::Hex(s) => {
                let mut v = Vec::new();
                reserve_vec(&mut v, s.len() / 2)?;
                self.replace(s.len() / 2, v.capacity())?;
                for pair in s.as_bytes().chunks_exact(2) {
                    v.push(json::nibble(pair[0]) * 16 + json::nibble(pair[1]));
                }
                Ok(v)
            }
        }
    }
}
impl CapabilityObservation {
    pub fn new(i: CapabilityObservationInput<'_>, l: &Limits) -> Result<Self, OperationError> {
        Self::construct(Parts::from_input(i), l)
    }
    fn construct(i: Parts<'_>, l: &Limits) -> Result<Self, OperationError> {
        let stage = Stage::Admission;
        if i.cause.evidence_ids.len() > 16 {
            return Err(error(ErrorKind::LimitExceeded, stage, None));
        }
        for (n, max) in [
            (i.profile.len(), 128),
            (i.context.architecture.len(), 64),
            (i.operation.len(), 96),
            (i.step_id.map_or(0, str::len), 96),
            (i.cause.method.len(), 96),
            (i.reason.len(), 4096),
            (i.diagnostic.len(), 16384),
        ] {
            if n > max {
                return Err(error(ErrorKind::LimitExceeded, stage, Some(n)));
            }
        }
        for s in i.cause.evidence_ids {
            if s.len() > 96 {
                return Err(error(ErrorKind::LimitExceeded, stage, Some(s.len())));
            }
        }
        let mut v = 0;
        for n in [
            i.profile.len(),
            i.context.architecture.len(),
            i.operation.len(),
            i.step_id.map_or(0, str::len),
            i.cause.method.len(),
            i.reason.len(),
            i.diagnostic.len(),
        ] {
            v = add(v, n, stage)?;
        }
        for s in i.cause.evidence_ids {
            v = add(v, s.len(), stage)?;
        }
        let p = add(
            add(256, v, stage)?,
            if i.context.btf.is_some() { 32 } else { 0 },
            stage,
        )?;
        if p > l.input_bytes.min(65536) {
            return Err(error(ErrorKind::LimitExceeded, stage, Some(p)));
        }
        let p64 = u64::try_from(p).map_err(|_| error(ErrorKind::Overflow, stage, None))?;
        let w = p64
            .checked_mul(8)
            .and_then(|n| n.checked_add(128))
            .and_then(|n| n.checked_add(8 * i.cause.evidence_ids.len() as u64))
            .ok_or_else(|| error(ErrorKind::Overflow, stage, None))?;
        if w > l.work_steps {
            return Err(error(ErrorKind::LimitExceeded, stage, None));
        }
        let min = add(
            add(size_of::<Self>(), v, stage)?,
            multiply(i.cause.evidence_ids.len(), size_of::<String>(), stage)?,
            stage,
        )?;
        let mut charge = Charge {
            bytes: min,
            cap: l.retained_bytes.min(131072),
        };
        charge.check(stage)?;
        if !profile_valid(i.profile)
            || !architecture_valid(&i.context.architecture)
            || !label_valid(i.operation)
            || i.step_id.is_some_and(|s| !label_valid(s))
            || !label_valid(i.cause.method)
            || i.cause.evidence_ids.iter().any(|s| !label_valid(s))
            || i.cause.evidence_ids.windows(2).any(|s| s[0] >= s[1])
        {
            return Err(error(ErrorKind::InvalidInput, stage, None));
        }
        if matches!(i.outcome, ObservationOutcome::Completed) && i.error.is_some()
            || matches!(i.outcome, ObservationOutcome::Refused) && i.error.is_none()
        {
            return Err(error(ErrorKind::InvalidInput, stage, None));
        }
        let profile = charge.string(i.profile)?;
        if profile.capacity() > 128 {
            return Err(error(
                ErrorKind::LimitExceeded,
                Stage::Allocate,
                Some(profile.capacity()),
            ));
        }
        let profile = ProfileId(profile);
        let architecture = charge.string(&i.context.architecture)?;
        let operation = charge.string(i.operation)?;
        let step_id = i.step_id.map(|s| charge.string(s)).transpose()?;
        let cause_method = charge.string(i.cause.method)?;
        let reason = charge.blob(i.reason)?;
        let diagnostic = charge.blob(i.diagnostic)?;
        let mut evidence_ids = Vec::new();
        reserve_vec(&mut evidence_ids, i.cause.evidence_ids.len())?;
        charge.replace(
            multiply(i.cause.evidence_ids.len(), size_of::<String>(), stage)?,
            multiply(
                evidence_ids.capacity(),
                size_of::<String>(),
                Stage::Allocate,
            )?,
        )?;
        for s in i.cause.evidence_ids {
            evidence_ids.push(charge.string(s)?);
        }
        Ok(Self {
            object: *i.object,
            profile,
            context: ProbeContext {
                kernel_build: i.context.kernel_build,
                btf: i.context.btf,
                architecture,
                namespace_context: i.context.namespace_context,
                security_context: i.context.security_context,
                topology: i.context.topology,
            },
            state: i.state,
            stage: i.stage,
            hazard: i.hazard,
            origin: ObservationOrigin::CallerDescribed,
            claimed_origin: ObservationOrigin::CallerDescribed,
            operation,
            step_id,
            outcome: i.outcome,
            error: i.error,
            reason,
            diagnostic,
            cause: i.cause.cause,
            cause_method,
            evidence_ids,
            retained: charge.bytes,
        })
    }
    pub fn state(&self) -> CapabilityState {
        self.state
    }
    pub fn stage(&self) -> EvidenceStage {
        self.stage
    }
    pub fn hazard(&self) -> Option<HazardState> {
        self.hazard
    }
    pub fn origin(&self) -> ObservationOrigin {
        self.origin
    }
    pub fn claimed_origin(&self) -> ObservationOrigin {
        self.claimed_origin
    }
    pub fn object(&self) -> &ArtifactId {
        &self.object
    }
    pub fn profile(&self) -> &ProfileId {
        &self.profile
    }
    pub fn context(&self) -> &ProbeContext {
        &self.context
    }
    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn step_id(&self) -> Option<&str> {
        self.step_id.as_deref()
    }
    pub fn outcome(&self) -> ObservationOutcome {
        self.outcome
    }
    pub fn operation_error(&self) -> Option<&OperationErrorSnapshot> {
        self.error.as_ref()
    }
    pub fn reason(&self) -> &[u8] {
        &self.reason
    }
    pub fn diagnostic(&self) -> &[u8] {
        &self.diagnostic
    }
    pub fn cause(&self) -> DescribedCause {
        self.cause
    }
    pub fn cause_method(&self) -> &str {
        &self.cause_method
    }
    pub fn cause_evidence_ids(&self) -> &[String] {
        &self.evidence_ids
    }
    pub fn retained_bytes(&self) -> usize {
        self.retained
    }
    pub fn applies_to(
        &self,
        object: &ArtifactId,
        profile: &ProfileId,
        context: &ProbeContext,
    ) -> bool {
        self.object == *object && self.profile == *profile && self.context == *context
    }
}
#[cfg(feature = "json")]
mod json;

#[cfg(test)]
fn measured_retained(v: &CapabilityObservation) -> usize {
    // Independent test inspection: no production retained_bytes/Charge call.
    size_of::<CapabilityObservation>()
        + v.profile.0.capacity()
        + v.context.architecture.capacity()
        + v.operation.capacity()
        + v.step_id.as_ref().map_or(0, String::capacity)
        + v.reason.capacity()
        + v.diagnostic.capacity()
        + v.cause_method.capacity()
        + v.evidence_ids.capacity() * size_of::<String>()
        + v.evidence_ids.iter().map(String::capacity).sum::<usize>()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn limits() -> Limits {
        Limits {
            input_bytes: 65536,
            retained_bytes: 131072,
            work_steps: 8388608,
            sites: 0,
            live_links: 0,
            pending_retirements: 0,
        }
    }
    fn setup() -> (ArtifactId, ProfileId, ProbeContext) {
        (
            ArtifactId([1; 32]),
            ProfileId::new("bounded").unwrap(),
            ProbeContext {
                kernel_build: [2; 32],
                btf: None,
                architecture: "x86_64".into(),
                namespace_context: [3; 32],
                security_context: [4; 32],
                topology: [5; 32],
            },
        )
    }
    fn input<'a>(
        o: &'a ArtifactId,
        p: &'a ProfileId,
        c: &'a ProbeContext,
    ) -> CapabilityObservationInput<'a> {
        CapabilityObservationInput {
            object: o,
            profile: p,
            context: c,
            state: CapabilityState::Unknown,
            stage: EvidenceStage::Metadata,
            hazard: None,
            operation: "op",
            step_id: Some("only-step"),
            outcome: ObservationOutcome::Completed,
            error: None,
            reason: b"binary\0\xff",
            diagnostic: b"opaque\xff",
            cause: CauseDescriptionInput {
                cause: DescribedCause::Unknown,
                method: "model",
                evidence_ids: &["a", "b"],
            },
        }
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ALLOCATION_FAILURE.with(|v| v.set(None));
            ALLOCATION_EXCESS.with(|v| v.set(0));
        }
    }
    #[test]
    fn actual_owned_capacities_are_charged() {
        let (o, p, c) = setup();
        let v = CapabilityObservation::new(input(&o, &p, &c), &limits()).unwrap();
        assert_eq!(v.retained_bytes(), measured_retained(&v));
        let mut c = c;
        c.architecture.reserve(50000);
        let other = CapabilityObservation::new(input(&o, &p, &c), &limits()).unwrap();
        assert_eq!(other, v, "capacity is not semantic equality");
        assert_eq!(other.retained_bytes(), measured_retained(&other));
    }
    #[test]
    fn every_constructor_allocation_failure_is_backend_allocate() {
        let (o, p, c) = setup();
        for index in 0..10 {
            let _reset = Reset;
            ALLOCATION_FAILURE.with(|v| v.set(Some(index)));
            let e = CapabilityObservation::new(input(&o, &p, &c), &limits()).unwrap_err();
            assert_eq!(
                (e.kind(), e.stage(), e.raw_os_error(), e.required_size()),
                (ErrorKind::Backend, Stage::Allocate, None, None),
                "allocation-stage preservation at {index}"
            );
        }
    }
    #[test]
    fn independent_zero_caps() {
        let (o, p, c) = setup();
        let i = input(&o, &p, &c);
        for field in 0..3 {
            let mut l = limits();
            match field {
                0 => l.input_bytes = 0,
                1 => l.work_steps = 0,
                2 => l.retained_bytes = 0,
                _ => unreachable!(),
            };
            let _reset = Reset;
            ALLOCATION_FAILURE.with(|v| v.set(Some(0)));
            let e = CapabilityObservation::new(i, &l).unwrap_err();
            assert_eq!(
                (e.kind(), e.stage()),
                (ErrorKind::LimitExceeded, Stage::Admission)
            );
        }
    }
    #[test]
    fn observed_capacity_refusals_and_checked_overflow() {
        let (o, p, c) = setup();
        let baseline = CapabilityObservation::new(input(&o, &p, &c), &limits()).unwrap();
        let d = measured_retained(&baseline);
        {
            let _reset = Reset;
            ALLOCATION_EXCESS.with(|n| n.set(1024));
            let e = CapabilityObservation::new(
                input(&o, &p, &c),
                &Limits {
                    retained_bytes: d,
                    ..limits()
                },
            )
            .unwrap_err();
            assert_eq!(
                (e.kind(), e.stage()),
                (ErrorKind::LimitExceeded, Stage::Allocate)
            );
            assert_eq!(e.required_size(), Some(d + 1024));
            let e = ProfileId::new("a").unwrap_err();
            assert_eq!(
                (e.kind(), e.stage(), e.required_size()),
                (ErrorKind::LimitExceeded, Stage::Allocate, Some(1025))
            );
        }
        let mut charge = Charge {
            bytes: d,
            cap: usize::MAX,
        };
        let e = charge.replace(0, usize::MAX).unwrap_err();
        assert_eq!(
            (e.kind(), e.stage(), e.required_size()),
            (ErrorKind::Overflow, Stage::Allocate, None)
        );
    }

    #[test]
    fn nested_profile_preserves_its_observed_capacity_bound() {
        let (o, p, c) = setup();
        let _reset = Reset;
        ALLOCATION_EXCESS.with(|n| n.set(128));
        let e = CapabilityObservation::new(input(&o, &p, &c), &limits()).unwrap_err();
        assert_eq!(
            (e.kind(), e.stage(), e.required_size()),
            (ErrorKind::LimitExceeded, Stage::Allocate, Some(135)),
            "nested-profile.capacity"
        );
    }
}
