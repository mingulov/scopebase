// SPDX-License-Identifier: Apache-2.0
//! Restricted ASCII schema 1. Shape is borrowed and precedes all semantics.
use super::*;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::{cell::Cell, marker::PhantomData};
#[derive(Default)]
struct Fault {
    count: Cell<bool>,
}
struct Seed<'a, T> {
    fault: &'a Fault,
    marker: PhantomData<T>,
}
impl<'a, T> Seed<'a, T> {
    fn new(fault: &'a Fault) -> Self {
        Self {
            fault,
            marker: PhantomData,
        }
    }
}
trait Borrowed<'de>: Sized {
    fn read<D: de::Deserializer<'de>>(d: D, f: &Fault) -> Result<Self, D::Error>;
}
impl<'de, T: Borrowed<'de>> DeserializeSeed<'de> for Seed<'_, T> {
    type Value = T;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<T, D::Error> {
        T::read(d, self.fault)
    }
}
impl<'de> Borrowed<'de> for &'de str {
    fn read<D: de::Deserializer<'de>>(d: D, _: &Fault) -> Result<Self, D::Error> {
        <Self as serde::Deserialize>::deserialize(d)
    }
}
impl<'de> Borrowed<'de> for u64 {
    fn read<D: de::Deserializer<'de>>(d: D, _: &Fault) -> Result<Self, D::Error> {
        <Self as serde::Deserialize>::deserialize(d)
    }
}
impl<'de, T: Borrowed<'de>> Borrowed<'de> for Option<T> {
    fn read<D: de::Deserializer<'de>>(d: D, f: &Fault) -> Result<Self, D::Error> {
        struct Nullable<'a, T>(&'a Fault, PhantomData<T>);
        impl<'de, T: Borrowed<'de>> Visitor<'de> for Nullable<'_, T> {
            type Value = Option<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("nullable scalar")
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_some<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
                T::read(d, self.0).map(Some)
            }
        }
        d.deserialize_option(Nullable(f, PhantomData))
    }
}
macro_rules! borrowed_object {($name:ident{$($field:ident:$ty:ty),+$(,)?})=>{
 struct $name<'de>{$($field:$ty),+}
 impl<'de>Borrowed<'de> for $name<'de>{fn read<D:de::Deserializer<'de>>(d:D,fault:&Fault)->Result<Self,D::Error>{
 struct Object<'a>(&'a Fault);impl<'de>Visitor<'de> for Object<'_>{type Value=$name<'de>;fn expecting(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.write_str("fixed object")}
 fn visit_map<M:MapAccess<'de>>(self,mut map:M)->Result<Self::Value,M::Error>{$(let mut $field:Option<$ty>=None;)+
 while let Some(key)=map.next_key::<&'de str>()?{match key{$(stringify!($field)=>{if $field.is_some(){return Err(de::Error::custom("duplicate member"));}$field=Some(map.next_value_seed(Seed::<$ty>::new(self.0))?);},)+_=>return Err(de::Error::custom("unknown member"))}}
 Ok($name{$($field:$field.ok_or_else(||de::Error::custom("missing member"))?),+})}}
 d.deserialize_map(Object(fault))}}
};}
#[derive(Clone, Copy)]
enum Integer {
    Signed(i64),
    Unsigned(u64),
}
impl<'de> Borrowed<'de> for Integer {
    fn read<D: de::Deserializer<'de>>(d: D, _: &Fault) -> Result<Self, D::Error> {
        struct Number;
        impl<'de> Visitor<'de> for Number {
            type Value = Integer;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("integer")
            }
            fn visit_i64<E: de::Error>(self, n: i64) -> Result<Integer, E> {
                Ok(Integer::Signed(n))
            }
            fn visit_u64<E: de::Error>(self, n: u64) -> Result<Integer, E> {
                Ok(Integer::Unsigned(n))
            }
        }
        d.deserialize_any(Number)
    }
}
struct Ids<'de> {
    values: [&'de str; 16],
    len: usize,
}
impl<'de> Borrowed<'de> for Ids<'de> {
    fn read<D: de::Deserializer<'de>>(d: D, fault: &Fault) -> Result<Self, D::Error> {
        struct Array<'a>(&'a Fault);
        impl<'de> Visitor<'de> for Array<'_> {
            type Value = Ids<'de>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded string array")
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                let mut ids = Ids {
                    values: [""; 16],
                    len: 0,
                };
                while let Some(s) = seq.next_element_seed(Seed::<&'de str>::new(self.0))? {
                    if ids.len == 16 {
                        self.0.count.set(true);
                        return Err(de::Error::custom("evidence count"));
                    }
                    ids.values[ids.len] = s;
                    ids.len += 1;
                }
                Ok(ids)
            }
        }
        d.deserialize_seq(Array(fault))
    }
}
borrowed_object!(RawContext{kernel_build:&'de str,btf:Option<&'de str>,architecture:&'de str,namespace_context:&'de str,security_context:&'de str,topology:&'de str});
borrowed_object!(RawError{kind:&'de str,stage:&'de str,raw_errno:Option<Integer>,required_size:Option<&'de str>});
borrowed_object!(RawCause{kind:&'de str,method:&'de str,evidence_ids:Ids<'de>});
borrowed_object!(Raw{schema_version:u64,kind:&'de str,schema_revision:u64,claimed_origin:&'de str,object:&'de str,profile:&'de str,context:RawContext<'de>,state:&'de str,stage:&'de str,hazard:Option<&'de str>,operation:&'de str,step_id:Option<&'de str>,outcome:&'de str,error:Option<RawError<'de>>,reason:&'de str,diagnostic:&'de str,cause:RawCause<'de>});
fn malformed() -> OperationError {
    error(ErrorKind::Malformed, Stage::Inspect, None)
}
fn overflow() -> OperationError {
    error(ErrorKind::Overflow, Stage::Inspect, None)
}
fn unsupported() -> OperationError {
    error(ErrorKind::Unsupported, Stage::Inspect, None)
}
macro_rules! tokens{($name:ident,$parse:ident,$ty:ident,{$($v:ident=>$text:literal),+})=>{
 fn $name(v:$ty)->Result<&'static str,OperationError>{#[allow(unreachable_patterns)]match v{$($ty::$v=>Ok($text),)+_=>Err(unsupported())}}
 fn $parse(s:&str)->Result<$ty,OperationError>{match s{$($text=>Ok($ty::$v),)+_=>Err(malformed())}}
};}
tokens!(state_token,parse_state,CapabilityState,{Supported=>"supported",Unsupported=>"unsupported",Denied=>"denied",Unknown=>"unknown",Incompatible=>"incompatible"});
tokens!(stage_token,parse_stage,EvidenceStage,{Metadata=>"metadata",Object=>"object",Load=>"load",Attach=>"attach",Behavior=>"behavior"});
tokens!(hazard_token,parse_hazard,HazardState,{Clean=>"clean",Affected=>"affected",Unknown=>"unknown"});
tokens!(origin_token,parse_origin,ObservationOrigin,{CallerDescribed=>"caller_described",Imported=>"imported"});
tokens!(outcome_token,parse_outcome,ObservationOutcome,{Completed=>"completed",Refused=>"refused",Incomplete=>"incomplete"});
tokens!(cause_token,parse_cause,DescribedCause,{Permission=>"permission",Verifier=>"verifier",License=>"license",UnsupportedOperation=>"unsupported_operation",Unknown=>"unknown"});
tokens!(kind_token,parse_kind,ErrorKind,{InvalidInput=>"invalid_input",Malformed=>"malformed",Incompatible=>"incompatible",Unsupported=>"unsupported",Denied=>"denied",Disappeared=>"disappeared",Changed=>"changed",LimitExceeded=>"limit_exceeded",Overflow=>"overflow",Backend=>"backend",Poisoned=>"poisoned"});
tokens!(bp_stage_token,parse_bp_stage,Stage,{Admission=>"admission",Metadata=>"metadata",Allocate=>"allocate",Read=>"read",Attach=>"attach",Drain=>"drain",Retire=>"retire",BtfQuery=>"btf_query",Compile=>"compile",Inspect=>"inspect",Execute=>"execute"});
fn valid_hex(s: &str) -> Result<(), OperationError> {
    if s.len() % 2 != 0
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    {
        Err(malformed())
    } else {
        Ok(())
    }
}
pub(super) fn nibble(b: u8) -> u8 {
    if b <= b'9' {
        b - b'0'
    } else {
        b - b'a' + 10
    }
}
fn digest(s: &str) -> Result<[u8; 32], OperationError> {
    valid_hex(s)?;
    if s.len() != 64 {
        return Err(malformed());
    }
    let mut out = [0; 32];
    for (slot, pair) in out.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        *slot = nibble(pair[0]) * 16 + nibble(pair[1]);
    }
    Ok(out)
}
fn required(s: &str) -> Result<usize, OperationError> {
    if s.is_empty() || s.len() > 1 && s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(malformed());
    }
    let mut n = 0u64;
    for b in s.bytes() {
        n = n
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(b - b'0')))
            .ok_or_else(overflow)?;
    }
    usize::try_from(n).map_err(|_| overflow())
}
fn decimal_digits(mut n: u64) -> usize {
    let mut count = 1;
    while n >= 10 {
        n /= 10;
        count += 1;
    }
    count
}
fn string_len(n: usize) -> Result<usize, OperationError> {
    add(2, n, Stage::Inspect)
}
fn hex_len(n: usize) -> Result<usize, OperationError> {
    string_len(multiply(n, 2, Stage::Inspect)?)
}
fn optional_string_len(s: Option<&str>) -> Result<usize, OperationError> {
    match s {
        Some(s) => string_len(s.len()),
        None => Ok(4),
    }
}
fn object_len(fields: &[(&str, usize)]) -> Result<usize, OperationError> {
    let mut n = add(2, fields.len() - 1, Stage::Inspect)?;
    for (key, value) in fields {
        n = add(
            n,
            add(add(3, key.len(), Stage::Inspect)?, *value, Stage::Inspect)?,
            Stage::Inspect,
        )?;
    }
    Ok(n)
}
/// Metadata only: no payload byte loop, serializer, validation or writer.
fn encoded_len(v: &CapabilityObservation) -> Result<usize, OperationError> {
    let c = &v.context;
    let context = object_len(&[
        ("kernel_build", 66),
        ("btf", if c.btf.is_some() { 66 } else { 4 }),
        ("architecture", string_len(c.architecture.len())?),
        ("namespace_context", 66),
        ("security_context", 66),
        ("topology", 66),
    ])?;
    let err = match v.error {
        None => 4,
        Some(e) => object_len(&[
            ("kind", string_len(kind_token(e.kind)?.len())?),
            ("stage", string_len(bp_stage_token(e.stage)?.len())?),
            (
                "raw_errno",
                match e.raw_errno {
                    None => 4,
                    Some(n) => decimal_digits(u64::from(n.unsigned_abs())) + usize::from(n < 0),
                },
            ),
            (
                "required_size",
                match e.required_size {
                    None => 4,
                    Some(n) => {
                        string_len(decimal_digits(u64::try_from(n).map_err(|_| overflow())?))?
                    }
                },
            ),
        ])?,
    };
    let mut ids = 2;
    if !v.evidence_ids.is_empty() {
        ids = add(ids, v.evidence_ids.len() - 1, Stage::Inspect)?;
    }
    for s in &v.evidence_ids {
        ids = add(ids, string_len(s.len())?, Stage::Inspect)?;
    }
    let cause = object_len(&[
        ("kind", string_len(cause_token(v.cause)?.len())?),
        ("method", string_len(v.cause_method.len())?),
        ("evidence_ids", ids),
    ])?;
    object_len(&[
        ("schema_version", 1),
        (
            "kind",
            string_len("scopebase-bpf-capability-observation".len())?,
        ),
        ("schema_revision", 1),
        (
            "claimed_origin",
            string_len(origin_token(v.claimed_origin)?.len())?,
        ),
        ("object", 66),
        ("profile", string_len(v.profile.as_str().len())?),
        ("context", context),
        ("state", string_len(state_token(v.state)?.len())?),
        ("stage", string_len(stage_token(v.stage)?.len())?),
        (
            "hazard",
            match v.hazard {
                None => 4,
                Some(h) => string_len(hazard_token(h)?.len())?,
            },
        ),
        ("operation", string_len(v.operation.len())?),
        ("step_id", optional_string_len(v.step_id.as_deref())?),
        ("outcome", string_len(outcome_token(v.outcome)?.len())?),
        ("error", err),
        ("reason", hex_len(v.reason.len())?),
        ("diagnostic", hex_len(v.diagnostic.len())?),
        ("cause", cause),
    ])
}
#[cfg(test)]
thread_local! {static PAYLOAD_ENTRIES:Cell<usize>=const{Cell::new(0)};static DECODE_ENTRIES:Cell<usize>=const{Cell::new(0)};}
fn ascii_record(bytes: &[u8]) -> bool {
    #[cfg(test)]
    DECODE_ENTRIES.with(|n| n.set(n.get() + 1));
    bytes.iter().all(|b| b.is_ascii() && *b != b'\\')
}
struct Writer {
    output: Vec<u8>,
    expected: usize,
}
impl Writer {
    fn raw(&mut self, b: &[u8]) -> Result<(), OperationError> {
        #[cfg(test)]
        PAYLOAD_ENTRIES.with(|v| v.set(v.get() + 1));
        let end = self
            .output
            .len()
            .checked_add(b.len())
            .ok_or_else(|| error(ErrorKind::Backend, Stage::Inspect, None))?;
        if end > self.expected || end > self.output.capacity() {
            return Err(error(ErrorKind::Backend, Stage::Inspect, None));
        }
        self.output.extend_from_slice(b);
        Ok(())
    }
    fn string(&mut self, s: &str) -> Result<(), OperationError> {
        self.raw(b"\"")?;
        self.raw(s.as_bytes())?;
        self.raw(b"\"")
    }
    fn key(&mut self, s: &str) -> Result<(), OperationError> {
        self.string(s)?;
        self.raw(b":")
    }
    fn number(&mut self, mut n: u64) -> Result<(), OperationError> {
        let mut buffer = [0; 20];
        let mut start = 20;
        loop {
            start -= 1;
            buffer[start] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        self.raw(&buffer[start..])
    }
    fn hex(&mut self, b: &[u8]) -> Result<(), OperationError> {
        self.raw(b"\"")?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for v in b {
            self.raw(&[HEX[(v / 16) as usize], HEX[(v % 16) as usize]])?;
        }
        self.raw(b"\"")
    }
    fn nullable(&mut self, s: Option<&str>) -> Result<(), OperationError> {
        match s {
            Some(s) => self.string(s),
            None => self.raw(b"null"),
        }
    }
}
fn write(v: &CapabilityObservation, w: &mut Writer) -> Result<(), OperationError> {
    macro_rules! key {
        ($s:literal) => {
            w.raw(b",")?;
            w.key($s)?
        };
    }
    w.raw(b"{")?;
    w.key("schema_version")?;
    w.number(1)?;
    key!("kind");
    w.string("scopebase-bpf-capability-observation")?;
    key!("schema_revision");
    w.number(1)?;
    key!("claimed_origin");
    w.string(origin_token(v.claimed_origin)?)?;
    key!("object");
    w.hex(&v.object.0)?;
    key!("profile");
    w.string(v.profile.as_str())?;
    key!("context");
    w.raw(b"{")?;
    w.key("kernel_build")?;
    w.hex(&v.context.kernel_build)?;
    key!("btf");
    match v.context.btf {
        Some(a) => w.hex(&a.0)?,
        None => w.raw(b"null")?,
    };
    key!("architecture");
    w.string(&v.context.architecture)?;
    key!("namespace_context");
    w.hex(&v.context.namespace_context)?;
    key!("security_context");
    w.hex(&v.context.security_context)?;
    key!("topology");
    w.hex(&v.context.topology)?;
    w.raw(b"}")?;
    key!("state");
    w.string(state_token(v.state)?)?;
    key!("stage");
    w.string(stage_token(v.stage)?)?;
    key!("hazard");
    w.nullable(v.hazard.map(hazard_token).transpose()?)?;
    key!("operation");
    w.string(&v.operation)?;
    key!("step_id");
    w.nullable(v.step_id.as_deref())?;
    key!("outcome");
    w.string(outcome_token(v.outcome)?)?;
    key!("error");
    match v.error {
        None => w.raw(b"null")?,
        Some(e) => {
            w.raw(b"{")?;
            w.key("kind")?;
            w.string(kind_token(e.kind)?)?;
            key!("stage");
            w.string(bp_stage_token(e.stage)?)?;
            key!("raw_errno");
            match e.raw_errno {
                None => w.raw(b"null")?,
                Some(n) => {
                    if n < 0 {
                        w.raw(b"-")?;
                    }
                    w.number(u64::from(n.unsigned_abs()))?
                }
            };
            key!("required_size");
            match e.required_size {
                None => w.raw(b"null")?,
                Some(n) => {
                    w.raw(b"\"")?;
                    w.number(u64::try_from(n).map_err(|_| overflow())?)?;
                    w.raw(b"\"")?
                }
            };
            w.raw(b"}")?
        }
    }
    key!("reason");
    w.hex(&v.reason)?;
    key!("diagnostic");
    w.hex(&v.diagnostic)?;
    key!("cause");
    w.raw(b"{")?;
    w.key("kind")?;
    w.string(cause_token(v.cause)?)?;
    key!("method");
    w.string(&v.cause_method)?;
    key!("evidence_ids");
    w.raw(b"[")?;
    for (n, s) in v.evidence_ids.iter().enumerate() {
        if n > 0 {
            w.raw(b",")?;
        }
        w.string(s)?;
    }
    w.raw(b"]}}")
}
impl CapabilityObservation {
    pub fn to_json(&self, l: &Limits) -> Result<Vec<u8>, OperationError> {
        let e = encoded_len(self)?;
        if e > l.input_bytes.min(65536) {
            return Err(error(ErrorKind::LimitExceeded, Stage::Inspect, Some(e)));
        }
        let work = u64::try_from(e)
            .map_err(|_| overflow())?
            .checked_mul(32)
            .and_then(|n| n.checked_add(1024))
            .ok_or_else(overflow)?;
        if work > l.work_steps {
            return Err(error(ErrorKind::LimitExceeded, Stage::Inspect, None));
        }
        let minimum = add(
            add(self.retained, size_of::<Vec<u8>>(), Stage::Inspect)?,
            e,
            Stage::Inspect,
        )?;
        let cap = l.retained_bytes.min(131072);
        if minimum > cap {
            return Err(error(
                ErrorKind::LimitExceeded,
                Stage::Inspect,
                Some(minimum),
            ));
        }
        let mut output = Vec::new();
        reserve_vec(&mut output, e)?;
        let actual = add(
            add(self.retained, size_of::<Vec<u8>>(), Stage::Allocate)?,
            output.capacity(),
            Stage::Allocate,
        )?;
        if actual > cap {
            return Err(error(
                ErrorKind::LimitExceeded,
                Stage::Allocate,
                Some(actual),
            ));
        }
        let mut w = Writer {
            output,
            expected: e,
        };
        write(self, &mut w)?;
        if w.output.len() != e {
            return Err(error(ErrorKind::Backend, Stage::Inspect, None));
        }
        Ok(w.output)
    }
    pub fn from_json(bytes: &[u8], l: &Limits) -> Result<Self, OperationError> {
        if bytes.len() > l.input_bytes.min(65536) {
            return Err(error(
                ErrorKind::LimitExceeded,
                Stage::Inspect,
                Some(bytes.len()),
            ));
        }
        let work = u64::try_from(bytes.len())
            .map_err(|_| overflow())?
            .checked_mul(32)
            .and_then(|n| n.checked_add(1024))
            .ok_or_else(overflow)?;
        if work > l.work_steps {
            return Err(error(ErrorKind::LimitExceeded, Stage::Inspect, None));
        }
        if !ascii_record(bytes) {
            return Err(malformed());
        }
        let fault = Fault::default();
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        let raw = Seed::<Raw<'_>>::new(&fault)
            .deserialize(&mut decoder)
            .map_err(|_| {
                if fault.count.get() {
                    error(ErrorKind::LimitExceeded, Stage::Inspect, None)
                } else {
                    malformed()
                }
            })?;
        decoder.end().map_err(|_| malformed())?;
        if raw.schema_version != 1
            || raw.kind != "scopebase-bpf-capability-observation"
            || raw.schema_revision != 1
        {
            return Err(unsupported());
        }
        let claimed = parse_origin(raw.claimed_origin)?;
        let object = ArtifactId(digest(raw.object)?);
        if raw.profile.len() > 128 {
            return Err(error(
                ErrorKind::LimitExceeded,
                Stage::Inspect,
                Some(raw.profile.len()),
            ));
        }
        if !profile_valid(raw.profile) {
            return Err(malformed());
        }
        let c = raw.context;
        let context = ContextParts {
            kernel_build: digest(c.kernel_build)?,
            btf: c.btf.map(digest).transpose()?.map(ArtifactId),
            architecture: c.architecture,
            namespace_context: digest(c.namespace_context)?,
            security_context: digest(c.security_context)?,
            topology: digest(c.topology)?,
        };
        let state = parse_state(raw.state)?;
        let stage = parse_stage(raw.stage)?;
        let hazard = raw.hazard.map(parse_hazard).transpose()?;
        let outcome = parse_outcome(raw.outcome)?;
        let snapshot = raw
            .error
            .map(|e| -> Result<_, OperationError> {
                Ok(OperationErrorSnapshot {
                    kind: parse_kind(e.kind)?,
                    stage: parse_bp_stage(e.stage)?,
                    raw_errno: e
                        .raw_errno
                        .map(|n| match n {
                            Integer::Signed(v) => i32::try_from(v),
                            Integer::Unsigned(v) => i32::try_from(v),
                        })
                        .transpose()
                        .map_err(|_| overflow())?,
                    required_size: e.required_size.map(required).transpose()?,
                })
            })
            .transpose()?;
        valid_hex(raw.reason)?;
        valid_hex(raw.diagnostic)?;
        let cause = parse_cause(raw.cause.kind)?;
        let ids = &raw.cause.evidence_ids.values[..raw.cause.evidence_ids.len];
        let i = Parts {
            object: &object,
            profile: raw.profile,
            context,
            state,
            stage,
            hazard,
            operation: raw.operation,
            step_id: raw.step_id,
            outcome,
            error: snapshot,
            reason: Blob::Hex(raw.reason),
            diagnostic: Blob::Hex(raw.diagnostic),
            cause: CauseDescriptionInput {
                cause,
                method: raw.cause.method,
                evidence_ids: ids,
            },
        };
        let mut value = Self::construct(
            i,
            &Limits {
                input_bytes: 65536,
                work_steps: u64::MAX,
                ..*l
            },
        )
        .map_err(|e| {
            if e.stage() == Stage::Admission {
                error(
                    if e.kind() == ErrorKind::InvalidInput {
                        ErrorKind::Malformed
                    } else {
                        e.kind()
                    },
                    Stage::Inspect,
                    e.required_size(),
                )
            } else {
                e
            }
        })?;
        value.origin = ObservationOrigin::Imported;
        value.claimed_origin = claimed;
        Ok(value)
    }
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
    const BASE: &[u8] = include_bytes!("../../fixtures/capability-v1/codec/valid-base.bytes");
    #[test]
    fn payload_prepaid_and_measured_retention() {
        let v = CapabilityObservation::from_json(BASE, &limits()).unwrap();
        let d = measured_retained(&v);
        assert_eq!(v.retained_bytes(), d);
        let m = d + size_of::<Vec<u8>>() + 1026;
        for (input, work, retained, required) in [
            (1025, 0, 0, Some(1026)),
            (1026, 0, 0, None),
            (1026, 33856, m - 1, Some(m)),
        ] {
            PAYLOAD_ENTRIES.with(|n| n.set(0));
            let e = v
                .to_json(&Limits {
                    input_bytes: input,
                    work_steps: work,
                    retained_bytes: retained,
                    ..limits()
                })
                .unwrap_err();
            assert_eq!(
                (e.kind(), e.stage(), e.raw_os_error(), e.required_size()),
                (ErrorKind::LimitExceeded, Stage::Inspect, None, required)
            );
            assert_eq!(
                PAYLOAD_ENTRIES.with(Cell::get),
                0,
                "codec.no-payload-before-work"
            );
        }
        PAYLOAD_ENTRIES.with(|n| n.set(0));
        let out = v
            .to_json(&Limits {
                input_bytes: 1026,
                work_steps: 33856,
                retained_bytes: m,
                ..limits()
            })
            .unwrap();
        assert_eq!(out, BASE);
        assert!(PAYLOAD_ENTRIES.with(Cell::get) > 0);
        for (bytes, work, retained, required) in [(1025, 0, 0, Some(1026)), (1026, 33855, 0, None)]
        {
            DECODE_ENTRIES.with(|n| n.set(0));
            let e = CapabilityObservation::from_json(
                BASE,
                &Limits {
                    input_bytes: bytes,
                    work_steps: work,
                    retained_bytes: retained,
                    ..limits()
                },
            )
            .unwrap_err();
            assert_eq!(
                (e.kind(), e.stage(), e.raw_os_error(), e.required_size()),
                (ErrorKind::LimitExceeded, Stage::Inspect, None, required)
            );
            assert_eq!(
                DECODE_ENTRIES.with(Cell::get),
                0,
                "codec.no-decode-before-work"
            );
        }
        let decoded = CapabilityObservation::from_json(
            BASE,
            &Limits {
                input_bytes: 1026,
                work_steps: 33856,
                retained_bytes: d,
                ..limits()
            },
        )
        .unwrap();
        assert_eq!(decoded.retained_bytes(), measured_retained(&decoded));
        assert!(DECODE_ENTRIES.with(Cell::get) > 0);
    }
    #[test]
    fn allocation_errors_keep_allocate_stage() {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                ALLOCATION_FAILURE.with(|v| v.set(None));
            }
        }
        let v = CapabilityObservation::from_json(BASE, &limits()).unwrap();
        {
            let _reset = Reset;
            ALLOCATION_FAILURE.with(|n| n.set(Some(0)));
            let e = v.to_json(&limits()).unwrap_err();
            assert_eq!(
                (e.kind(), e.stage(), e.required_size()),
                (ErrorKind::Backend, Stage::Allocate, None)
            );
        }
        {
            let _reset = Reset;
            ALLOCATION_FAILURE.with(|n| n.set(Some(0)));
            let e = CapabilityObservation::from_json(BASE, &limits()).unwrap_err();
            assert_eq!(
                (e.kind(), e.stage(), e.required_size()),
                (ErrorKind::Backend, Stage::Allocate, None),
                "codec.error-stage"
            );
        }
    }
}
