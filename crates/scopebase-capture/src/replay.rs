// SPDX-License-Identifier: Apache-2.0
//! Strict replay vectors (v1 document format).
//!
//! ADAPT: KryProbe d153f3a
//! `scripts/kcrypto_perf/successorvalidity.py:44-56`
//! (`_no_duplicate_members`: contradictory receipts refuse, never
//! last-wins) and `:58-64` (`_reject_constant`: NaN/Infinity refuse).
//! The duplicate scan runs on decoded member names, so an escaped twin
//! (`"valu\u0065"` beside `"value"`) refuses like a literal repeat.
//! ADAPT: KryProbe d153f3a `successorvalidity.py:353-363,434-444`
//! (exactly one terminal object: a second contradicts the first and a
//! missing terminal refuses; earlier evidence is never overwritten).
//! VECTORS: KryProbe d153f3a `tests/kcrypto_perf/test_successor.py`
//! `:316,:335,:386,:393,:570`; MemVeil 8307a17
//! `tests/unit/test_reader.mojo:296-308` (nesting-depth guard).
//! CONCEPT: MojoBPF coordination `2b26baee`
//! `doc/validation/2026-10-15-f02-fullmatch-boundary.md` (F02 exact-pin
//! fullmatch: trailing-newline pins refuse with a typed error, exact
//! pins including zero parse). Binding/capture/producer/clock pins are
//! exact lowercase-hex fullmatches here; no donor lines are copied.
//!
//! Decoding is three bounded phases: a structural pre-scan (byte,
//! nesting, string, breadth and duplicate rules with byte offsets), a
//! `serde_json` parse (malformed input refuses, never coerces), and a
//! semantic walk that builds [`NeutralObservationV1`] and calls
//! [`validate_v1`](crate::neutral::validate_v1), the sole neutral
//! semantic validator. Limits precede collection growth at every phase:
//! the 4,097th record refuses before any record buffer grows. V1 has no
//! bare numbers: every integer-typed field is a canonical decimal string
//! parsed by [`parse_count_u64`](crate::neutral::parse_count_u64), so no
//! float or bare-int coercion exists (a deliberate tightening of the K
//! donor, which also accepts bare integers). [`ReplayError`] carries a
//! typed kind and a byte offset only; no raw payload is echoed.
use crate::{
    domain::{BindingId, Origin},
    neutral::{
        parse_count_u64, parse_loss_kind, parse_origin_name, parse_reason_name, parse_unit_name,
        validate_v1, NeutralClaim, NeutralCorrection, NeutralCounter, NeutralLimits, NeutralLoss,
        NeutralMagnitude, NeutralObservationV1, NeutralPartition, NeutralPolicy, NeutralSignal,
        NeutralSource, NeutralUnit, ValidatedNeutralV1,
    },
    ContractError,
};
use std::fmt;

/// Installed byte limit.
pub const REPLAY_MAX_BYTES: usize = 1_048_576;
/// Installed record limit, also the hard maximum.
pub const REPLAY_MAX_RECORDS: usize = 4096;
/// Installed nesting limit.
pub const REPLAY_MAX_NESTING: usize = 16;
/// Installed per-container and per-collection item limit.
pub const REPLAY_MAX_ITEMS: usize = 4096;
/// Installed string-content limit in raw bytes.
pub const REPLAY_MAX_STRING: usize = 256;

/// Exact v1 schema tag.
pub const REPLAY_SCHEMA_V1: &str = "scopebase-capture/replay-v1";

/// Bounded decode limits. Every value, including zero, is valid input;
/// tighter caller limits refuse more. The default is the installed
/// profile: bytes 1,048,576, records 4,096, nesting 16, items 4,096,
/// strings 256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayLimits {
    /// Maximum input bytes, checked before parsing.
    pub max_bytes: usize,
    /// Maximum data records, checked before buffer growth. The mandatory
    /// terminal occupies one extra structural slot.
    pub max_records: usize,
    /// Maximum object/array nesting depth.
    pub max_nesting: usize,
    /// Maximum members per object, elements per array, and entries per
    /// semantic collection (parts, reasons).
    pub max_items: usize,
    /// Maximum string-content bytes (raw, escapes counted as written).
    pub max_string: usize,
}

impl Default for ReplayLimits {
    /// The installed replay limits.
    fn default() -> Self {
        Self {
            max_bytes: REPLAY_MAX_BYTES,
            max_records: REPLAY_MAX_RECORDS,
            max_nesting: REPLAY_MAX_NESTING,
            max_items: REPLAY_MAX_ITEMS,
            max_string: REPLAY_MAX_STRING,
        }
    }
}

/// One raw decoded value. V1 has no numbers: bare JSON numbers refuse
/// with [`ReplayErrorKind::TypeMismatch`] during conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayValue {
    /// JSON null.
    Null,
    /// JSON boolean.
    Bool(bool),
    /// Decoded JSON string.
    Text(String),
    /// JSON array in order.
    Array(Vec<ReplayValue>),
    /// JSON object in order with unique decoded member names.
    Object(Vec<(String, ReplayValue)>),
}

/// One raw data record. Construction is unchecked; [`ReplayDocument::new`]
/// and [`decode`] validate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRecord {
    kind: String,
    epoch: u64,
    fields: Vec<(String, ReplayValue)>,
}

impl ReplayRecord {
    /// Retain a raw record without validating it. Members are stored
    /// sorted by name (canonical order), matching decoded records.
    pub fn new(kind: &str, epoch: u64, mut fields: Vec<(String, ReplayValue)>) -> Self {
        fields.sort_by(|left, right| left.0.cmp(&right.0));
        Self {
            kind: kind.to_string(),
            epoch,
            fields,
        }
    }
    /// The raw kind name.
    pub fn kind(&self) -> &str {
        &self.kind
    }
    /// The raw asserted epoch ordinal.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Look up a raw member by exact name.
    pub fn get(&self, name: &str) -> Option<&ReplayValue> {
        self.fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, v)| v)
    }
    /// The raw members in document order.
    pub fn fields(&self) -> &[(String, ReplayValue)] {
        &self.fields
    }
}

/// One raw terminal inventory. Construction is unchecked; admission
/// checks it against the unique prior records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayTerminal {
    epoch: u64,
    counters: u64,
    loss: u64,
    signals: u64,
    claims: u64,
    partitions: u64,
    corrections: u64,
}

impl ReplayTerminal {
    /// Retain a raw terminal inventory without validating it.
    pub fn new(
        epoch: u64,
        counters: u64,
        loss: u64,
        signals: u64,
        claims: u64,
        partitions: u64,
        corrections: u64,
    ) -> Self {
        Self {
            epoch,
            counters,
            loss,
            signals,
            claims,
            partitions,
            corrections,
        }
    }
    /// The raw asserted epoch ordinal.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// The inventoried counter records.
    pub fn counters(&self) -> u64 {
        self.counters
    }
    /// The inventoried loss records.
    pub fn loss(&self) -> u64 {
        self.loss
    }
    /// The inventoried signal records.
    pub fn signals(&self) -> u64 {
        self.signals
    }
    /// The inventoried claim records.
    pub fn claims(&self) -> u64 {
        self.claims
    }
    /// The inventoried partition records.
    pub fn partitions(&self) -> u64 {
        self.partitions
    }
    /// The inventoried correction records.
    pub fn corrections(&self) -> u64 {
        self.corrections
    }
}

/// Typed refusal reason. Every variant is structural except [`Contract`],
/// which carries the neutral constructor refusal unchanged.
///
/// [`Contract`]: ReplayErrorKind::Contract
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayErrorKind {
    /// Input exceeds `max_bytes`.
    TooLarge,
    /// Nesting exceeds `max_nesting`.
    TooDeep,
    /// A string exceeds `max_string` raw bytes.
    StringTooLong,
    /// An object, array or semantic collection exceeds `max_items`.
    TooManyItems,
    /// A decoded member name repeats within one object.
    DuplicateMember,
    /// Bytes are not JSON.
    Malformed,
    /// A value has the wrong JSON type, range or shape (including hex
    /// pins, vocabularies and out-of-range integers).
    TypeMismatch,
    /// A text field breaks the canonical u64 grammar.
    NonCanonicalNumber,
    /// A record kind is outside the v1 vocabulary.
    UnknownKind,
    /// An object member is outside the v1 vocabulary.
    UnknownMember,
    /// A required member is absent. Nothing is defaulted.
    MissingMember,
    /// The records array exceeds `max_records`.
    LimitExceeded,
    /// A record epoch differs from the document epoch.
    EpochMismatch,
    /// No terminal record exists.
    TerminalMissing,
    /// More than one terminal record exists.
    TerminalDuplicate,
    /// The terminal record is not the last element.
    TerminalNotFinal,
    /// The terminal inventory disagrees with the unique prior records.
    InventoryMismatch,
    /// Neutral semantic validation refused.
    Contract(ContractError),
}

/// A typed refusal with a byte offset and no raw payload:
///
/// ```compile_fail
/// use scopebase_capture::replay::{ReplayError, ReplayErrorKind};
/// fn forge(e: ReplayError) -> ReplayError {
///     ReplayError { kind: e.kind(), offset: e.offset() }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayError {
    kind: ReplayErrorKind,
    offset: usize,
}

impl ReplayError {
    /// The typed refusal reason.
    pub fn kind(&self) -> ReplayErrorKind {
        self.kind.clone()
    }
    /// Byte offset of the offending syntax or record when decoded from
    /// bytes; cross-record and constructor-built refusals carry 0.
    pub fn offset(&self) -> usize {
        self.offset
    }
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} at byte {}", self.kind, self.offset)
    }
}

impl std::error::Error for ReplayError {}

fn refuse(kind: ReplayErrorKind, offset: usize) -> ReplayError {
    ReplayError { kind, offset }
}

/// Structural pre-scan over raw bytes. Enforces nesting, string, breadth
/// and duplicate-member rules before `serde_json` builds any DOM, and
/// counts the root `records` array (refusing past `max_records`) while
/// recording each element start offset. Invalid JSON encountered here
/// refuses as [`ReplayErrorKind::Malformed`]; anything subtler is left
/// for the real parser. Recursion depth never exceeds `max_nesting + 1`.
struct Scanner<'a> {
    bytes: &'a [u8],
    pos: usize,
    limits: ReplayLimits,
    record_offsets: Vec<usize>,
}

impl<'a> Scanner<'a> {
    fn new(bytes: &'a [u8], limits: ReplayLimits) -> Self {
        Self {
            bytes,
            pos: 0,
            limits,
            record_offsets: Vec::new(),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn scan(&mut self) -> Result<Vec<usize>, ReplayError> {
        self.skip_ws();
        self.value(0, false)?;
        self.skip_ws();
        if self.peek().is_some() {
            return Err(refuse(ReplayErrorKind::Malformed, self.pos));
        }
        Ok(std::mem::take(&mut self.record_offsets))
    }

    /// Scan one value. `records_array` marks the root `records` array so
    /// its elements are counted and their offsets recorded.
    fn value(&mut self, depth: usize, records_array: bool) -> Result<(), ReplayError> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1, records_array),
            Some(b'"') => {
                let _ = self.string(false)?;
                Ok(())
            }
            Some(byte) if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.') => {
                self.literal()
            }
            _ => Err(refuse(ReplayErrorKind::Malformed, self.pos)),
        }
    }

    fn object(&mut self, depth: usize) -> Result<(), ReplayError> {
        if depth > self.limits.max_nesting {
            return Err(refuse(ReplayErrorKind::TooDeep, self.pos));
        }
        self.pos += 1;
        let mut members: Vec<Vec<u8>> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(refuse(ReplayErrorKind::Malformed, self.pos));
            }
            let start = self.pos;
            let name = self.string(true)?.unwrap_or_default();
            if members.contains(&name) {
                return Err(refuse(ReplayErrorKind::DuplicateMember, start));
            }
            if members.len() == self.limits.max_items {
                return Err(refuse(ReplayErrorKind::TooManyItems, start));
            }
            members.push(name);
            let is_records = depth == 1 && members.last().is_some_and(|n| n == b"records");
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(refuse(ReplayErrorKind::Malformed, self.pos));
            }
            self.pos += 1;
            self.value(depth, is_records)?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => return Err(refuse(ReplayErrorKind::Malformed, self.pos)),
            }
        }
    }

    fn array(&mut self, depth: usize, records_array: bool) -> Result<(), ReplayError> {
        if depth > self.limits.max_nesting {
            return Err(refuse(ReplayErrorKind::TooDeep, self.pos));
        }
        self.pos += 1;
        let mut count = 0usize;
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            self.skip_ws();
            if records_array {
                // Data records are capped at max_records; one extra slot
                // holds the mandatory terminal. Saturating keeps
                // usize::MAX limits total without overflow.
                if count == self.limits.max_records.saturating_add(1) {
                    return Err(refuse(ReplayErrorKind::LimitExceeded, self.pos));
                }
                self.record_offsets.push(self.pos);
            } else if count == self.limits.max_items {
                return Err(refuse(ReplayErrorKind::TooManyItems, self.pos));
            }
            count += 1;
            self.value(depth, false)?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => return Err(refuse(ReplayErrorKind::Malformed, self.pos)),
            }
        }
    }

    /// Skip a literal or numeric run; strict validity belongs to the parser.
    fn literal(&mut self) -> Result<(), ReplayError> {
        let start = self.pos;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.' | b'_') {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(refuse(ReplayErrorKind::Malformed, self.pos));
        }
        Ok(())
    }

    /// Scan one string starting at the opening quote. Returns the decoded
    /// bytes when `decode` is set. Raw control bytes, bad escapes, lone
    /// surrogates and unterminated strings are malformed JSON.
    fn string(&mut self, decode: bool) -> Result<Option<Vec<u8>>, ReplayError> {
        let start = self.pos;
        self.pos += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let byte = self
                .peek()
                .ok_or(refuse(ReplayErrorKind::Malformed, self.pos))?;
            if byte == b'"' {
                self.pos += 1;
                if self.pos - start - 2 > self.limits.max_string {
                    return Err(refuse(ReplayErrorKind::StringTooLong, start));
                }
                return Ok(decode.then_some(out));
            }
            if byte < 0x20 {
                return Err(refuse(ReplayErrorKind::Malformed, self.pos));
            }
            if byte != b'\\' {
                if decode {
                    out.push(byte);
                }
                self.pos += 1;
                continue;
            }
            self.pos += 1;
            let end = self.pos;
            let escaped = self.peek().ok_or(refuse(ReplayErrorKind::Malformed, end))?;
            match escaped {
                b'"' | b'\\' | b'/' => {
                    if decode {
                        out.push(escaped);
                    }
                    self.pos += 1;
                }
                b'b' => {
                    if decode {
                        out.push(0x08);
                    }
                    self.pos += 1;
                }
                b'f' => {
                    if decode {
                        out.push(0x0C);
                    }
                    self.pos += 1;
                }
                b'n' => {
                    if decode {
                        out.push(b'\n');
                    }
                    self.pos += 1;
                }
                b'r' => {
                    if decode {
                        out.push(b'\r');
                    }
                    self.pos += 1;
                }
                b't' => {
                    if decode {
                        out.push(b'\t');
                    }
                    self.pos += 1;
                }
                b'u' => {
                    self.pos += 1;
                    let first = self.hex4()?;
                    let scalar = if (0xD800..0xDC00).contains(&first) {
                        if self.bytes.get(self.pos) == Some(&b'\\')
                            && self.bytes.get(self.pos + 1) == Some(&b'u')
                        {
                            self.pos += 2;
                            let second = self.hex4()?;
                            if !(0xDC00..0xE000).contains(&second) {
                                return Err(refuse(ReplayErrorKind::Malformed, self.pos));
                            }
                            0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                        } else {
                            return Err(refuse(ReplayErrorKind::Malformed, self.pos));
                        }
                    } else if (0xDC00..0xE000).contains(&first) {
                        return Err(refuse(ReplayErrorKind::Malformed, self.pos));
                    } else {
                        first
                    };
                    if decode {
                        let scalar = char::from_u32(scalar)
                            .ok_or(refuse(ReplayErrorKind::Malformed, self.pos))?;
                        let mut encoded = [0u8; 4];
                        out.extend_from_slice(scalar.encode_utf8(&mut encoded).as_bytes());
                    }
                }
                _ => return Err(refuse(ReplayErrorKind::Malformed, self.pos)),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, ReplayError> {
        if self.pos + 4 > self.bytes.len() {
            return Err(refuse(ReplayErrorKind::Malformed, self.pos));
        }
        let mut value: u32 = 0;
        for offset in 0..4 {
            let digit = self.bytes[self.pos + offset];
            let digit = match digit {
                b'0'..=b'9' => u32::from(digit - b'0'),
                b'a'..=b'f' => u32::from(digit - b'a') + 10,
                b'A'..=b'F' => u32::from(digit - b'A') + 10,
                _ => return Err(refuse(ReplayErrorKind::Malformed, self.pos)),
            };
            value = value * 16 + digit;
        }
        self.pos += 4;
        Ok(value)
    }
}

/// Convert a parsed JSON value to its raw form. Bare numbers refuse:
/// v1 integers are canonical decimal strings only.
fn convert(value: &serde_json::Value, offset: usize) -> Result<ReplayValue, ReplayError> {
    match value {
        serde_json::Value::Null => Ok(ReplayValue::Null),
        serde_json::Value::Bool(flag) => Ok(ReplayValue::Bool(*flag)),
        serde_json::Value::Number(_) => Err(refuse(ReplayErrorKind::TypeMismatch, offset)),
        serde_json::Value::String(text) => Ok(ReplayValue::Text(text.clone())),
        serde_json::Value::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                out.push(convert(item, offset)?);
            }
            Ok(ReplayValue::Array(out))
        }
        serde_json::Value::Object(map) => {
            let mut out = Vec::new();
            for (key, item) in map {
                out.push((key.clone(), convert(item, offset)?));
            }
            Ok(ReplayValue::Object(out))
        }
    }
}

fn text_of(value: &ReplayValue, offset: usize) -> Result<&str, ReplayError> {
    match value {
        ReplayValue::Text(text) => Ok(text),
        _ => Err(refuse(ReplayErrorKind::TypeMismatch, offset)),
    }
}

fn count_of(value: &ReplayValue, offset: usize) -> Result<u64, ReplayError> {
    let text = text_of(value, offset)?;
    parse_count_u64(text).map_err(|_| refuse(ReplayErrorKind::NonCanonicalNumber, offset))
}

fn hex_bytes<const N: usize>(text: &str, offset: usize) -> Result<[u8; N], ReplayError> {
    if text.len() != N * 2 {
        return Err(refuse(ReplayErrorKind::TypeMismatch, offset));
    }
    let mut out = [0u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        let pair = text.get(index * 2..index * 2 + 2);
        let Some(pair) = pair else {
            return Err(refuse(ReplayErrorKind::TypeMismatch, offset));
        };
        let Ok(parsed) = u8::from_str_radix(pair, 16) else {
            return Err(refuse(ReplayErrorKind::TypeMismatch, offset));
        };
        if pair.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(refuse(ReplayErrorKind::TypeMismatch, offset));
        }
        *byte = parsed;
    }
    Ok(out)
}

fn member<'a>(
    fields: &'a [(String, ReplayValue)],
    name: &str,
    offset: usize,
) -> Result<&'a ReplayValue, ReplayError> {
    fields
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
        .ok_or(refuse(ReplayErrorKind::MissingMember, offset))
}

fn check_members(
    fields: &[(String, ReplayValue)],
    known: &[&str],
    offset: usize,
) -> Result<(), ReplayError> {
    for (key, _) in fields {
        if !known.contains(&key.as_str()) {
            return Err(refuse(ReplayErrorKind::UnknownMember, offset));
        }
    }
    Ok(())
}

fn unit_of(value: &ReplayValue, offset: usize) -> Result<NeutralUnit, ReplayError> {
    parse_unit_name(text_of(value, offset)?)
        .map_err(|_| refuse(ReplayErrorKind::TypeMismatch, offset))
}

fn policy_of(value: &ReplayValue, offset: usize) -> Result<NeutralPolicy, ReplayError> {
    match value {
        ReplayValue::Text(name) if name == "monotonic" => Ok(NeutralPolicy::Monotonic),
        ReplayValue::Text(_) => Err(refuse(ReplayErrorKind::TypeMismatch, offset)),
        ReplayValue::Object(fields) => {
            check_members(fields, &["saturating", "modulo"], offset)?;
            if let Some(max) = fields.iter().find(|(key, _)| key == "saturating") {
                if fields.len() != 1 {
                    return Err(refuse(ReplayErrorKind::UnknownMember, offset));
                }
                Ok(NeutralPolicy::Saturating {
                    maximum: count_of(&max.1, offset)?,
                })
            } else if let Some(width) = fields.iter().find(|(key, _)| key == "modulo") {
                if fields.len() != 1 {
                    return Err(refuse(ReplayErrorKind::UnknownMember, offset));
                }
                let width = count_of(&width.1, offset)?;
                let Ok(width) = u8::try_from(width) else {
                    return Err(refuse(ReplayErrorKind::TypeMismatch, offset));
                };
                Ok(NeutralPolicy::Modulo { width })
            } else {
                Err(refuse(ReplayErrorKind::MissingMember, offset))
            }
        }
        _ => Err(refuse(ReplayErrorKind::TypeMismatch, offset)),
    }
}

fn magnitude_of(value: &ReplayValue, offset: usize) -> Result<NeutralMagnitude, ReplayError> {
    match value {
        ReplayValue::Text(name) if name == "unknown" => Ok(NeutralMagnitude::Unknown),
        ReplayValue::Text(_) => Err(refuse(ReplayErrorKind::TypeMismatch, offset)),
        ReplayValue::Object(fields) => {
            check_members(fields, &["exact", "at-least"], offset)?;
            if fields.len() != 1 {
                return Err(refuse(ReplayErrorKind::MissingMember, offset));
            }
            if let Some(exact) = fields.iter().find(|(key, _)| key == "exact") {
                Ok(NeutralMagnitude::Exact(count_of(&exact.1, offset)?))
            } else if let Some(bound) = fields.iter().find(|(key, _)| key == "at-least") {
                Ok(NeutralMagnitude::AtLeast(count_of(&bound.1, offset)?))
            } else {
                Err(refuse(ReplayErrorKind::MissingMember, offset))
            }
        }
        _ => Err(refuse(ReplayErrorKind::TypeMismatch, offset)),
    }
}

fn u32_of(value: &ReplayValue, offset: usize) -> Result<u32, ReplayError> {
    let raw = count_of(value, offset)?;
    u32::try_from(raw).map_err(|_| refuse(ReplayErrorKind::TypeMismatch, offset))
}

fn u8_of(value: &ReplayValue, offset: usize) -> Result<u8, ReplayError> {
    let raw = count_of(value, offset)?;
    u8::try_from(raw).map_err(|_| refuse(ReplayErrorKind::TypeMismatch, offset))
}

/// Translate one raw record into its neutral row. Single-item failures
/// carry the record offset so per-record pre-validation attributes them.
#[allow(clippy::too_many_lines)]
fn translate(
    record: &ReplayRecord,
    limits: ReplayLimits,
    offset: usize,
    obs: &mut NeutralObservationV1,
) -> Result<(), ReplayError> {
    let fields = record.fields();
    match record.kind() {
        "counter" => {
            check_members(
                fields,
                &[
                    "kind", "epoch", "channel", "policy", "clock", "start", "end", "value", "unit",
                ],
                offset,
            )?;
            obs.counters.push(NeutralCounter {
                channel: u32_of(member(fields, "channel", offset)?, offset)?,
                policy: policy_of(member(fields, "policy", offset)?, offset)?,
                clock: hex_bytes(text_of(member(fields, "clock", offset)?, offset)?, offset)?,
                start: count_of(member(fields, "start", offset)?, offset)?,
                end: count_of(member(fields, "end", offset)?, offset)?,
                value: count_of(member(fields, "value", offset)?, offset)?,
                unit: unit_of(member(fields, "unit", offset)?, offset)?,
            });
        }
        "loss" => {
            check_members(
                fields,
                &["kind", "epoch", "channel", "loss-kind", "magnitude", "unit"],
                offset,
            )?;
            let kind = parse_loss_kind(text_of(member(fields, "loss-kind", offset)?, offset)?)
                .map_err(|_| refuse(ReplayErrorKind::TypeMismatch, offset))?;
            obs.losses.push(NeutralLoss {
                channel: u32_of(member(fields, "channel", offset)?, offset)?,
                kind,
                magnitude: magnitude_of(member(fields, "magnitude", offset)?, offset)?,
                unit: unit_of(member(fields, "unit", offset)?, offset)?,
            });
        }
        "signal" => {
            check_members(
                fields,
                &["kind", "epoch", "channel", "observed", "cap", "unit"],
                offset,
            )?;
            obs.signals.push(NeutralSignal {
                channel: u32_of(member(fields, "channel", offset)?, offset)?,
                observed: u8_of(member(fields, "observed", offset)?, offset)?,
                cap: u8_of(member(fields, "cap", offset)?, offset)?,
                unit: unit_of(member(fields, "unit", offset)?, offset)?,
            });
        }
        "claim" => {
            check_members(fields, &["kind", "epoch", "claim", "reasons"], offset)?;
            let claim = u32_of(member(fields, "claim", offset)?, offset)?;
            let reasons = member(fields, "reasons", offset)?;
            let ReplayValue::Array(items) = reasons else {
                return Err(refuse(ReplayErrorKind::TypeMismatch, offset));
            };
            if items.len() > limits.max_items {
                return Err(refuse(ReplayErrorKind::TooManyItems, offset));
            }
            let mut reasons_out = Vec::new();
            for item in items {
                let reason = parse_reason_name(text_of(item, offset)?)
                    .map_err(|_| refuse(ReplayErrorKind::TypeMismatch, offset))?;
                reasons_out.push(reason);
            }
            obs.claims.push(NeutralClaim {
                claim,
                reasons: reasons_out,
            });
        }
        "partition" => {
            check_members(fields, &["kind", "epoch", "total", "parts", "unit"], offset)?;
            let total = count_of(member(fields, "total", offset)?, offset)?;
            let parts = member(fields, "parts", offset)?;
            let ReplayValue::Array(items) = parts else {
                return Err(refuse(ReplayErrorKind::TypeMismatch, offset));
            };
            if items.len() > limits.max_items {
                return Err(refuse(ReplayErrorKind::TooManyItems, offset));
            }
            let mut parts_out = Vec::new();
            for item in items {
                parts_out.push(count_of(item, offset)?);
            }
            obs.partitions.push(NeutralPartition {
                total,
                parts: parts_out,
                unit: unit_of(member(fields, "unit", offset)?, offset)?,
            });
        }
        "correction" => {
            check_members(fields, &["kind", "epoch", "from", "to"], offset)?;
            obs.corrections.push(NeutralCorrection {
                from: count_of(member(fields, "from", offset)?, offset)?,
                to: count_of(member(fields, "to", offset)?, offset)?,
            });
        }
        _ => return Err(refuse(ReplayErrorKind::UnknownKind, offset)),
    }
    Ok(())
}

/// Shared admission: epochs, inventory and neutral validation. `offsets`
/// holds one record-start offset per record when decoded from bytes and
/// is empty for constructor-built documents (offset 0 then).
fn assemble(
    source: NeutralSource,
    unit: NeutralUnit,
    records: Vec<ReplayRecord>,
    terminal: ReplayTerminal,
    offsets: &[usize],
    limits: ReplayLimits,
) -> Result<ReplayDocument, ReplayError> {
    let at = |index: usize| offsets.get(index).copied().unwrap_or(0);
    for (index, record) in records.iter().enumerate() {
        if record.kind() == "terminal" {
            return Err(refuse(ReplayErrorKind::TerminalDuplicate, at(index)));
        }
        if record.epoch() != source.ordinal {
            return Err(refuse(ReplayErrorKind::EpochMismatch, at(index)));
        }
    }
    if terminal.epoch() != source.ordinal {
        return Err(refuse(
            ReplayErrorKind::EpochMismatch,
            offsets.last().copied().unwrap_or(0),
        ));
    }
    let mut counts = [0u64; 6];
    for record in &records {
        let slot = match record.kind() {
            "counter" => &mut counts[0],
            "loss" => &mut counts[1],
            "signal" => &mut counts[2],
            "claim" => &mut counts[3],
            "partition" => &mut counts[4],
            "correction" => &mut counts[5],
            _ => return Err(refuse(ReplayErrorKind::UnknownKind, at(0))),
        };
        *slot += 1;
    }
    if terminal.counters() != counts[0]
        || terminal.loss() != counts[1]
        || terminal.signals() != counts[2]
        || terminal.claims() != counts[3]
        || terminal.partitions() != counts[4]
        || terminal.corrections() != counts[5]
    {
        return Err(refuse(
            ReplayErrorKind::InventoryMismatch,
            offsets.last().copied().unwrap_or(0),
        ));
    }
    let mut obs = NeutralObservationV1 {
        source: source.clone(),
        unit,
        counters: Vec::new(),
        losses: Vec::new(),
        signals: Vec::new(),
        claims: Vec::new(),
        partitions: Vec::new(),
        corrections: Vec::new(),
    };
    for (index, record) in records.iter().enumerate() {
        translate(record, limits, at(index), &mut obs)?;
    }
    for (index, record) in records.iter().enumerate() {
        let mut single = NeutralObservationV1 {
            source: source.clone(),
            unit,
            counters: Vec::new(),
            losses: Vec::new(),
            signals: Vec::new(),
            claims: Vec::new(),
            partitions: Vec::new(),
            corrections: Vec::new(),
        };
        translate(record, limits, at(index), &mut single)?;
        validate_v1(&single, NeutralLimits::default())
            .map_err(|refused| refuse(ReplayErrorKind::Contract(refused), at(index)))?;
    }
    let validated = validate_v1(&obs, NeutralLimits::default())
        .map_err(|refused| refuse(ReplayErrorKind::Contract(refused), 0))?;
    let binding = validated.source().binding();
    let origin = validated.source().origin();
    Ok(ReplayDocument {
        records,
        terminal,
        validated,
        binding,
        origin,
        capture_hex: hex_of(&source.capture),
        producer_hex: hex_of(&source.producer),
        binding_hex: hex_of(&source.binding),
    })
}

fn hex_of(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}

/// An admitted replay document. Immutable SDK metadata only:
///
/// ```compile_fail
/// use scopebase_capture::replay::ReplayDocument;
/// fn forge(d: ReplayDocument) -> usize {
///     d.records.len()
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ReplayDocument {
    records: Vec<ReplayRecord>,
    terminal: ReplayTerminal,
    validated: ValidatedNeutralV1,
    binding: BindingId,
    origin: Origin,
    capture_hex: String,
    producer_hex: String,
    binding_hex: String,
}

impl ReplayDocument {
    /// Admit raw records plus their terminal under the installed limits,
    /// running the same epoch, inventory and neutral checks as [`decode`].
    /// Offsets are 0: constructor-built documents have no source bytes.
    pub fn new(
        source: NeutralSource,
        unit: NeutralUnit,
        records: Vec<ReplayRecord>,
        terminal: ReplayTerminal,
    ) -> Result<Self, ReplayError> {
        if records.len() > ReplayLimits::default().max_records {
            return Err(refuse(ReplayErrorKind::LimitExceeded, 0));
        }
        assemble(
            source,
            unit,
            records,
            terminal,
            &[],
            ReplayLimits::default(),
        )
    }
    /// The admitted data records in document order (terminal excluded).
    pub fn records(&self) -> &[ReplayRecord] {
        &self.records
    }
    /// The admitted artifact binding.
    pub fn binding(&self) -> BindingId {
        self.binding
    }
    /// The admitted origin, preserved exactly.
    pub fn origin(&self) -> Origin {
        self.origin
    }
    /// The validated neutral observation.
    pub fn validated(&self) -> &ValidatedNeutralV1 {
        &self.validated
    }
}

fn serde_offset(input: &[u8], line: usize, column: usize) -> usize {
    let mut offset = 0usize;
    let mut current = 1usize;
    while current < line {
        let rest = &input[offset..];
        let Some(newline) = rest.iter().position(|&byte| byte == b'\n') else {
            return input.len();
        };
        offset += newline + 1;
        current += 1;
    }
    offset.saturating_add(column).min(input.len())
}

/// Decode and admit one v1 document. The pre-scan enforces structural
/// limits before the JSON parser builds its DOM; the semantic walk
/// checks every collection push against its limit before growing.
pub fn decode(input: &[u8], limits: ReplayLimits) -> Result<ReplayDocument, ReplayError> {
    if input.len() > limits.max_bytes {
        return Err(refuse(ReplayErrorKind::TooLarge, limits.max_bytes));
    }
    let record_offsets = Scanner::new(input, limits).scan()?;
    let parsed: serde_json::Value = serde_json::from_slice(input).map_err(|failed| {
        refuse(
            ReplayErrorKind::Malformed,
            serde_offset(input, failed.line(), failed.column()),
        )
    })?;
    let serde_json::Value::Object(root) = &parsed else {
        return Err(refuse(ReplayErrorKind::TypeMismatch, 0));
    };
    for key in root.keys() {
        if ![
            "schema", "capture", "producer", "epoch", "binding", "origin", "unit", "records",
        ]
        .contains(&key.as_str())
        {
            return Err(refuse(ReplayErrorKind::UnknownMember, 0));
        }
    }
    let root_member = |name: &str| {
        root.get(name)
            .ok_or(refuse(ReplayErrorKind::MissingMember, 0))
    };
    let schema = convert(root_member("schema")?, 0)?;
    if text_of(&schema, 0)? != REPLAY_SCHEMA_V1 {
        return Err(refuse(
            ReplayErrorKind::Contract(ContractError::IncompatibleVersion),
            0,
        ));
    }
    let capture_text = text_of(&convert(root_member("capture")?, 0)?, 0)?.to_string();
    let producer_text = text_of(&convert(root_member("producer")?, 0)?, 0)?.to_string();
    let epoch = count_of(&convert(root_member("epoch")?, 0)?, 0)?;
    let binding_text = text_of(&convert(root_member("binding")?, 0)?, 0)?.to_string();
    let origin = parse_origin_name(text_of(&convert(root_member("origin")?, 0)?, 0)?)
        .map_err(|_| refuse(ReplayErrorKind::TypeMismatch, 0))?;
    let unit = unit_of(&convert(root_member("unit")?, 0)?, 0)?;
    let source = NeutralSource {
        capture: hex_bytes(&capture_text, 0)?,
        producer: hex_bytes(&producer_text, 0)?,
        ordinal: epoch,
        binding: hex_bytes(&binding_text, 0)?,
        origin,
    };
    let records_value = root_member("records")?;
    let serde_json::Value::Array(elements) = records_value else {
        return Err(refuse(ReplayErrorKind::TypeMismatch, 0));
    };
    let at = |index: usize| record_offsets.get(index).copied().unwrap_or(0);
    let mut kinds: Vec<Option<String>> = Vec::new();
    for element in elements.iter() {
        let kind = match element {
            serde_json::Value::Object(map) => match map.get("kind") {
                Some(serde_json::Value::String(kind)) => Some(kind.clone()),
                Some(_) => None,
                None => None,
            },
            _ => None,
        };
        kinds.push(kind);
    }
    let terminal_positions: Vec<usize> = kinds
        .iter()
        .enumerate()
        .filter(|(_, kind)| kind.as_deref() == Some("terminal"))
        .map(|(index, _)| index)
        .collect();
    if terminal_positions.is_empty() {
        return Err(refuse(ReplayErrorKind::TerminalMissing, 0));
    }
    if terminal_positions.len() > 1 {
        return Err(refuse(
            ReplayErrorKind::TerminalDuplicate,
            at(terminal_positions[1]),
        ));
    }
    if terminal_positions[0] != elements.len() - 1 {
        return Err(refuse(
            ReplayErrorKind::TerminalNotFinal,
            at(terminal_positions[0]),
        ));
    }
    let mut records = Vec::new();
    for (index, element) in elements.iter().enumerate() {
        let offset = at(index);
        let serde_json::Value::Object(map) = element else {
            return Err(refuse(ReplayErrorKind::TypeMismatch, offset));
        };
        let mut fields = Vec::new();
        for (key, item) in map {
            fields.push((key.clone(), convert(item, offset)?));
        }
        let kind = text_of(member(&fields, "kind", offset)?, offset)?.to_string();
        let record_epoch = count_of(member(&fields, "epoch", offset)?, offset)?;
        if index == terminal_positions[0] {
            check_members(
                &fields,
                &[
                    "kind",
                    "epoch",
                    "counters",
                    "loss",
                    "signals",
                    "claims",
                    "partitions",
                    "corrections",
                ],
                offset,
            )?;
            let terminal = ReplayTerminal::new(
                record_epoch,
                count_of(member(&fields, "counters", offset)?, offset)?,
                count_of(member(&fields, "loss", offset)?, offset)?,
                count_of(member(&fields, "signals", offset)?, offset)?,
                count_of(member(&fields, "claims", offset)?, offset)?,
                count_of(member(&fields, "partitions", offset)?, offset)?,
                count_of(member(&fields, "corrections", offset)?, offset)?,
            );
            let _ = kind;
            return assemble(source, unit, records, terminal, &record_offsets, limits);
        }
        if records.len() == limits.max_records {
            return Err(refuse(ReplayErrorKind::LimitExceeded, offset));
        }
        records.push(ReplayRecord::new(&kind, record_epoch, fields));
    }
    Err(refuse(ReplayErrorKind::TerminalMissing, 0))
}

fn escape_into(out: &mut String, text: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in text.bytes() {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7E => out.push(byte as char),
            _ => {
                out.push_str("\\u00");
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 15) as usize] as char);
            }
        }
    }
}

fn emit_string(out: &mut String, text: &str) {
    out.push('"');
    escape_into(out, text);
    out.push('"');
}

fn emit_value(out: &mut String, value: &ReplayValue) {
    match value {
        ReplayValue::Null => out.push_str("null"),
        ReplayValue::Bool(true) => out.push_str("true"),
        ReplayValue::Bool(false) => out.push_str("false"),
        ReplayValue::Text(text) => emit_string(out, text),
        ReplayValue::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                emit_value(out, item);
            }
            out.push(']');
        }
        ReplayValue::Object(fields) => {
            out.push('{');
            for (index, (key, item)) in fields.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                emit_string(out, key);
                out.push(':');
                emit_value(out, item);
            }
            out.push('}');
        }
    }
}

fn emit_record(out: &mut String, record: &ReplayRecord) -> Result<(), ReplayError> {
    let order: &[&str] = match record.kind() {
        "counter" => &[
            "kind", "epoch", "channel", "policy", "clock", "start", "end", "value", "unit",
        ],
        "loss" => &["kind", "epoch", "channel", "loss-kind", "magnitude", "unit"],
        "signal" => &["kind", "epoch", "channel", "observed", "cap", "unit"],
        "claim" => &["kind", "epoch", "claim", "reasons"],
        "partition" => &["kind", "epoch", "total", "parts", "unit"],
        "correction" => &["kind", "epoch", "from", "to"],
        _ => return Err(refuse(ReplayErrorKind::UnknownKind, 0)),
    };
    out.push('{');
    for (index, name) in order.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        emit_string(out, name);
        out.push(':');
        match *name {
            "kind" => emit_string(out, record.kind()),
            "epoch" => emit_string(out, &record.epoch().to_string()),
            _ => {
                let value = record
                    .get(name)
                    .ok_or(refuse(ReplayErrorKind::MissingMember, 0))?;
                emit_value(out, value);
            }
        }
    }
    out.push('}');
    Ok(())
}

fn emit_terminal(out: &mut String, terminal: &ReplayTerminal) {
    out.push_str("{\"kind\":\"terminal\",\"epoch\":\"");
    out.push_str(&terminal.epoch().to_string());
    for (name, count) in [
        ("counters", terminal.counters()),
        ("loss", terminal.loss()),
        ("signals", terminal.signals()),
        ("claims", terminal.claims()),
        ("partitions", terminal.partitions()),
        ("corrections", terminal.corrections()),
    ] {
        out.push_str("\",\"");
        out.push_str(name);
        out.push_str("\":\"");
        out.push_str(&count.to_string());
    }
    out.push_str("\"}");
}

/// Re-encode an admitted document in canonical member order. The bytes
/// are a deterministic function of admitted content; hand-authored
/// fixtures (not self-roundtrips) are the encoding oracle.
pub fn encode(document: &ReplayDocument) -> Result<Vec<u8>, ReplayError> {
    let mut out = String::new();
    out.push_str("{\"schema\":\"");
    out.push_str(REPLAY_SCHEMA_V1);
    out.push_str("\",\"capture\":\"");
    out.push_str(&document.capture_hex);
    out.push_str("\",\"producer\":\"");
    out.push_str(&document.producer_hex);
    out.push_str("\",\"epoch\":\"");
    out.push_str(&document.validated.source().epoch().ordinal().to_string());
    out.push_str("\",\"binding\":\"");
    out.push_str(&document.binding_hex);
    out.push_str("\",\"origin\":\"");
    out.push_str(match document.origin {
        Origin::AdapterReported => "adapter-reported",
        Origin::Synthetic => "synthetic",
        Origin::Replayed => "replayed",
    });
    out.push_str("\",\"unit\":\"");
    out.push_str(&document.validated.unit().to_string());
    out.push_str("\",\"records\":[");
    for (index, record) in document.records.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        emit_record(&mut out, record)?;
    }
    if !document.records.is_empty() {
        out.push(',');
    }
    emit_terminal(&mut out, &document.terminal);
    out.push_str("]}");
    Ok(out.into_bytes())
}
