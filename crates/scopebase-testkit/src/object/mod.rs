// SPDX-License-Identifier: Apache-2.0
//! TC01: strict versioned compiler-profile, patch-register and toolchain parsing.
//!
//! Donor slices (p11scope-ws w000 @ 6f97aa47, frozen tree; whole user-authored
//! files): `llvm-bpf-toolchain-experiment.md` (lines 1-216),
//! `llvm-bpf-atomic-load-report.md` (lines 1-140),
//! `evidence/llvm-toolchain-review-20260922/kernel-oracle/cases.json` (1-142),
//! `prepare.py` (1-139), `run.py` (1-91), `run-raw-bpf.c` (1-76). The register
//! records only patch identity and preimage metadata; no upstream
//! context/deletion lines are copied. Grant: OWNER-2026-10-23.
//!
//! All three documents share one strict prelude: structural [`Limits`]
//! validation, input/retained/work bounds, UTF-8, duplicate-field rejection at
//! every object level (escape-insensitive), then typed admission. Unknown
//! fields refuse: new fields require a new `schema_version`, currently 1.
//!
//! TC03 appends final-object inventory ([`manifest`]), decoded inspection
//! ([`inspect`]) and explicit ISA profile admission ([`rules`]) as
//! submodules reusing this prelude. TC01 parsing above is unchanged.
use scopebase_bpf::{ErrorKind, Limits, OperationError, Stage};
use serde_json::Value;

use crate::ids::{CaseId, Label, ProfileId};

pub mod atomic;
pub mod graph;
pub mod inspect;
pub mod manifest;
pub mod rules;

pub use atomic::{
    atomic_reference, check_atomics, check_load_selector, decode_atomic, decode_plain_access,
    select_atomic_load, verify_outcome, AtomicCase, AtomicCell, AtomicDecodeError, AtomicExpected,
    AtomicInsn, AtomicLoadOutcome, AtomicOp, AtomicWidth, BackendClass, CpuClass, LoadOrdering,
    LoadRefusalReason, ObservedOutcome, OutcomeVerdict, PlainAccess,
};
pub use inspect::{inspect_final_object, FamilySpan, ObjectInspection, RuleViolation};
pub use manifest::{AdmittedObject, ArtifactId, FinalObjectManifest, ObjectEntry, ObjectKind};
pub use rules::{admit_profile, check_object, contract_families, IsaProfile};

/// Admitted profile/register/inventory schema version. Only 1 exists.
pub const SCHEMA_VERSION: u32 = 1;
const MAX_DEPTH: usize = 64;

pub(crate) fn invalid(message: &'static str) -> OperationError {
    OperationError::new(
        ErrorKind::InvalidInput,
        Stage::Admission,
        None,
        Some(Box::new(Simple(message))),
    )
}

fn incompatible(message: &'static str) -> OperationError {
    OperationError::new(
        ErrorKind::Incompatible,
        Stage::Admission,
        None,
        Some(Box::new(Simple(message))),
    )
}

fn malformed() -> OperationError {
    OperationError::new(ErrorKind::Malformed, Stage::Admission, None, None)
}

pub(crate) fn limited() -> OperationError {
    OperationError::new(ErrorKind::LimitExceeded, Stage::Admission, None, None)
}

#[derive(Debug)]
struct Simple(&'static str);

impl std::fmt::Display for Simple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tc01 strict document: {}", self.0)
    }
}

impl std::error::Error for Simple {}

pub(crate) fn strict_value(bytes: &[u8], limits: &Limits) -> Result<Value, OperationError> {
    limits.validate()?;
    if bytes.len() > limits.input_bytes || bytes.len() > limits.retained_bytes {
        return Err(limited());
    }
    if bytes.len() as u64 > limits.work_steps {
        return Err(limited());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| malformed())?;
    reject_duplicate_fields(text)?;
    serde_json::from_str(text).map_err(|_| malformed())
}

pub(crate) fn check_version(root: &serde_json::Map<String, Value>) -> Result<(), OperationError> {
    match root.get("schema_version").and_then(Value::as_u64) {
        Some(version) if version == u64::from(SCHEMA_VERSION) => Ok(()),
        _ => Err(invalid("schema_version must be exactly 1")),
    }
}

pub(crate) fn check_no_unknown(
    root: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> Result<(), OperationError> {
    if root.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid("unknown field"));
    }
    Ok(())
}

pub(crate) fn get_str<'a>(
    root: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, OperationError> {
    root.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(field))
}

fn get_opt_str<'a>(
    root: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<Option<&'a str>, OperationError> {
    match root.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(_) => Err(invalid(field)),
    }
}

pub(crate) fn parse_sha256(text: &str, field: &'static str) -> Result<[u8; 32], OperationError> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(field));
    }
    let mut out = [0u8; 32];
    for (index, chunk) in text.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| invalid(field))?;
        out[index] = u8::from_str_radix(pair, 16).map_err(|_| invalid(field))?;
    }
    Ok(out)
}

pub(crate) fn parse_label(text: &str, field: &'static str) -> Result<(), OperationError> {
    Label::parse(text).map(|_| ()).map_err(|_| invalid(field))
}

fn parse_profile(text: &str, field: &'static str) -> Result<(), OperationError> {
    ProfileId::parse(text)
        .map(|_| ())
        .map_err(|_| invalid(field))
}

fn parse_case(text: &str, field: &'static str) -> Result<(), OperationError> {
    CaseId::parse(text).map(|_| ()).map_err(|_| invalid(field))
}

fn parse_id_list(
    root: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<Vec<String>, OperationError> {
    let values = root
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(field))?;
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let text = value.as_str().ok_or_else(|| invalid(field))?;
        parse_label(text, field)?;
        out.push(text.to_owned());
    }
    Ok(out)
}

/// Reject duplicate object keys at every nesting level.
///
/// Keys compare after JSON escape decoding, so `"a"` and `"\\u0061"` collide.
/// Malformed strings or nesting beyond [`MAX_DEPTH`] refuse here; remaining
/// JSON shape errors are reported by the typed decoder.
fn reject_duplicate_fields(text: &str) -> Result<(), OperationError> {
    #[derive(PartialEq)]
    enum Expect {
        Key,
        Colon,
        Value,
        CommaOrEnd,
    }
    enum Frame {
        Object { keys: Vec<Vec<u8>>, expect: Expect },
        Array { expect_value: bool, empty: bool },
    }
    let bytes = text.as_bytes();
    let mut index = 0usize;
    let mut stack: Vec<Frame> = Vec::new();
    let mut root_done = false;

    let skip_ws = |index: &mut usize| {
        while *index < bytes.len() && matches!(bytes[*index], b' ' | b'\t' | b'\n' | b'\r') {
            *index += 1;
        }
    };
    // Decode one JSON string starting at the opening quote; return decoded
    // bytes and the index just past the closing quote.
    let decode_string = |start: usize| -> Result<(Vec<u8>, usize), OperationError> {
        let mut out = Vec::new();
        let mut i = start + 1;
        while i < bytes.len() {
            match bytes[i] {
                b'"' => return Ok((out, i + 1)),
                b'\\' => {
                    i += 1;
                    if i >= bytes.len() {
                        return Err(malformed());
                    }
                    match bytes[i] {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0C),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            if i + 4 >= bytes.len() {
                                return Err(malformed());
                            }
                            let digits = std::str::from_utf8(&bytes[i + 1..i + 5])
                                .map_err(|_| malformed())?;
                            let mut unit =
                                u32::from_str_radix(digits, 16).map_err(|_| malformed())?;
                            i += 4;
                            if (0xD800..0xDC00).contains(&unit)
                                && i + 6 < bytes.len()
                                && bytes[i + 1] == b'\\'
                                && bytes[i + 2] == b'u'
                            {
                                let low = std::str::from_utf8(&bytes[i + 3..i + 7])
                                    .map_err(|_| malformed())?;
                                let low = u32::from_str_radix(low, 16).map_err(|_| malformed())?;
                                if (0xDC00..0xE000).contains(&low) {
                                    unit = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                                    i += 6;
                                }
                            }
                            let scalar = char::from_u32(unit).ok_or_else(malformed)?;
                            let mut encoded = [0u8; 4];
                            out.extend_from_slice(scalar.encode_utf8(&mut encoded).as_bytes());
                        }
                        _ => return Err(malformed()),
                    }
                    i += 1;
                }
                _ => {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
        }
        Err(malformed())
    };
    // Mark one complete value in the enclosing frame.
    let complete_value =
        |stack: &mut Vec<Frame>, root_done: &mut bool| -> Result<(), OperationError> {
            match stack.last_mut() {
                None => {
                    if *root_done {
                        return Err(malformed());
                    }
                    *root_done = true;
                }
                Some(Frame::Object { expect, .. }) => {
                    if *expect != Expect::Value {
                        return Err(malformed());
                    }
                    *expect = Expect::CommaOrEnd;
                }
                Some(Frame::Array {
                    expect_value,
                    empty,
                }) => {
                    if !*expect_value {
                        return Err(malformed());
                    }
                    *expect_value = false;
                    *empty = false;
                }
            }
            Ok(())
        };

    loop {
        skip_ws(&mut index);
        if index >= bytes.len() {
            break;
        }
        if stack.len() > MAX_DEPTH {
            return Err(limited());
        }
        let byte = bytes[index];
        match byte {
            b'{' | b'[' => {
                let value_position = match stack.last() {
                    None => !root_done,
                    Some(Frame::Object { expect, .. }) => *expect == Expect::Value,
                    Some(Frame::Array { expect_value, .. }) => *expect_value,
                };
                if !value_position {
                    return Err(malformed());
                }
                if stack.len() + 1 > MAX_DEPTH {
                    return Err(limited());
                }
                stack.push(if byte == b'{' {
                    Frame::Object {
                        keys: Vec::new(),
                        expect: Expect::Key,
                    }
                } else {
                    Frame::Array {
                        expect_value: true,
                        empty: true,
                    }
                });
                index += 1;
            }
            b'}' => {
                match stack.pop() {
                    Some(Frame::Object { keys, expect }) => {
                        if expect != Expect::CommaOrEnd
                            && !(expect == Expect::Key && keys.is_empty())
                        {
                            return Err(malformed());
                        }
                    }
                    _ => return Err(malformed()),
                }
                index += 1;
                complete_value(&mut stack, &mut root_done)?;
            }
            b']' => {
                match stack.pop() {
                    Some(Frame::Array {
                        expect_value,
                        empty,
                    }) => {
                        // `[]` is the only value-position close; `[1,]` refuses
                        // because a comma always demands another value.
                        if expect_value && !empty {
                            return Err(malformed());
                        }
                    }
                    _ => return Err(malformed()),
                }
                index += 1;
                complete_value(&mut stack, &mut root_done)?;
            }
            b',' => {
                match stack.last_mut() {
                    Some(Frame::Object { expect, .. }) => {
                        if *expect != Expect::CommaOrEnd {
                            return Err(malformed());
                        }
                        *expect = Expect::Key;
                    }
                    Some(Frame::Array { expect_value, .. }) => {
                        if *expect_value {
                            return Err(malformed());
                        }
                        *expect_value = true;
                    }
                    None => return Err(malformed()),
                }
                index += 1;
            }
            b':' => {
                match stack.last_mut() {
                    Some(Frame::Object { expect, .. }) => {
                        if *expect != Expect::Colon {
                            return Err(malformed());
                        }
                        *expect = Expect::Value;
                    }
                    _ => return Err(malformed()),
                }
                index += 1;
            }
            b'"' => {
                let (decoded, next) = decode_string(index)?;
                index = next;
                match stack.last_mut() {
                    Some(Frame::Object { keys, expect }) if *expect == Expect::Key => {
                        if keys.iter().any(|seen| *seen == decoded) {
                            return Err(invalid("duplicate field"));
                        }
                        keys.push(decoded);
                        *expect = Expect::Colon;
                    }
                    _ => complete_value(&mut stack, &mut root_done)?,
                }
            }
            _ => {
                // Skip one scalar atom; spelling is validated by the decoder.
                let start = index;
                while index < bytes.len()
                    && !matches!(bytes[index], b'"' | b'{' | b'}' | b'[' | b']' | b',' | b':')
                    && !matches!(bytes[index], b' ' | b'\t' | b'\n' | b'\r')
                {
                    index += 1;
                }
                if index == start {
                    return Err(malformed());
                }
                complete_value(&mut stack, &mut root_done)?;
            }
        }
    }
    if stack.is_empty() && root_done {
        Ok(())
    } else {
        Err(malformed())
    }
}

// ---------------------------------------------------------------------------
// ObjectContract
// ---------------------------------------------------------------------------

const PROFILE_FIELDS: &[&str] = &[
    "schema_version",
    "artifact",
    "profile",
    "target",
    "backend",
    "cpu",
    "features_enabled",
    "features_disabled",
    "required_cells",
    "optional_cells",
];
const TARGET_FIELDS: &[&str] = &["triple", "arch", "endian", "pointer_width_bits"];
const BACKEND_FIELDS: &[&str] = &["kind", "name", "version", "sha256"];
const BACKEND_KINDS: &[&str] = &["llvm-llc", "clang", "rustc", "bpf-linker", "aya", "libbpf"];
pub(crate) const KNOWN_CPUS: &[&str] = &["generic", "v3", "v4"];
pub(crate) const KNOWN_FEATURES: &[&str] = &[
    "alu32",
    "jump32",
    "ext-jumps",
    "signed-load-move",
    "byte-swap",
    "signed-div",
    "long-jump",
    "imm-store",
    "acqrel",
    "indirect-jumps",
];
/// Backend features the donor evidence ties to the v4 CPU preset only:
/// acquire/release lowering and indirect jumps are absent from generic/v3.
pub(crate) const V4_ONLY_FEATURES: &[&str] = &["acqrel", "indirect-jumps"];

/// Strict compiler-profile admission contract (TC01 parsing increment).
///
/// This owns document admission only: schema version, identifiers, target,
/// backend identity, CPU/feature coherence and exact cell lists. Final-object
/// inspection over an admitted contract is TC03 work.
#[derive(Debug, Clone)]
pub struct ObjectContract {
    artifact: String,
    profile: String,
    triple: String,
    arch: String,
    endian: String,
    pointer_width_bits: u64,
    backend_kind: String,
    backend_name: String,
    backend_version: String,
    backend_sha256: [u8; 32],
    cpu: Option<String>,
    features_enabled: Vec<String>,
    features_disabled: Vec<String>,
    required_cells: Vec<String>,
    optional_cells: Vec<String>,
}

impl ObjectContract {
    /// Admit one strict versioned profile document.
    pub fn from_json(bytes: &[u8], limits: &Limits) -> Result<Self, OperationError> {
        let value = strict_value(bytes, limits)?;
        let root = value.as_object().ok_or_else(|| invalid("profile object"))?;
        check_version(root)?;
        check_no_unknown(root, PROFILE_FIELDS)?;
        let artifact = get_str(root, "artifact")?;
        parse_label(artifact, "artifact")?;
        let profile = get_str(root, "profile")?;
        parse_profile(profile, "profile")?;
        let target = root
            .get("target")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("target"))?;
        check_no_unknown(target, TARGET_FIELDS)?;
        let triple = get_str(target, "triple")?;
        if triple.is_empty()
            || triple.len() > 128
            || !triple.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(invalid("triple"));
        }
        let arch = get_str(target, "arch")?;
        if !matches!(arch, "bpf" | "bpfel" | "bpfeb") {
            return Err(invalid("arch"));
        }
        let endian = get_str(target, "endian")?;
        if !matches!(endian, "little" | "big") {
            return Err(invalid("endian"));
        }
        let pointer_width_bits = target
            .get("pointer_width_bits")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("pointer_width_bits"))?;
        if !matches!(pointer_width_bits, 32 | 64) {
            return Err(invalid("pointer_width_bits"));
        }
        let backend = root
            .get("backend")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("backend"))?;
        check_no_unknown(backend, BACKEND_FIELDS)?;
        let backend_kind = get_str(backend, "kind")?;
        if !BACKEND_KINDS.contains(&backend_kind) {
            return Err(invalid("backend kind"));
        }
        let backend_name = get_str(backend, "name")?;
        if backend_name.is_empty() || backend_name.len() > 128 {
            return Err(invalid("backend name"));
        }
        let backend_version = get_str(backend, "version")?;
        if backend_version.is_empty() || backend_version.len() > 128 {
            return Err(invalid("backend version"));
        }
        let backend_sha256 = parse_sha256(get_str(backend, "sha256")?, "backend sha256")?;
        let cpu = get_opt_str(root, "cpu")?;
        if let Some(cpu) = cpu {
            if !KNOWN_CPUS.contains(&cpu) {
                return Err(invalid("cpu"));
            }
        }
        let features_enabled = parse_id_list(root, "features_enabled")?;
        let features_disabled = parse_id_list(root, "features_disabled")?;
        for feature in features_enabled.iter().chain(features_disabled.iter()) {
            if !KNOWN_FEATURES.contains(&feature.as_str()) {
                return Err(invalid("feature"));
            }
        }
        if features_enabled
            .iter()
            .any(|feature| features_disabled.iter().any(|other| other == feature))
        {
            return Err(incompatible("feature enabled and disabled"));
        }
        match cpu {
            None | Some("generic") => {
                if !features_enabled.is_empty() {
                    return Err(incompatible("enabled features without a v3/v4 cpu pin"));
                }
            }
            Some("v3") => {
                if features_enabled
                    .iter()
                    .any(|feature| V4_ONLY_FEATURES.contains(&feature.as_str()))
                {
                    return Err(incompatible("v4-only feature on v3"));
                }
            }
            Some(_) => {}
        }
        let required_cells = parse_id_list(root, "required_cells")?;
        let optional_cells = parse_id_list(root, "optional_cells")?;
        Ok(Self {
            artifact: artifact.to_owned(),
            profile: profile.to_owned(),
            triple: triple.to_owned(),
            arch: arch.to_owned(),
            endian: endian.to_owned(),
            pointer_width_bits,
            backend_kind: backend_kind.to_owned(),
            backend_name: backend_name.to_owned(),
            backend_version: backend_version.to_owned(),
            backend_sha256,
            cpu: cpu.map(str::to_owned),
            features_enabled,
            features_disabled,
            required_cells,
            optional_cells,
        })
    }

    /// Admitted schema version; always [`SCHEMA_VERSION`].
    pub fn schema_version(&self) -> u32 {
        SCHEMA_VERSION
    }
    /// Admitted artifact name.
    pub fn artifact(&self) -> &str {
        &self.artifact
    }
    /// Admitted conformance profile id.
    pub fn profile(&self) -> &str {
        &self.profile
    }
    /// Admitted target triple.
    pub fn triple(&self) -> &str {
        &self.triple
    }
    /// Admitted target architecture.
    pub fn arch(&self) -> &str {
        &self.arch
    }
    /// Admitted target endianness.
    pub fn endian(&self) -> &str {
        &self.endian
    }
    /// Admitted pointer width in bits.
    pub fn pointer_width_bits(&self) -> u64 {
        self.pointer_width_bits
    }
    /// Admitted backend kind.
    pub fn backend_kind(&self) -> &str {
        &self.backend_kind
    }
    /// Admitted backend tool name.
    pub fn backend_name(&self) -> &str {
        &self.backend_name
    }
    /// Admitted exact backend version.
    pub fn backend_version(&self) -> &str {
        &self.backend_version
    }
    /// Admitted exact backend identity hash.
    pub fn backend_sha256(&self) -> &[u8; 32] {
        &self.backend_sha256
    }
    /// Admitted CPU pin; `None` is distinct from every named preset.
    pub fn cpu(&self) -> Option<&str> {
        self.cpu.as_deref()
    }
    /// Admitted explicitly enabled backend features.
    pub fn features_enabled(&self) -> &[String] {
        &self.features_enabled
    }
    /// Admitted explicitly disabled backend features.
    pub fn features_disabled(&self) -> &[String] {
        &self.features_disabled
    }
    /// Admitted exact required runtime cells; wildcards refuse.
    pub fn required_cells(&self) -> &[String] {
        &self.required_cells
    }
    /// Admitted exact optional runtime cells; wildcards refuse.
    pub fn optional_cells(&self) -> &[String] {
        &self.optional_cells
    }
}

// ---------------------------------------------------------------------------
// PatchRegister
// ---------------------------------------------------------------------------

const REGISTER_FIELDS: &[&str] = &["schema_version", "kind", "patches"];
const PATCH_FIELDS: &[&str] = &[
    "id",
    "scope",
    "upstream_base",
    "preimage_kind",
    "preimage",
    "preimage_note",
    "patch_sha256",
    "applicability",
    "affected_profiles",
    "owner",
    "defect_test",
    "upstream_status",
    "inclusion_test",
    "removal_test",
    "expired",
];
const STATUS_FIELDS: &[&str] = &["state", "ref"];
const STATUS_STATES: &[&str] = &["open", "merged", "unsubmitted", "not-applicable"];
const PREIMAGE_KINDS: &[&str] = &["sha256", "git-sha1"];

/// One individually scoped patch/workaround record.
#[derive(Debug, Clone)]
pub struct PatchRecord {
    id: String,
    scope: String,
    upstream_base: String,
    preimage_kind: String,
    preimage: String,
    preimage_note: String,
    patch_sha256: [u8; 32],
    applicability: String,
    affected_profiles: Vec<String>,
    owner: String,
    defect_test: String,
    upstream_state: String,
    upstream_ref: String,
    inclusion_test: String,
    removal_test: String,
    expired: bool,
}

impl PatchRecord {
    /// Record identifier.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Patch scope; distinct repairs never share one record.
    pub fn scope(&self) -> &str {
        &self.scope
    }
    /// Exact upstream base the patch applies to.
    pub fn upstream_base(&self) -> &str {
        &self.upstream_base
    }
    /// Preimage hash kind: `sha256` (exact bytes hashed) or `git-sha1`.
    pub fn preimage_kind(&self) -> &str {
        &self.preimage_kind
    }
    /// Exact preimage pin: 64 lowercase hex for `sha256`, 40 for `git-sha1`.
    pub fn preimage(&self) -> &str {
        &self.preimage
    }
    /// What the preimage pin identifies (archive, file bytes, or base commit).
    pub fn preimage_note(&self) -> &str {
        &self.preimage_note
    }
    /// Hash of the exact patch bytes.
    pub fn patch_sha256(&self) -> &[u8; 32] {
        &self.patch_sha256
    }
    /// When the patch applies (scope/conditions in prose).
    pub fn applicability(&self) -> &str {
        &self.applicability
    }
    /// Affected conformance profiles.
    pub fn affected_profiles(&self) -> &[String] {
        &self.affected_profiles
    }
    /// Record owner.
    pub fn owner(&self) -> &str {
        &self.owner
    }
    /// Reproducer test for the defect.
    pub fn defect_test(&self) -> &str {
        &self.defect_test
    }
    /// Upstream state; a merge alone never expires the record.
    pub fn upstream_state(&self) -> &str {
        &self.upstream_state
    }
    /// Upstream reference (issue, pull request or commit).
    pub fn upstream_ref(&self) -> &str {
        &self.upstream_ref
    }
    /// Selected-binary inclusion test.
    pub fn inclusion_test(&self) -> &str {
        &self.inclusion_test
    }
    /// Workaround removal test.
    pub fn removal_test(&self) -> &str {
        &self.removal_test
    }
    /// Whether the workaround has expired with full evidence.
    pub fn expired(&self) -> bool {
        self.expired
    }
}

/// Strict versioned patch register.
#[derive(Debug, Clone)]
pub struct PatchRegister {
    patches: Vec<PatchRecord>,
}

impl PatchRegister {
    /// Admit one strict versioned patch register document.
    pub fn from_json(bytes: &[u8], limits: &Limits) -> Result<Self, OperationError> {
        let value = strict_value(bytes, limits)?;
        let root = value
            .as_object()
            .ok_or_else(|| invalid("register object"))?;
        check_version(root)?;
        check_no_unknown(root, REGISTER_FIELDS)?;
        if get_str(root, "kind")? != "tc01_patch_register" {
            return Err(invalid("kind"));
        }
        let patches = root
            .get("patches")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("patches"))?;
        let mut out = Vec::with_capacity(patches.len());
        for patch in patches {
            let patch = patch.as_object().ok_or_else(|| invalid("patch"))?;
            check_no_unknown(patch, PATCH_FIELDS)?;
            let id = get_str(patch, "id")?;
            parse_label(id, "patch id")?;
            if out.iter().any(|seen: &PatchRecord| seen.id == id) {
                return Err(invalid("duplicate patch id"));
            }
            let scope = get_str(patch, "scope")?;
            parse_label(scope, "scope")?;
            let upstream_base = get_str(patch, "upstream_base")?;
            if upstream_base.is_empty() {
                return Err(invalid("upstream_base"));
            }
            let preimage_kind = get_str(patch, "preimage_kind")?;
            if !PREIMAGE_KINDS.contains(&preimage_kind) {
                return Err(invalid("preimage_kind"));
            }
            let preimage = get_str(patch, "preimage")?;
            let expected_len = if preimage_kind == "sha256" { 64 } else { 40 };
            if preimage.len() != expected_len
                || !preimage
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(invalid("preimage"));
            }
            let preimage_note = get_str(patch, "preimage_note")?;
            if preimage_note.is_empty() || preimage_note.len() > 1024 {
                return Err(invalid("preimage_note"));
            }
            let patch_sha256 = parse_sha256(get_str(patch, "patch_sha256")?, "patch_sha256")?;
            let applicability = get_str(patch, "applicability")?;
            if applicability.is_empty() {
                return Err(invalid("applicability"));
            }
            let affected = patch
                .get("affected_profiles")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("affected_profiles"))?;
            if affected.is_empty() {
                return Err(invalid("affected_profiles"));
            }
            let mut affected_profiles = Vec::with_capacity(affected.len());
            for profile in affected {
                let text = profile
                    .as_str()
                    .ok_or_else(|| invalid("affected_profiles"))?;
                parse_profile(text, "affected_profiles")?;
                affected_profiles.push(text.to_owned());
            }
            let owner = get_str(patch, "owner")?;
            if owner.is_empty() {
                return Err(invalid("owner"));
            }
            let defect_test = get_str(patch, "defect_test")?;
            parse_case(defect_test, "defect_test")?;
            let status = patch
                .get("upstream_status")
                .and_then(Value::as_object)
                .ok_or_else(|| invalid("upstream_status"))?;
            check_no_unknown(status, STATUS_FIELDS)?;
            let upstream_state = get_str(status, "state")?;
            if !STATUS_STATES.contains(&upstream_state) {
                return Err(invalid("upstream state"));
            }
            let upstream_ref = get_str(status, "ref")?;
            if upstream_ref.is_empty() {
                return Err(invalid("upstream ref"));
            }
            let inclusion_test = get_str(patch, "inclusion_test")?;
            parse_case(inclusion_test, "inclusion_test")?;
            let removal_test = get_str(patch, "removal_test")?;
            parse_case(removal_test, "removal_test")?;
            let expired = patch
                .get("expired")
                .and_then(Value::as_bool)
                .ok_or_else(|| invalid("expired"))?;
            out.push(PatchRecord {
                id: id.to_owned(),
                scope: scope.to_owned(),
                upstream_base: upstream_base.to_owned(),
                preimage_kind: preimage_kind.to_owned(),
                preimage: preimage.to_owned(),
                preimage_note: preimage_note.to_owned(),
                patch_sha256,
                applicability: applicability.to_owned(),
                affected_profiles,
                owner: owner.to_owned(),
                defect_test: defect_test.to_owned(),
                upstream_state: upstream_state.to_owned(),
                upstream_ref: upstream_ref.to_owned(),
                inclusion_test: inclusion_test.to_owned(),
                removal_test: removal_test.to_owned(),
                expired,
            });
        }
        Ok(Self { patches: out })
    }

    /// Admitted patch records.
    pub fn patches(&self) -> &[PatchRecord] {
        &self.patches
    }

    /// Number of admitted patch records.
    pub fn len(&self) -> usize {
        self.patches.len()
    }

    /// Whether the register holds no records.
    pub fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    /// Find one record by id.
    pub fn find(&self, id: &str) -> Option<&PatchRecord> {
        self.patches.iter().find(|patch| patch.id == id)
    }
}

// ---------------------------------------------------------------------------
// ToolchainInventory
// ---------------------------------------------------------------------------

const INVENTORY_FIELDS: &[&str] = &["schema_version", "kind", "tools"];
const TOOL_FIELDS: &[&str] = &[
    "id",
    "role",
    "name",
    "version",
    "version_detail",
    "sha256",
    "hash_status",
    "origin",
    "origin_ref",
    "used_for",
];
const TOOL_ROLES: &[&str] = &[
    "frontend",
    "backend",
    "linker",
    "rust",
    "runner",
    "source-archive",
];
const TOOL_ORIGINS: &[&str] = &["pinned-archive", "preserved-binary", "system-observed"];

/// One pinned toolchain entry. Entries resolve offline: exact versions plus
/// exact hashes where the donor recorded them, never a download step.
#[derive(Debug, Clone)]
pub struct ToolPin {
    id: String,
    role: String,
    name: String,
    version: String,
    version_detail: String,
    sha256: Option<[u8; 32]>,
    hash_status: String,
    origin: String,
    origin_ref: String,
    used_for: String,
}

impl ToolPin {
    /// Pin identifier.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Tool role in the compiler closure.
    pub fn role(&self) -> &str {
        &self.role
    }
    /// Tool name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Exact observed version.
    pub fn version(&self) -> &str {
        &self.version
    }
    /// Exact observed version detail.
    pub fn version_detail(&self) -> &str {
        &self.version_detail
    }
    /// Exact binary/archive hash where the donor recorded one.
    pub fn sha256(&self) -> Option<&[u8; 32]> {
        self.sha256.as_ref()
    }
    /// Whether an exact hash was recorded.
    pub fn hash_recorded(&self) -> bool {
        self.sha256.is_some()
    }
    /// Hash provenance: `recorded` or `unrecorded`.
    pub fn hash_status(&self) -> &str {
        &self.hash_status
    }
    /// Offline origin class.
    pub fn origin(&self) -> &str {
        &self.origin
    }
    /// Frozen-evidence reference for the pin.
    pub fn origin_ref(&self) -> &str {
        &self.origin_ref
    }
    /// What the pinned tool was used for.
    pub fn used_for(&self) -> &str {
        &self.used_for
    }
}

/// Strict versioned toolchain inventory.
#[derive(Debug, Clone)]
pub struct ToolchainInventory {
    tools: Vec<ToolPin>,
}

impl ToolchainInventory {
    /// Admit one strict versioned toolchain inventory document.
    pub fn from_json(bytes: &[u8], limits: &Limits) -> Result<Self, OperationError> {
        let value = strict_value(bytes, limits)?;
        let root = value
            .as_object()
            .ok_or_else(|| invalid("inventory object"))?;
        check_version(root)?;
        check_no_unknown(root, INVENTORY_FIELDS)?;
        if get_str(root, "kind")? != "tc01_toolchain_inventory" {
            return Err(invalid("kind"));
        }
        let tools = root
            .get("tools")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("tools"))?;
        let mut out = Vec::with_capacity(tools.len());
        for tool in tools {
            let tool = tool.as_object().ok_or_else(|| invalid("tool"))?;
            check_no_unknown(tool, TOOL_FIELDS)?;
            let id = get_str(tool, "id")?;
            parse_label(id, "tool id")?;
            if out.iter().any(|seen: &ToolPin| seen.id == id) {
                return Err(invalid("duplicate tool id"));
            }
            let role = get_str(tool, "role")?;
            if !TOOL_ROLES.contains(&role) {
                return Err(invalid("role"));
            }
            let name = get_str(tool, "name")?;
            if name.is_empty() {
                return Err(invalid("name"));
            }
            let version = get_str(tool, "version")?;
            if version.is_empty() {
                return Err(invalid("version"));
            }
            let version_detail = get_str(tool, "version_detail")?;
            if version_detail.is_empty() {
                return Err(invalid("version_detail"));
            }
            let sha256 = match tool.get("sha256") {
                None | Some(Value::Null) => None,
                Some(Value::String(text)) => Some(parse_sha256(text, "sha256")?),
                Some(_) => return Err(invalid("sha256")),
            };
            let hash_status = get_str(tool, "hash_status")?;
            match (hash_status, sha256.is_some()) {
                ("recorded", true) | ("unrecorded", false) => {}
                _ => return Err(invalid("hash_status")),
            }
            let origin = get_str(tool, "origin")?;
            if !TOOL_ORIGINS.contains(&origin) {
                return Err(invalid("origin"));
            }
            let origin_ref = get_str(tool, "origin_ref")?;
            if origin_ref.is_empty() {
                return Err(invalid("origin_ref"));
            }
            let used_for = get_str(tool, "used_for")?;
            if used_for.is_empty() {
                return Err(invalid("used_for"));
            }
            out.push(ToolPin {
                id: id.to_owned(),
                role: role.to_owned(),
                name: name.to_owned(),
                version: version.to_owned(),
                version_detail: version_detail.to_owned(),
                sha256,
                hash_status: hash_status.to_owned(),
                origin: origin.to_owned(),
                origin_ref: origin_ref.to_owned(),
                used_for: used_for.to_owned(),
            });
        }
        Ok(Self { tools: out })
    }

    /// Admitted toolchain pins.
    pub fn tools(&self) -> &[ToolPin] {
        &self.tools
    }

    /// Number of admitted pins.
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Whether the inventory holds no pins.
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Find one pin by id.
    pub fn find(&self, id: &str) -> Option<&ToolPin> {
        self.tools.iter().find(|tool| tool.id == id)
    }
}

// ---------------------------------------------------------------------------
// TC03 shared refusal constructor (appended; TC01 helpers above unchanged)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Tc03Msg(&'static str);

impl std::fmt::Display for Tc03Msg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tc03 object: {}", self.0)
    }
}

impl std::error::Error for Tc03Msg {}

pub(crate) fn tc03_refuse(kind: ErrorKind, message: &'static str) -> OperationError {
    OperationError::new(
        kind,
        Stage::Admission,
        None,
        Some(Box::new(Tc03Msg(message))),
    )
}
