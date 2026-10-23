// SPDX-License-Identifier: Apache-2.0
//! BP10: narrow adapters over existing BPF loaders plus native contract vectors.
//!
//! Each adapter wraps an already-loaded program owned by an existing
//! loader and implements the BP04/BP05 [`AttachBackend`](crate::attach::AttachBackend)
//! seam with `Authority = Arc<HeldFile>`. Adapters adapt upstream APIs;
//! they never vendor loader code. No backend-neutral loader is added:
//! every backend names its loader ([`LoaderId`]) and refuses versions
//! outside its admitted table ([`admit_loader`]).
//!
//! Loader coverage in BP10:
//! - Aya: the narrow [`AyaUprobeShape`](aya::AyaUprobeShape) seam is fully
//!   proven here; the real binding over upstream `aya =0.14.0` compiles
//!   behind the `aya` feature. Live attach cells need a privileged
//!   kernel and stay NOT_RUN here (BP11/TT05 owners).
//! - libbpf: shape-only (`libbpf-rs` was unavailable in the offline crate
//!   cache); the real binding is a named follow-up.
//! - bpfman: shape-only by design (an operator/manager API, not a linked
//!   loader); an operator binding is later work.
//!
//! Standalone-seam ratification (explicit): TC05 shipped a standalone
//! graph seam (`inspect_final_object` untouched) and TC06 recorded the
//! standalone decision. BP10 keeps it: the native contract vectors in
//! `fixtures/bpf/native/` are a separate scheme over native configure and
//! output state ([`NativeState`], [`OutputLedger`]), not an extension of
//! TC03 inspect, TC05 graph extraction or TC06 prune. The `aya_adapter`
//! integration test calls those three seams as independent entry points
//! and pins their independent typed refusals.
//!
//! ADAPT provenance (all user-owned donor lines; upstream loader code
//! never copied):
//! - p11scope `.worktrees/v040-integration/crates/bpf-multi/src/lib.rs`
//!   @ `2c2713e66292b0d2688508a25f79e813ae823d81`: offsets/cookies
//!   pairing refusal (lines 226-245), errno classification
//!   (lines 288-310, adapted as [`classify_loader_errno`]) and the
//!   `GroupHalt` terminal taxonomy (lines 312-324).
//! - p11scope `tests/bpf_map_contracts.rs` @ `7f8ca02bf926a5cbd4345180bbe7367c4f1abdf4`
//!   lines 61-107: distinct sentinel FD per map. ADAPT: distinct
//!   sentinel per output span ([`OutputLedger::admit`]); no `aya_obj` use.
//! - KryProbe `crates/kryprobe-privilege/src/bpfloader/progload.rs` @
//!   `d153f3aaf9a3931337b47c9e1b046c692da55083`:
//!   `attach_type_for_section` prefix routing (lines 141-160) and its
//!   twin test (lines 622-635). ADAPT: entry/return mode routing and
//!   program-name admission with unknown-shape refusal.
//! Grant: OWNER-2026-10-23 plus the D03 scoped GPL-source to Apache-2.0
//! library-destination grant; original donor files/terms untouched.
//!
//! Native configuration is before loading/attachment; no fabricated
//! post-load autoload API is introduced. Caller-fork children must exec
//! and reacquire before using native owners; an inherited owner refuses
//! without claiming native child-destructor retirement.

use crate::{ErrorKind, Limits, OperationError, Stage};
use std::collections::HashSet;

pub mod aya;
pub mod bpfman;
pub mod libbpf;

pub use aya::{AyaBackend, AyaUprobeShape};
pub use bpfman::{BpfmanBackend, BpfmanShape};
pub use libbpf::{LibbpfBackend, LibbpfObjectShape};

/// Rule: loader version outside the admitted table.
pub const RULE_VERSION_SUPPORTED: &str = "native.version.supported";
/// Rule: site pairing rejected (empty, duplicate offset/cookie, over cap).
pub const RULE_ATTACH_PAIRING: &str = "native.attach.pairing";
/// Rule: attach mode incompatible with the loaded program shape.
pub const RULE_ATTACH_MODE: &str = "native.attach.mode-mismatch";
/// Rule: autoload flag changed after load.
pub const RULE_CONFIG_AUTOLOAD: &str = "native.configure.autoload-immutable";
/// Rule: attach target changed after load.
pub const RULE_CONFIG_TARGET: &str = "native.configure.target-immutable";
/// Rule: generation did not advance by exactly one.
pub const RULE_CONFIG_GENERATION: &str = "native.configure.generation-monotonic";
/// Rule: configure attempted on poisoned state.
pub const RULE_CONFIG_POISONED: &str = "native.configure.poisoned";
/// Rule: output spans must carry distinct ids and distinct sentinels.
pub const RULE_OUTPUT_DISTINCT: &str = "native.output.distinct-sentinels";
/// Rule: requested profile unsupported by this loader.
pub const RULE_PROFILE_SUPPORTED: &str = "native.profile.supported";

/// Existing loader selected by one adapter. There is no neutral loader.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoaderId {
    Aya,
    Libbpf,
    Bpfman,
}

impl LoaderId {
    pub fn as_str(self) -> &'static str {
        match self {
            LoaderId::Aya => "aya",
            LoaderId::Libbpf => "libbpf",
            LoaderId::Bpfman => "bpfman",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "aya" => Some(LoaderId::Aya),
            "libbpf" => Some(LoaderId::Libbpf),
            "bpfman" => Some(LoaderId::Bpfman),
            _ => None,
        }
    }
}

/// Bounded `major.minor.patch` loader version. Pre-1.0 minors break:
/// only exactly listed versions admit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoaderVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl LoaderVersion {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub const fn major(self) -> u32 {
        self.major
    }

    pub const fn minor(self) -> u32 {
        self.minor
    }

    pub const fn patch(self) -> u32 {
        self.patch
    }

    /// Parse strict ASCII `M.m.p`: one to three digits per component, no
    /// leading zeros unless the component is zero, no surrounding text.
    pub fn parse(text: &str) -> Result<Self, OperationError> {
        let mut parts = text.split('.');
        let mut values = [0u32; 3];
        for slot in values.iter_mut() {
            let part = parts.next().ok_or_else(invalid_version)?;
            if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid_version());
            }
            if part.len() > 1 && part.starts_with('0') {
                return Err(invalid_version());
            }
            *slot = part.parse::<u32>().map_err(|_| invalid_version())?;
        }
        if parts.next().is_some() {
            return Err(invalid_version());
        }
        Ok(Self {
            major: values[0],
            minor: values[1],
            patch: values[2],
        })
    }

    /// Render back to canonical `M.m.p` text.
    pub fn to_text(self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

fn invalid_version() -> OperationError {
    OperationError::new(ErrorKind::InvalidInput, Stage::Admission, None, None)
}

/// A loader/version pair admitted by [`admit_loader`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmittedLoader {
    loader: LoaderId,
    version: LoaderVersion,
}

impl AdmittedLoader {
    pub fn loader(self) -> LoaderId {
        self.loader
    }

    pub fn version(self) -> LoaderVersion {
        self.version
    }
}

/// Admit exactly the BP10-supported versions: Aya `0.14.0` (the upstream
/// pin the real binding compiles against) and shape seam `0.1.0` for the
/// libbpf/bpfman shapes (versioned with this crate). Anything else
/// refuses [`ErrorKind::Incompatible`].
pub fn admit_loader(
    loader: LoaderId,
    version: &LoaderVersion,
) -> Result<AdmittedLoader, OperationError> {
    let supported = matches!(
        (loader, version.major, version.minor, version.patch),
        (LoaderId::Aya, 0, 14, 0) | (LoaderId::Libbpf, 0, 1, 0) | (LoaderId::Bpfman, 0, 1, 0)
    );
    if !supported {
        return Err(OperationError::new(
            ErrorKind::Incompatible,
            Stage::Admission,
            None,
            None,
        ));
    }
    Ok(AdmittedLoader {
        loader,
        version: *version,
    })
}

/// Failed program adoption: the original owner travels back with the
/// cause, so admission failure never strands or drops a live program.
#[derive(Debug)]
pub struct ProgramAdoptError<T> {
    owner: T,
    cause: OperationError,
}

impl<T> ProgramAdoptError<T> {
    pub fn new(owner: T, cause: OperationError) -> Self {
        Self { owner, cause }
    }

    pub fn cause(&self) -> &OperationError {
        &self.cause
    }

    pub fn into_parts(self) -> (T, OperationError) {
        (self.owner, self.cause)
    }
}

/// One native contract violation, located by rule id and location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterViolation {
    rule: &'static str,
    location: String,
    kind: ErrorKind,
}

impl AdapterViolation {
    pub fn new(rule: &'static str, location: String, kind: ErrorKind) -> Self {
        Self {
            rule,
            location,
            kind,
        }
    }

    pub fn rule(&self) -> &'static str {
        self.rule
    }

    pub fn location(&self) -> &str {
        &self.location
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn into_error(self, stage: Stage) -> OperationError {
        OperationError::new(self.kind, stage, None, None)
    }
}

/// Loader errno classification (ADAPT of the p11scope `bpf-multi`
/// discipline): permission is systemic [`ErrorKind::Denied`], a full fd
/// table is [`ErrorKind::LimitExceeded`], missing multi support is
/// [`ErrorKind::Unsupported`]; `EINVAL` from a correctly formed request
/// means poison offsets and stays [`ErrorKind::Backend`] — it must
/// bisect, never fall back.
pub fn classify_loader_errno(errno: i32) -> ErrorKind {
    const EPERM: i32 = 1;
    const EACCES: i32 = 13;
    const EMFILE: i32 = 24;
    // EOPNOTSUPP and ENOTSUP share the value 95 on Linux; one arm
    // covers the donor's "ENOTSUP/EOPNOTSUPP" pair.
    const EOPNOTSUPP: i32 = 95;
    match errno {
        EPERM | EACCES => ErrorKind::Denied,
        EMFILE => ErrorKind::LimitExceeded,
        EOPNOTSUPP => ErrorKind::Unsupported,
        _ => ErrorKind::Backend,
    }
}

/// Native loader configuration: autoload selection, attach target and a
/// generation counter. Native configuration happens before loading; after
/// load only the generation may advance, by exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeConfig {
    pub autoload: bool,
    pub target_pid: u32,
    pub generation: u64,
}

impl NativeConfig {
    pub const fn new(autoload: bool, target_pid: u32, generation: u64) -> Self {
        Self {
            autoload,
            target_pid,
            generation,
        }
    }
}

/// Native configure state machine proving no-effect-on-error: a refused
/// configure leaves the config bit-identical; rollback failure poisons
/// explicitly and every later configure refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeState {
    config: NativeConfig,
    loaded: bool,
    poisoned: bool,
}

impl NativeState {
    pub fn new(config: NativeConfig) -> Self {
        Self {
            config,
            loaded: false,
            poisoned: false,
        }
    }

    pub fn config(&self) -> &NativeConfig {
        &self.config
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn mark_loaded(&mut self) {
        self.loaded = true;
    }

    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Apply `next`, or refuse with the locating rule. Refusal never
    /// mutates: the checks run before any assignment.
    pub fn configure(&mut self, next: &NativeConfig) -> Result<(), AdapterViolation> {
        if self.poisoned {
            return Err(AdapterViolation::new(
                RULE_CONFIG_POISONED,
                String::from("configure"),
                ErrorKind::Poisoned,
            ));
        }
        if self.loaded && next.autoload != self.config.autoload {
            return Err(AdapterViolation::new(
                RULE_CONFIG_AUTOLOAD,
                String::from("configure.autoload"),
                ErrorKind::Incompatible,
            ));
        }
        if self.loaded && next.target_pid != self.config.target_pid {
            return Err(AdapterViolation::new(
                RULE_CONFIG_TARGET,
                String::from("configure.target_pid"),
                ErrorKind::Incompatible,
            ));
        }
        if next.generation != self.config.generation.wrapping_add(1) {
            return Err(AdapterViolation::new(
                RULE_CONFIG_GENERATION,
                format!("configure.generation[{}]", self.config.generation),
                ErrorKind::Incompatible,
            ));
        }
        self.config = *next;
        Ok(())
    }
}

/// One output span: a stable id plus its sentinel bytes. Lookups never
/// mutate sentinels; a lookup failure leaves every sentinel unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputSpan {
    pub id: u32,
    pub sentinel: [u8; 8],
}

/// Admitted output ledger: span ids and sentinel values are pairwise
/// distinct (ADAPT of the donor distinct-sentinel-FD discipline), so a
/// retained sentinel proves which span produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputLedger {
    spans: Vec<OutputSpan>,
}

impl OutputLedger {
    /// Admit spans with pairwise distinct ids and sentinel values.
    pub fn admit(spans: &[OutputSpan]) -> Result<Self, AdapterViolation> {
        let mut ids = HashSet::with_capacity(spans.len());
        let mut sentinels = HashSet::with_capacity(spans.len());
        for span in spans {
            if !ids.insert(span.id) {
                return Err(AdapterViolation::new(
                    RULE_OUTPUT_DISTINCT,
                    format!("span[{}]", span.id),
                    ErrorKind::InvalidInput,
                ));
            }
            if !sentinels.insert(span.sentinel) {
                return Err(AdapterViolation::new(
                    RULE_OUTPUT_DISTINCT,
                    format!("span[{}].sentinel", span.id),
                    ErrorKind::InvalidInput,
                ));
            }
        }
        Ok(Self {
            spans: spans.to_vec(),
        })
    }

    pub fn len(&self) -> usize {
        self.spans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    /// Look up a span by id. The borrow never mutates the ledger.
    pub fn lookup(&self, id: u32) -> Option<&OutputSpan> {
        self.spans.iter().find(|span| span.id == id)
    }

    /// Read one span's sentinel bytes.
    pub fn sentinel(&self, id: u32) -> Option<[u8; 8]> {
        self.lookup(id).map(|span| span.sentinel)
    }
}

/// Shared site admission for every adapter (ADAPT of the donor pairing
/// refusal): nonempty, within `limits.sites`, pairwise distinct offsets
/// and cookies. The shape is never touched on refusal.
pub(crate) fn admit_sites(
    sites: &[crate::attach::Site],
    limits: &Limits,
) -> Result<(), OperationError> {
    if sites.is_empty() {
        return Err(OperationError::new(
            ErrorKind::InvalidInput,
            Stage::Attach,
            None,
            None,
        ));
    }
    if sites.len() > limits.sites {
        return Err(OperationError::new(
            ErrorKind::LimitExceeded,
            Stage::Attach,
            None,
            None,
        ));
    }
    let mut offsets = HashSet::with_capacity(sites.len());
    let mut cookies = HashSet::with_capacity(sites.len());
    for site in sites {
        if !offsets.insert(site.offset) || !cookies.insert(site.cookie) {
            return Err(OperationError::new(
                ErrorKind::InvalidInput,
                Stage::Attach,
                None,
                None,
            ));
        }
    }
    Ok(())
}

/// Shared custody charge: one link slot per site plus the terminal
/// uncertain slot, sixteen retained bytes per site.
pub(crate) fn charge_for(
    sites: &[crate::attach::Site],
    limits: &Limits,
) -> Result<crate::attach::CustodyCharge, OperationError> {
    if sites.len() > limits.sites {
        return Err(OperationError::new(
            ErrorKind::LimitExceeded,
            Stage::Admission,
            None,
            None,
        ));
    }
    Ok(crate::attach::CustodyCharge {
        link_slots: sites.len() + 1,
        retained_bytes: sites.len() * 16,
    })
}

// ---------------------------------------------------------------------------
// Native contract vector documents (JSON).
// ---------------------------------------------------------------------------

/// Admitted native vector schema version. Only 1 exists.
#[cfg(feature = "json")]
pub const NATIVE_VECTOR_SCHEMA_VERSION: u32 = 1;
/// Maximum cases in one vector document.
#[cfg(feature = "json")]
pub const NATIVE_VECTOR_MAX_CASES: usize = 256;
/// Maximum spans in one output case.
#[cfg(feature = "json")]
pub const NATIVE_VECTOR_MAX_SPANS: usize = 128;
/// Maximum bytes in one case name.
#[cfg(feature = "json")]
pub const NATIVE_VECTOR_MAX_NAME: usize = 128;

#[cfg(feature = "json")]
fn vector_invalid() -> OperationError {
    OperationError::new(ErrorKind::InvalidInput, Stage::Admission, None, None)
}

#[cfg(feature = "json")]
fn vector_limited() -> OperationError {
    OperationError::new(ErrorKind::LimitExceeded, Stage::Admission, None, None)
}

#[cfg(feature = "json")]
fn check_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    expected: &[&str],
) -> Result<(), OperationError> {
    for key in object.keys() {
        if !expected.contains(&key.as_str()) {
            return Err(vector_invalid());
        }
    }
    Ok(())
}

#[cfg(feature = "json")]
fn get_bool(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<bool, OperationError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(vector_invalid)
}

#[cfg(feature = "json")]
fn get_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, OperationError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(vector_invalid)
}

#[cfg(feature = "json")]
fn get_str<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a str, OperationError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(vector_invalid)
}

#[cfg(feature = "json")]
fn parse_native_config(value: &serde_json::Value) -> Result<NativeConfig, OperationError> {
    let object = value.as_object().ok_or_else(vector_invalid)?;
    check_keys(object, &["autoload", "target_pid", "generation"])?;
    Ok(NativeConfig {
        autoload: get_bool(object, "autoload")?,
        target_pid: get_u64(object, "target_pid")
            .and_then(|v| u32::try_from(v).map_err(|_| vector_invalid()))?,
        generation: get_u64(object, "generation")?,
    })
}

#[cfg(feature = "json")]
fn parse_hex8(text: &str) -> Result<[u8; 8], OperationError> {
    if text.len() != 16 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(vector_invalid());
    }
    let mut out = [0u8; 8];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| vector_invalid())?;
    }
    Ok(out)
}

/// One parsed `configure.json` case.
#[cfg(feature = "json")]
#[derive(Debug, Clone)]
pub struct ConfigureCase {
    name: String,
    loaded: bool,
    poisoned: bool,
    initial: NativeConfig,
    attempt: NativeConfig,
    expect_applied: bool,
    expect_rule: Option<String>,
    final_config: NativeConfig,
}

#[cfg(feature = "json")]
impl ConfigureCase {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn loaded(&self) -> bool {
        self.loaded
    }

    pub fn poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn initial(&self) -> &NativeConfig {
        &self.initial
    }

    pub fn attempt(&self) -> &NativeConfig {
        &self.attempt
    }

    pub fn expect_applied(&self) -> bool {
        self.expect_applied
    }

    pub fn expect_rule(&self) -> Option<&str> {
        self.expect_rule.as_deref()
    }

    pub fn final_config(&self) -> &NativeConfig {
        &self.final_config
    }
}

/// Parsed `configure.json` vector.
#[cfg(feature = "json")]
#[derive(Debug, Clone)]
pub struct ConfigureVector {
    cases: Vec<ConfigureCase>,
}

#[cfg(feature = "json")]
impl ConfigureVector {
    pub fn cases(&self) -> &[ConfigureCase] {
        &self.cases
    }
}

/// Parse one `configure.json` document: exact schema version 1, known
/// keys only, bounded names/cases. Refusals are typed; a refused
/// document never yields a partial vector.
#[cfg(feature = "json")]
pub fn parse_configure_vector(
    bytes: &[u8],
    limits: &Limits,
) -> Result<ConfigureVector, OperationError> {
    limits.validate()?;
    if bytes.len() > limits.input_bytes {
        return Err(vector_limited());
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| OperationError::new(ErrorKind::Malformed, Stage::Admission, None, None))?;
    let root = value.as_object().ok_or_else(vector_invalid)?;
    check_keys(root, &["schema_version", "kind", "cases"])?;
    if get_u64(root, "schema_version")? != u64::from(NATIVE_VECTOR_SCHEMA_VERSION) {
        return Err(vector_invalid());
    }
    if get_str(root, "kind")? != "bp10_native_configure_vector" {
        return Err(vector_invalid());
    }
    let cases = root
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(vector_invalid)?;
    if cases.len() > NATIVE_VECTOR_MAX_CASES {
        return Err(vector_limited());
    }
    let mut out = Vec::with_capacity(cases.len());
    for case in cases {
        let object = case.as_object().ok_or_else(vector_invalid)?;
        check_keys(
            object,
            &[
                "name", "loaded", "poisoned", "initial", "attempt", "expect", "rule", "final",
            ],
        )?;
        let name = get_str(object, "name")?;
        if name.is_empty() || name.len() > NATIVE_VECTOR_MAX_NAME {
            return Err(vector_invalid());
        }
        let expect = get_str(object, "expect")?;
        let expect_applied = match expect {
            "applied" => true,
            "refused" => false,
            _ => return Err(vector_invalid()),
        };
        let rule_value = object.get("rule").ok_or_else(vector_invalid)?;
        let expect_rule = match (expect_applied, rule_value) {
            (true, serde_json::Value::Null) => None,
            (false, serde_json::Value::String(rule)) => Some(rule.clone()),
            _ => return Err(vector_invalid()),
        };
        out.push(ConfigureCase {
            name: name.to_string(),
            loaded: get_bool(object, "loaded")?,
            poisoned: get_bool(object, "poisoned")?,
            initial: parse_native_config(object.get("initial").ok_or_else(vector_invalid)?)?,
            attempt: parse_native_config(object.get("attempt").ok_or_else(vector_invalid)?)?,
            expect_applied,
            expect_rule,
            final_config: parse_native_config(object.get("final").ok_or_else(vector_invalid)?)?,
        });
    }
    Ok(ConfigureVector { cases: out })
}

/// One parsed `output-spans.json` case.
#[cfg(feature = "json")]
#[derive(Debug, Clone)]
pub struct OutputCase {
    name: String,
    spans: Vec<OutputSpan>,
    lookup: u32,
    expect_hit: Option<bool>,
    expect_rule: Option<String>,
    expected_sentinels: Vec<[u8; 8]>,
}

#[cfg(feature = "json")]
impl OutputCase {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn spans(&self) -> &[OutputSpan] {
        &self.spans
    }

    pub fn lookup(&self) -> u32 {
        self.lookup
    }

    /// `Some(true)` for hit, `Some(false)` for miss, `None` for refused.
    pub fn expect_hit(&self) -> Option<bool> {
        self.expect_hit
    }

    pub fn expect_rule(&self) -> Option<&str> {
        self.expect_rule.as_deref()
    }

    pub fn expected_sentinels(&self) -> &[[u8; 8]] {
        &self.expected_sentinels
    }
}

/// Parsed `output-spans.json` vector.
#[cfg(feature = "json")]
#[derive(Debug, Clone)]
pub struct OutputVector {
    cases: Vec<OutputCase>,
}

#[cfg(feature = "json")]
impl OutputVector {
    pub fn cases(&self) -> &[OutputCase] {
        &self.cases
    }
}

/// Parse one `output-spans.json` document: exact schema version 1, known
/// keys only, 16-hex-digit sentinels, bounded names/cases/spans.
#[cfg(feature = "json")]
pub fn parse_output_vector(bytes: &[u8], limits: &Limits) -> Result<OutputVector, OperationError> {
    limits.validate()?;
    if bytes.len() > limits.input_bytes {
        return Err(vector_limited());
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| OperationError::new(ErrorKind::Malformed, Stage::Admission, None, None))?;
    let root = value.as_object().ok_or_else(vector_invalid)?;
    check_keys(root, &["schema_version", "kind", "cases"])?;
    if get_u64(root, "schema_version")? != u64::from(NATIVE_VECTOR_SCHEMA_VERSION) {
        return Err(vector_invalid());
    }
    if get_str(root, "kind")? != "bp10_native_output_vector" {
        return Err(vector_invalid());
    }
    let cases = root
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(vector_invalid)?;
    if cases.len() > NATIVE_VECTOR_MAX_CASES {
        return Err(vector_limited());
    }
    let mut out = Vec::with_capacity(cases.len());
    for case in cases {
        let object = case.as_object().ok_or_else(vector_invalid)?;
        check_keys(
            object,
            &["name", "spans", "lookup", "expect", "rule", "sentinels"],
        )?;
        let name = get_str(object, "name")?;
        if name.is_empty() || name.len() > NATIVE_VECTOR_MAX_NAME {
            return Err(vector_invalid());
        }
        let raw_spans = object
            .get("spans")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(vector_invalid)?;
        if raw_spans.len() > NATIVE_VECTOR_MAX_SPANS {
            return Err(vector_limited());
        }
        let mut spans = Vec::with_capacity(raw_spans.len());
        for span in raw_spans {
            let span_object = span.as_object().ok_or_else(vector_invalid)?;
            check_keys(span_object, &["id", "sentinel"])?;
            let id = get_u64(span_object, "id")
                .and_then(|v| u32::try_from(v).map_err(|_| vector_invalid()))?;
            spans.push(OutputSpan {
                id,
                sentinel: parse_hex8(get_str(span_object, "sentinel")?)?,
            });
        }
        let lookup = get_u64(object, "lookup")
            .and_then(|v| u32::try_from(v).map_err(|_| vector_invalid()))?;
        let expect = get_str(object, "expect")?;
        let rule_value = object.get("rule").ok_or_else(vector_invalid)?;
        let (expect_hit, expect_rule) = match (expect, rule_value) {
            ("hit", serde_json::Value::Null) => (Some(true), None),
            ("miss", serde_json::Value::Null) => (Some(false), None),
            ("refused", serde_json::Value::String(rule)) => (None, Some(rule.clone())),
            _ => return Err(vector_invalid()),
        };
        let raw_sentinels = object
            .get("sentinels")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(vector_invalid)?;
        let mut expected_sentinels = Vec::with_capacity(raw_sentinels.len());
        for sentinel in raw_sentinels {
            let text = sentinel.as_str().ok_or_else(vector_invalid)?;
            expected_sentinels.push(parse_hex8(text)?);
        }
        if expect_hit.is_some() && expected_sentinels.len() != spans.len() {
            return Err(vector_invalid());
        }
        out.push(OutputCase {
            name: name.to_string(),
            spans,
            lookup,
            expect_hit,
            expect_rule,
            expected_sentinels,
        });
    }
    Ok(OutputVector { cases: out })
}
