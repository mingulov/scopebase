// SPDX-License-Identifier: Apache-2.0
//! TC06: restricted dead-code repair and verifier-sensitive rule manifests.
//!
//! [`prune_dead_code`] is the one admitted object transform: it strips
//! unreachable `.text` functions, and only functions named by the caller
//! allowlist drawn from the frozen dead-builtins inventory
//! ([`FROZEN_DEAD_BUILTINS`]). Dead code outside the allowlist, shifted
//! entry targets, shifted section-symbol call destinations (R01: no pass
//! rewrites call immediates), interior calls, unrelocated call sites,
//! unsupported relocations, truncation, misalignment and BTF-affecting
//! strips all refuse typed; the repair never rewrites speculatively and
//! never treats
//! a compiler flag as proof that roots disappeared. The transformed bytes
//! are a new final artifact: the caller re-admits and reruns the rules on
//! them ([`PruneReport`] carries both hashes).
//!
//! [`check_verifier_rules`] evaluates admitted [`VerifierRules`] manifests
//! (shipped in `tools/bpf-compat/profiles/`) over one final object plus an
//! optional BP09 [`BtfView`]. Structural truncation, target contradiction
//! and budget exhaustion refuse typed; every semantic finding returns as a
//! [`RuleViolation`] with a stable rule id. Covered families: named
//! padding SHAPE only (H08 extent rule; the byte-initialization check
//! stays open per the rule docs and the TODO.md H08 row), exact GLOBAL
//! symbol/BTF linkage (H10), per-frame stack accounting with call-arity
//! and pointer-bundled shapes (H08/H10), path-scoped initializer guards
//! (H10) and the required private-stack tail-call prologue with
//! program-array attribution (H09). R45: the summary previously
//! overclaimed initialized-padding coverage the shape rule cannot prove.
//!
//! Standalone-seam decision (explicit): the plan's Interfaces text wanted
//! `inspect_final_object`/`ObjectInspection` extension, but TC05 shipped a
//! standalone graph seam, and wiring the repair onto TC05's [`CallGraph`]
//! would be unsound, not merely invasive: TC05 resolves immediate-only
//! linked calls within one section, while the repair must resolve
//! relocation-aware `-1` calls across sections. Composing them would
//! misread live relocatable roots as dead and strip live code. TC06
//! therefore keeps its own bounded decode (the TC05 precedent beside TC03
//! inspect) and reuses TC03's `RuleViolation`/`ObjectContract`/`Limits`
//! types plus BP09 `BtfView` queries at the seams that are sound.
//!
//! ADAPT (mechanism + vectors, user-owned donor lines only):
//! - kryprobe-ws kryprobe w001 @ d153f3aaf9a3931337b47c9e1b046c692da55083,
//!   `xtask/src/bpf/strip.rs`: rationale 1-9, pipeline 64-103, tiling
//!   249-307, call-target/entry-root `-1` convention 347-412, reachability
//!   424-474, kept planning and shifted-entry refusal 551-592, compaction
//!   594-615, symtab/reloc rewrite 617-800, verify 825-852, vectors
//!   1019-1076. Adapted to typed errors, `Limits` budgets, contract
//!   endianness and an explicit allowlist gate; the unrelocated-call scan
//!   closes a linked-input hole the donor's relocatable-only path never
//!   meets; the first-global boundary is recomputed over kept globals.
//! - Same worktree/commit, `docs/dependencies/pins.md` lines 72-85
//!   (flag/injection distinction, 28-byte `memset` fusion hazard) and
//!   `crates/bpf-spine/src/bin/spine.rs` lines 104-132 (builtin-free init
//!   path through volatile stores).
//! - p11scope-ws `.worktrees/v040-integration` @
//!   2c2713e66292b0d2688508a25f79e813ae823d81,
//!   `crates/ebpf/src/main.rs` lines 173-205 (opt-out prologue) and
//!   750-771 (named `_pad`; old-verifier EACCES counterexample),
//!   `scripts/check-bpf-map-defs.py` lines 1216-1302 (per-program
//!   opt-out/continuation/attribution), 1195-1214 (array attribution),
//!   1002-1006 (helper id, opt-out index), 1042-1051 (opt-out-only
//!   bodies), 1321-1339 and 1402-1405 (exact `0x12` GLOBAL linkage in
//!   symbol and BTF), `tests/python/test_bpf_map_defs.py` lines 274-356
//!   (prologue twin matrix). The six-scalar/bundled call shape is a
//!   design-frozen classification (BPF r1-r5 register file); no donor
//!   slice for it was found and the TC07 live gate is pending.
//! Grant: OWNER-2026-10-23 plus the D03 scoped GPL-source to Apache-2.0
//! library-destination grant; original donor files/terms untouched.
use scopebase_bpf::{
    btf::{BtfView, TypeKind},
    ErrorKind, Limits, OperationError, Stage,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::inspect::RuleViolation;
use super::{
    check_no_unknown, check_version, get_str, invalid, parse_label, strict_value, ObjectContract,
};

/// Relocation types (donor-cited docs.kernel.org/bpf/llvm_reloc.html).
const R_BPF_NONE: u32 = 0;
const R_BPF_64_64: u32 = 1;
const R_BPF_64_ABS64: u32 = 2;
const R_BPF_64_ABS32: u32 = 3;
const R_BPF_64_NODYLD32: u32 = 4;
const R_BPF_64_32: u32 = 10;

const EM_BPF: u16 = 247;
const SHF_EXECINSTR: u64 = 0x4;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_REL: u32 = 9;
const SHT_SYMTAB_SHNDX: u32 = 18;

const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;
/// Exact `st_info` for a GLOBAL FUNC symbol (donor `0x12` linkage check).
const ST_INFO_GLOBAL_FUNC: u8 = 0x12;

/// Opcode `JMP | CALL` (helper call with src 0, subprogram call src 1).
const OP_CALL: u8 = 0x85;
/// Opcode `LD | IMM_DW` (16-byte wide load; second slot is data).
const OP_LD_IMM64: u8 = 0x18;
/// `BPF_FUNC_tail_call` (kernel UAPI helper id, donor-pinned bpf.h fact).
const TAIL_CALL_HELPER: i32 = 12;

/// The only function names the restricted repair may remove, and then
/// only when unreachable. Frozen to KryProbe's demonstrated case: rustc
/// exports exactly these as link roots and bpf-linker has no GC.
/// Extending this list needs a new demonstrated donor case, not a flag.
pub const FROZEN_DEAD_BUILTINS: &[&str] = &["memcpy", "memmove", "memset"];

/// Maximum entries in one manifest list (rules, sections, arrays, ...).
const MAX_LIST: usize = 64;
/// Maximum bytes in one admitted manifest name or label.
const MAX_NAME: usize = 256;

#[derive(Debug)]
struct Tc06Msg(String);

impl std::fmt::Display for Tc06Msg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tc06 prune and object rules: {}", self.0)
    }
}

impl std::error::Error for Tc06Msg {}

fn refuse(kind: ErrorKind, message: impl Into<String>) -> OperationError {
    OperationError::new(
        kind,
        Stage::Inspect,
        None,
        Some(Box::new(Tc06Msg(message.into()))),
    )
}

fn limited() -> OperationError {
    OperationError::new(ErrorKind::LimitExceeded, Stage::Inspect, None, None)
}

fn finding(rule_id: &'static str, section: Option<String>, offset: Option<u64>) -> RuleViolation {
    RuleViolation {
        rule_id: rule_id.to_owned(),
        section,
        offset,
        kind: ErrorKind::Incompatible,
    }
}

/// R08: charge a result record BEFORE allocating it. Every rule
/// finding accounts its record plus retained strings against the
/// same cumulative `retained_bytes` ceiling as decoding, so a long
/// section name times many findings cannot amplify past the budget.
/// All rule paths push through here; direct `finding` pushes are gone.
fn push_finding(
    violations: &mut Vec<RuleViolation>,
    retained: &mut usize,
    limits: &Limits,
    rule_id: &'static str,
    section: Option<&str>,
    offset: Option<u64>,
) -> Result<(), OperationError> {
    let mut bytes = size_of::<RuleViolation>().saturating_add(rule_id.len());
    if let Some(name) = section {
        bytes = bytes.saturating_add(name.len());
    }
    retain(retained, limits, bytes)?;
    violations.push(finding(rule_id, section.map(str::to_owned), offset));
    Ok(())
}

/// R08: section-attributed finding without cloning the name before
/// its charge. The fallback label length is computed arithmetically
/// (`"section#{}"`: 8 fixed bytes plus decimal digits, no allocation).
fn push_section_finding(
    violations: &mut Vec<RuleViolation>,
    retained: &mut usize,
    limits: &Limits,
    rule_id: &'static str,
    section: &Section,
    offset: Option<u64>,
) -> Result<(), OperationError> {
    let len = section
        .name
        .as_deref()
        .map(str::len)
        .unwrap_or_else(|| 8 + section.index.checked_ilog10().unwrap_or(0) as usize + 1);
    retain(
        retained,
        limits,
        size_of::<RuleViolation>()
            .saturating_add(rule_id.len())
            .saturating_add(len),
    )?;
    violations.push(finding(rule_id, Some(section.label()), offset));
    Ok(())
}

fn charge(work: &mut u64, steps: u64) -> Result<(), OperationError> {
    if *work < steps {
        return Err(limited());
    }
    *work -= steps;
    Ok(())
}

/// Account `bytes` of decoded heap retention against the cumulative
/// `retained_bytes` ceiling (F12): shared strings cloned per symbol or
/// record would otherwise amplify a small input without bound.
fn retain(retained: &mut usize, limits: &Limits, bytes: usize) -> Result<(), OperationError> {
    *retained = retained.checked_add(bytes).ok_or_else(limited)?;
    if *retained > limits.retained_bytes {
        return Err(limited());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Strict admission: prune allowlist and rule manifests
// ---------------------------------------------------------------------------

const ALLOWLIST_FIELDS: &[&str] = &["schema_version", "kind", "names"];
const MANIFEST_FIELDS: &[&str] = &["schema_version", "kind", "name", "version", "rules"];

/// Caller allowlist admitted from a strict JSON document: every name must
/// belong to [`FROZEN_DEAD_BUILTINS`] and appear exactly once.
#[derive(Debug, Clone)]
pub struct PruneAllowlist {
    names: Vec<String>,
}

impl PruneAllowlist {
    /// Admit one strict allowlist document.
    pub fn from_json(bytes: &[u8], limits: &Limits) -> Result<Self, OperationError> {
        let value = strict_value(bytes, limits)?;
        let root = value
            .as_object()
            .ok_or_else(|| invalid("allowlist object"))?;
        check_version(root)?;
        check_no_unknown(root, ALLOWLIST_FIELDS)?;
        if get_str(root, "kind")? != "tc06_prune_allowlist" {
            return Err(invalid("allowlist kind"));
        }
        let names = root
            .get("names")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("allowlist names"))?;
        if names.len() > MAX_LIST {
            return Err(super::limited());
        }
        let mut out = Vec::with_capacity(names.len());
        for name in names {
            let text = name.as_str().ok_or_else(|| invalid("allowlist names"))?;
            parse_label(text, "allowlist names")?;
            if !FROZEN_DEAD_BUILTINS.contains(&text) {
                return Err(invalid("unknown allowlist entry"));
            }
            if out.iter().any(|seen: &String| seen == text) {
                return Err(invalid("duplicate allowlist entry"));
            }
            out.push(text.to_owned());
        }
        Ok(Self { names: out })
    }

    /// The full frozen inventory.
    pub fn frozen_builtins() -> Self {
        Self {
            names: FROZEN_DEAD_BUILTINS
                .iter()
                .map(|name| name.to_string())
                .collect(),
        }
    }

    /// Admitted names in document order.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    fn allows(&self, name: &str) -> bool {
        self.names.iter().any(|allowed| allowed == name)
    }
}

fn get_u64(
    root: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<u64, OperationError> {
    root.get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(field))
}

fn get_name(
    root: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<String, OperationError> {
    let text = get_str(root, field)?;
    parse_label(text, field)?;
    if text.len() > MAX_NAME {
        return Err(invalid(field));
    }
    Ok(text.to_owned())
}

/// Assembler-name grammar for BTF/symbol/function names: C identifiers
/// plus dots and dollars for linker-qualified forms (`_pad`,
/// `p11_link_current_identity`, `.text`). Labels are stricter (no
/// leading punctuation); these names need the wider set.
fn check_long_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_NAME
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'$'))
}

/// ELF section names additionally admit `/` (`raw_tp/sched_process_exec`).
fn check_section_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_NAME
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'$' | b'/'))
}

fn get_long_name(
    root: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<String, OperationError> {
    let text = get_str(root, field)?;
    if !check_long_name(text) {
        return Err(invalid(field));
    }
    Ok(text.to_owned())
}

fn get_section_list(
    root: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<Vec<String>, OperationError> {
    let values = root
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(field))?;
    if values.is_empty() || values.len() > MAX_LIST {
        return Err(invalid(field));
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let text = value.as_str().ok_or_else(|| invalid(field))?;
        if !check_section_name(text) {
            return Err(invalid(field));
        }
        if out.iter().any(|seen: &String| seen == text) {
            return Err(invalid(field));
        }
        out.push(text.to_owned());
    }
    Ok(out)
}

fn get_label_list(
    root: &serde_json::Map<String, Value>,
    field: &'static str,
    min: usize,
) -> Result<Vec<String>, OperationError> {
    let values = root
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(field))?;
    if values.len() < min || values.len() > MAX_LIST {
        return Err(invalid(field));
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let text = value.as_str().ok_or_else(|| invalid(field))?;
        parse_label(text, field)?;
        if out.iter().any(|seen: &String| seen == text) {
            return Err(invalid(field));
        }
        out.push(text.to_owned());
    }
    Ok(out)
}

/// One admitted verifier-sensitive rule with its manifest parameters.
#[derive(Debug, Clone)]
enum Rule {
    /// A BTF struct/union carries one named padding member at an exact
    /// extent with an exact whole size (H08 named padding, shape only).
    /// This proves the pad is explicit, not that emitted stores
    /// initialize it; the byte-initialization check stays open (F24).
    PadNamed {
        ty: String,
        member: String,
        offset: u64,
        size: u64,
        struct_size: u64,
    },
    /// One symbol is exactly GLOBAL FUNC in its section with a unique
    /// valid BTF FUNC prototype that is itself GLOBAL (H10 linkage).
    LinkageGlobal { symbol: String, section: String },
    /// Every executable function frame counts at least the minimum
    /// against a combined budget (H08/H10 stack accounting).
    FrameMinimum {
        min_frame_bytes: u64,
        max_total_bytes: u64,
    },
    /// A BTF function prototype takes at most the register-file limit
    /// (design-frozen arity; TC07 live gate pending).
    MaxParams { function: String, max_params: u64 },
    /// A BTF function prototype matches the prescribed pointer-bundled
    /// replacement shape exactly (design-frozen; TC07 gate pending).
    Bundled {
        function: String,
        pointers: Vec<bool>,
    },
    /// One named path never calls one named initializer; other callers
    /// are unaffected (H10 path-scoped guard).
    PathGuard { path: String, forbidden: String },
    /// Every uprobe-section program carries the opt-out tail call or a
    /// known continuation through its attributed array (H09).
    OptOut {
        sections: Vec<String>,
        arrays: Vec<String>,
        opt_out_index: u64,
        continuations: Vec<(String, u64)>,
        multi_loaded: Vec<String>,
        pair: Option<String>,
        pair_array: String,
        plain_array: String,
        multi_array: String,
    },
}

/// One admitted verifier-sensitive rule manifest.
#[derive(Debug, Clone)]
pub struct VerifierRules {
    name: String,
    version: String,
    rules: Vec<Rule>,
}

impl VerifierRules {
    /// Admit one strict rule-manifest document.
    pub fn from_json(bytes: &[u8], limits: &Limits) -> Result<Self, OperationError> {
        let value = strict_value(bytes, limits)?;
        let root = value.as_object().ok_or_else(|| invalid("rule manifest"))?;
        check_version(root)?;
        check_no_unknown(root, MANIFEST_FIELDS)?;
        if get_str(root, "kind")? != "tc06_rule_manifest" {
            return Err(invalid("rule manifest kind"));
        }
        let name = get_name(root, "name")?;
        let version = get_name(root, "version")?;
        let rules = root
            .get("rules")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("rule manifest rules"))?;
        if rules.len() > MAX_LIST {
            return Err(super::limited());
        }
        let mut out = Vec::with_capacity(rules.len());
        for rule in rules {
            let body = rule.as_object().ok_or_else(|| invalid("rule object"))?;
            out.push(admit_rule(body)?);
        }
        Ok(Self {
            name,
            version,
            rules: out,
        })
    }

    /// Manifest name (`padding`, `linkage`, `stack`, `private-stack`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Manifest version label.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Number of admitted rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the manifest carries no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

const PAD_FIELDS: &[&str] = &["rule", "type", "member", "offset", "size", "struct_size"];
const LINKAGE_FIELDS: &[&str] = &["rule", "symbol", "section"];
const FRAME_FIELDS: &[&str] = &["rule", "min_frame_bytes", "max_total_bytes"];
const PARAMS_FIELDS: &[&str] = &["rule", "function", "max_params"];
const BUNDLED_FIELDS: &[&str] = &["rule", "function", "params"];
const BUNDLED_PARAM_FIELDS: &[&str] = &["pointer"];
const GUARD_FIELDS: &[&str] = &["rule", "path", "forbidden"];
const OPTOUT_FIELDS: &[&str] = &[
    "rule",
    "sections",
    "arrays",
    "opt_out_index",
    "continuations",
    "multi_loaded",
    "pair",
    "pair_array",
    "plain_array",
    "multi_array",
];
const ARRAY_FIELDS: &[&str] = &["name"];
const SLOT_FIELDS: &[&str] = &["array", "slot"];

fn admit_rule(body: &serde_json::Map<String, Value>) -> Result<Rule, OperationError> {
    match get_str(body, "rule")? {
        "padding.named-pad-required" => {
            check_no_unknown(body, PAD_FIELDS)?;
            Ok(Rule::PadNamed {
                ty: get_long_name(body, "type")?,
                member: get_long_name(body, "member")?,
                offset: get_u64(body, "offset")?,
                size: get_u64(body, "size")?,
                struct_size: get_u64(body, "struct_size")?,
            })
        }
        "linkage.global-required" => {
            check_no_unknown(body, LINKAGE_FIELDS)?;
            Ok(Rule::LinkageGlobal {
                symbol: get_long_name(body, "symbol")?,
                section: get_long_name(body, "section")?,
            })
        }
        "stack.per-frame-minimum" => {
            check_no_unknown(body, FRAME_FIELDS)?;
            Ok(Rule::FrameMinimum {
                min_frame_bytes: get_u64(body, "min_frame_bytes")?,
                max_total_bytes: get_u64(body, "max_total_bytes")?,
            })
        }
        "call.max-params" => {
            check_no_unknown(body, PARAMS_FIELDS)?;
            Ok(Rule::MaxParams {
                function: get_long_name(body, "function")?,
                max_params: get_u64(body, "max_params")?,
            })
        }
        "call.bundled-replacement" => {
            check_no_unknown(body, BUNDLED_FIELDS)?;
            let params = body
                .get("params")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("bundled params"))?;
            if params.is_empty() || params.len() > MAX_LIST {
                return Err(invalid("bundled params"));
            }
            let mut pointers = Vec::with_capacity(params.len());
            for param in params {
                let entry = param.as_object().ok_or_else(|| invalid("bundled param"))?;
                check_no_unknown(entry, BUNDLED_PARAM_FIELDS)?;
                pointers.push(
                    entry
                        .get("pointer")
                        .and_then(Value::as_bool)
                        .ok_or_else(|| invalid("bundled pointer"))?,
                );
            }
            Ok(Rule::Bundled {
                function: get_long_name(body, "function")?,
                pointers,
            })
        }
        "init.path-guard" => {
            check_no_unknown(body, GUARD_FIELDS)?;
            Ok(Rule::PathGuard {
                path: get_long_name(body, "path")?,
                forbidden: get_long_name(body, "forbidden")?,
            })
        }
        "private-stack.opt-out-required" => admit_opt_out(body),
        _ => Err(invalid("unknown rule")),
    }
}

fn admit_opt_out(body: &serde_json::Map<String, Value>) -> Result<Rule, OperationError> {
    check_no_unknown(body, OPTOUT_FIELDS)?;
    let sections = get_section_list(body, "sections")?;
    let raw_arrays = body
        .get("arrays")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("opt-out arrays"))?;
    if raw_arrays.is_empty() || raw_arrays.len() > MAX_LIST {
        return Err(invalid("opt-out arrays"));
    }
    let mut arrays = Vec::with_capacity(raw_arrays.len());
    for entry in raw_arrays {
        let item = entry.as_object().ok_or_else(|| invalid("opt-out array"))?;
        check_no_unknown(item, ARRAY_FIELDS)?;
        let name = get_name(item, "name")?;
        if arrays.iter().any(|seen: &String| seen == &name) {
            return Err(invalid("opt-out arrays"));
        }
        arrays.push(name);
    }
    let raw_slots = body
        .get("continuations")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("opt-out continuations"))?;
    if raw_slots.len() > MAX_LIST {
        return Err(invalid("opt-out continuations"));
    }
    let mut continuations = Vec::with_capacity(raw_slots.len());
    for entry in raw_slots {
        let item = entry
            .as_object()
            .ok_or_else(|| invalid("opt-out continuation"))?;
        check_no_unknown(item, SLOT_FIELDS)?;
        let array = get_name(item, "array")?;
        if !arrays.iter().any(|known: &String| known == &array) {
            return Err(invalid("unknown program array"));
        }
        let slot = item
            .get("slot")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("opt-out slot"))?;
        continuations.push((array, slot));
    }
    let multi_loaded = get_label_list(body, "multi_loaded", 0)?;
    let pair = match body.get("pair") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => {
            parse_label(text, "opt-out pair")?;
            Some(text.clone())
        }
        Some(_) => return Err(invalid("opt-out pair")),
    };
    let pair_array = get_name(body, "pair_array")?;
    let plain_array = get_name(body, "plain_array")?;
    let multi_array = get_name(body, "multi_array")?;
    for array in [&pair_array, &plain_array, &multi_array] {
        if !arrays.iter().any(|known: &String| known == array) {
            return Err(invalid("unknown program array"));
        }
    }
    Ok(Rule::OptOut {
        sections,
        arrays,
        opt_out_index: get_u64(body, "opt_out_index")?,
        continuations,
        multi_loaded,
        pair,
        pair_array,
        plain_array,
        multi_array,
    })
}

// ---------------------------------------------------------------------------
// Bounded ELF decode shared by the repair and the checker
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Data {
    Little,
    Big,
}

impl Data {
    fn u16(self, bytes: &[u8]) -> u16 {
        let pair = [bytes[0], bytes[1]];
        match self {
            Self::Little => u16::from_le_bytes(pair),
            Self::Big => u16::from_be_bytes(pair),
        }
    }

    fn u32(self, bytes: &[u8]) -> u32 {
        let quad = [bytes[0], bytes[1], bytes[2], bytes[3]];
        match self {
            Self::Little => u32::from_le_bytes(quad),
            Self::Big => u32::from_be_bytes(quad),
        }
    }

    /// S04: register nibbles follow object endianness. Genuine `llc
    /// -march=bpfeb` output swaps them: a pseudo-call emits register
    /// byte 0x01 and `mov32 r1, 1` emits 0x10 (LE: 0x10 and 0x01).
    /// Decoding `src` as the high nibble unconditionally treats every
    /// big-endian pseudo-call as a helper call and lets unrelocated
    /// sites evade the initializer guard.
    fn dst_reg(self, regs: u8) -> u8 {
        match self {
            Self::Little => regs & 15,
            Self::Big => regs >> 4,
        }
    }

    fn src_reg(self, regs: u8) -> u8 {
        match self {
            Self::Little => regs >> 4,
            Self::Big => regs & 15,
        }
    }

    fn u64(self, bytes: &[u8]) -> u64 {
        let mut wide = [0u8; 8];
        wide.copy_from_slice(&bytes[..8]);
        match self {
            Self::Little => u64::from_le_bytes(wide),
            Self::Big => u64::from_be_bytes(wide),
        }
    }

    fn encode_u32(self, value: u32) -> [u8; 4] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }

    fn encode_u64(self, value: u64) -> [u8; 8] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }
}

struct Section {
    index: usize,
    name: Option<String>,
    kind: u32,
    flags: u64,
    off: u64,
    len: u64,
    link: u32,
    info: u32,
    entsize: u64,
}

impl Section {
    fn label(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("section#{}", self.index))
    }

    fn executable(&self) -> bool {
        self.kind == SHT_PROGBITS && self.flags & SHF_EXECINSTR != 0
    }
}

struct Symbol {
    name: Option<String>,
    info: u8,
    other: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

impl Symbol {
    fn kind(&self) -> u8 {
        self.info & 15
    }

    fn bind(&self) -> u8 {
        self.info >> 4
    }

    fn display(&self) -> String {
        self.name.clone().unwrap_or_else(|| "symbol#?".to_owned())
    }
}

/// One raw `Elf64_Rel` entry plus its section context.
#[derive(Debug, Clone, Copy)]
struct Reloc {
    /// Index of the `SHT_REL` section holding the entry.
    rel_sect: usize,
    /// Section the reloc applies to (`sh_info` of the reloc section).
    target_sect: usize,
    /// Byte offset within the target section.
    offset: u64,
    /// Referenced symbol index.
    sym_idx: usize,
    /// Relocation type.
    typ: u32,
}

struct Image<'a> {
    bytes: &'a [u8],
    data: Data,
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
}

impl<'a> Image<'a> {
    fn body(&self, section: &Section) -> Result<&'a [u8], OperationError> {
        let end = section.off.checked_add(section.len).ok_or_else(|| {
            refuse(
                ErrorKind::Malformed,
                format!("{} outside file", section.label()),
            )
        })?;
        if end > self.bytes.len() as u64 {
            return Err(refuse(
                ErrorKind::Malformed,
                format!("{} outside file", section.label()),
            ));
        }
        Ok(&self.bytes[section.off as usize..end as usize])
    }

    fn find_text(&self) -> Result<usize, OperationError> {
        self.sections
            .iter()
            .position(|section| section.name.as_deref() == Some(".text"))
            .ok_or_else(|| refuse(ErrorKind::InvalidInput, "missing section '.text'"))
    }
}

fn decode<'a>(
    bytes: &'a [u8],
    contract: &ObjectContract,
    limits: &Limits,
    work: &mut u64,
) -> Result<(Image<'a>, usize), OperationError> {
    limits.validate()?;
    if bytes.len() > limits.input_bytes || bytes.len() > limits.retained_bytes {
        return Err(limited());
    }
    charge(work, 1)?;
    let mut retained = bytes.len();
    if bytes.len() < 64 {
        return Err(refuse(ErrorKind::Malformed, "truncated elf header"));
    }
    if bytes[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(refuse(ErrorKind::Malformed, "not an elf object"));
    }
    if bytes[4] != 2 {
        return Err(refuse(ErrorKind::Malformed, "not a 64-bit object"));
    }
    let data = match bytes[5] {
        1 => Data::Little,
        2 => Data::Big,
        _ => return Err(refuse(ErrorKind::Malformed, "unknown elf data encoding")),
    };
    let contract_little = match contract.endian() {
        "little" => true,
        "big" => false,
        _ => return Err(refuse(ErrorKind::InvalidInput, "contract endian")),
    };
    if (data == Data::Little) != contract_little {
        return Err(refuse(
            ErrorKind::Incompatible,
            "object endianness contradicts contract",
        ));
    }
    if data.u16(&bytes[0x12..0x14]) != EM_BPF {
        return Err(refuse(
            ErrorKind::Incompatible,
            "object machine contradicts bpf contract",
        ));
    }
    let shoff = data.u64(&bytes[0x28..0x30]);
    let shentsize = data.u16(&bytes[0x3a..0x3c]);
    let shnum = data.u16(&bytes[0x3c..0x3e]);
    let shstrndx = data.u16(&bytes[0x3e..0x40]);
    if shentsize != 64 {
        return Err(refuse(
            ErrorKind::Malformed,
            "unsupported section header size",
        ));
    }
    if usize::from(shnum) > limits.sites {
        return Err(limited());
    }
    let table_end = shoff
        .checked_add(u64::from(shnum) * 64)
        .ok_or_else(|| refuse(ErrorKind::Malformed, "truncated section table"))?;
    if table_end > bytes.len() as u64 {
        return Err(refuse(ErrorKind::Malformed, "truncated section table"));
    }
    let mut sections = Vec::with_capacity(usize::from(shnum));
    for index in 0..usize::from(shnum) {
        charge(work, 1)?;
        retain(&mut retained, limits, size_of::<Section>())?;
        let header = &bytes[shoff as usize + index * 64..shoff as usize + (index + 1) * 64];
        sections.push(Section {
            index,
            name: None,
            kind: data.u32(&header[4..8]),
            flags: data.u64(&header[8..16]),
            off: data.u64(&header[24..32]),
            len: data.u64(&header[32..40]),
            link: data.u32(&header[40..44]),
            info: data.u32(&header[44..48]),
            entsize: data.u64(&header[56..64]),
        });
    }
    if usize::from(shstrndx) >= sections.len() {
        return Err(refuse(ErrorKind::Malformed, "truncated section names"));
    }
    let names = sections[usize::from(shstrndx)].off;
    let names_len = sections[usize::from(shstrndx)].len;
    let names_end = names
        .checked_add(names_len)
        .ok_or_else(|| refuse(ErrorKind::Malformed, "section names outside file"))?;
    if names_end > bytes.len() as u64 {
        return Err(refuse(ErrorKind::Malformed, "section names outside file"));
    }
    let table = &bytes[names as usize..names_end as usize];
    for section in &mut sections {
        let header =
            &bytes[shoff as usize + section.index * 64..shoff as usize + section.index * 64 + 4];
        let name_off = data.u32(header) as usize;
        if name_off >= table.len() {
            return Err(refuse(ErrorKind::Malformed, "bad section name"));
        }
        let end = table[name_off..]
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| refuse(ErrorKind::Malformed, "bad section name"))?;
        charge(work, end as u64)?;
        let name = std::str::from_utf8(&table[name_off..name_off + end])
            .map_err(|_| refuse(ErrorKind::Malformed, "bad section name"))?;
        if section.index != 0 {
            retain(&mut retained, limits, name.len())?;
            section.name = Some(name.to_owned());
        }
    }
    for section in &sections {
        if section.kind == SHT_SYMTAB_SHNDX {
            return Err(refuse(
                ErrorKind::Unsupported,
                "extended section indices unsupported",
            ));
        }
    }
    let symtab = sections
        .iter()
        .filter(|section| section.kind == SHT_SYMTAB)
        .count();
    if symtab > 1 {
        return Err(refuse(ErrorKind::InvalidInput, "more than one symtab"));
    }
    let symtab = sections
        .iter()
        .find(|section| section.kind == SHT_SYMTAB)
        .ok_or_else(|| refuse(ErrorKind::InvalidInput, "missing symtab"))?;
    if symtab.entsize != 24 {
        return Err(refuse(ErrorKind::Malformed, "symtab entry size is not 24"));
    }
    let sym_end = symtab
        .off
        .checked_add(symtab.len)
        .ok_or_else(|| refuse(ErrorKind::Malformed, "symtab outside file"))?;
    if sym_end > bytes.len() as u64 {
        return Err(refuse(ErrorKind::Malformed, "symtab outside file"));
    }
    if symtab.len % 24 != 0 {
        return Err(refuse(
            ErrorKind::Malformed,
            "symtab length is not a multiple of 24",
        ));
    }
    if symtab.link as usize >= sections.len() {
        return Err(refuse(ErrorKind::Malformed, "symtab names outside file"));
    }
    let strings = &sections[symtab.link as usize];
    let strings_end = strings
        .off
        .checked_add(strings.len)
        .ok_or_else(|| refuse(ErrorKind::Malformed, "symtab names outside file"))?;
    if strings_end > bytes.len() as u64 {
        return Err(refuse(ErrorKind::Malformed, "symtab names outside file"));
    }
    let strtab = &bytes[strings.off as usize..strings_end as usize];
    let raw = &bytes[symtab.off as usize..sym_end as usize];
    let mut symbols = Vec::with_capacity(raw.len() / 24);
    for entry in raw.chunks_exact(24) {
        charge(work, 1)?;
        retain(&mut retained, limits, size_of::<Symbol>())?;
        let name_off = data.u32(&entry[0..4]) as usize;
        if name_off >= strtab.len() {
            return Err(refuse(ErrorKind::Malformed, "bad symbol name"));
        }
        let end = strtab[name_off..]
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| refuse(ErrorKind::Malformed, "bad symbol name"))?;
        charge(work, end as u64)?;
        let name = std::str::from_utf8(&strtab[name_off..name_off + end])
            .map_err(|_| refuse(ErrorKind::Malformed, "bad symbol name"))?;
        if !name.is_empty() {
            retain(&mut retained, limits, name.len())?;
        }
        symbols.push(Symbol {
            name: if name.is_empty() {
                None
            } else {
                Some(name.to_owned())
            },
            info: entry[4],
            other: entry[5],
            shndx: data.u16(&entry[6..8]),
            value: data.u64(&entry[8..16]),
            size: data.u64(&entry[16..24]),
        });
    }
    Ok((
        Image {
            bytes,
            data,
            sections,
            symbols,
        },
        retained,
    ))
}

fn digest_of(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

fn contains_name(haystack: &[u8], needle: &str) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

// ---------------------------------------------------------------------------
// Restricted dead-code repair
// ---------------------------------------------------------------------------

/// One `.text` function symbol.
struct Func {
    name: String,
    value: u64,
    size: u64,
    sym_idx: usize,
}

/// Restricted-repair report with original/transformed hashes.
#[derive(Debug, Clone)]
pub struct PruneReport {
    removed: Vec<String>,
    text_before: u64,
    text_after: u64,
    original_sha256: [u8; 32],
    output_sha256: [u8; 32],
}

impl PruneReport {
    /// Removed function names, ascending by old `.text` offset.
    pub fn removed(&self) -> &[String] {
        &self.removed
    }

    /// `.text` length before the repair, in bytes.
    pub fn text_before(&self) -> u64 {
        self.text_before
    }

    /// `.text` length after the repair, in bytes.
    pub fn text_after(&self) -> u64 {
        self.text_after
    }

    /// Hash of the input bytes.
    pub fn original_sha256(&self) -> &[u8; 32] {
        &self.original_sha256
    }

    /// Hash of the repaired bytes.
    pub fn output_sha256(&self) -> &[u8; 32] {
        &self.output_sha256
    }
}

/// Restricted dead-code repair over the frozen builtins inventory.
///
/// Plan-exact entry: unreachable `memcpy`/`memmove`/`memset` `.text`
/// functions are stripped with consistent symbol/call/relocation
/// rewrites; every other shape refuses typed.
pub fn prune_dead_code(
    bytes: &[u8],
    contract: &ObjectContract,
    limits: &Limits,
) -> Result<Vec<u8>, OperationError> {
    Ok(prune_dead_code_with_report(bytes, contract, &PruneAllowlist::frozen_builtins(), limits)?.0)
}

/// Restricted dead-code repair with an explicit allowlist and report.
///
/// The allowlist must itself be admitted (unknown names refuse there);
/// dead functions outside it refuse the whole repair.
pub fn prune_dead_code_with_report(
    bytes: &[u8],
    contract: &ObjectContract,
    allow: &PruneAllowlist,
    limits: &Limits,
) -> Result<(Vec<u8>, PruneReport), OperationError> {
    let mut work = limits.work_steps;
    let (image, mut retained) = decode(bytes, contract, limits, &mut work)?;
    if image
        .sections
        .iter()
        .any(|section| section.kind == SHT_RELA)
    {
        return Err(refuse(ErrorKind::Unsupported, "rela sections unsupported"));
    }
    let text_idx = image.find_text()?;
    let symtab_idx = image
        .sections
        .iter()
        .position(|section| section.kind == SHT_SYMTAB)
        .ok_or_else(|| refuse(ErrorKind::InvalidInput, "missing symtab"))?;
    let funcs = collect_funcs(&image, text_idx, &mut work, &mut retained, limits)?;
    let relocs = collect_relocs(&image, &mut work, &mut retained, limits)?;
    check_call_coverage(&image, &relocs, &mut work, &mut retained, limits)?;
    let roots = entry_roots(&image, text_idx, &relocs, &mut work)?;
    let live = reachable(&image, text_idx, &funcs, &relocs, &roots, &mut work)?;
    let dead: Vec<&Func> = funcs.iter().filter(|func| !live[func.sym_idx]).collect();
    for func in &dead {
        if !allow.allows(&func.name) {
            return Err(refuse(
                ErrorKind::Unsupported,
                format!(
                    "dead function '{}' is outside the prune allowlist",
                    func.name
                ),
            ));
        }
    }
    let text_len = image.sections[text_idx].len;
    if dead.is_empty() {
        let hash = digest_of(bytes);
        return Ok((
            bytes.to_vec(),
            PruneReport {
                removed: Vec::new(),
                text_before: text_len,
                text_after: text_len,
                original_sha256: hash,
                output_sha256: hash,
            },
        ));
    }
    check_btf_gates(&image, &dead, &mut work)?;
    let (kept, cursor) = plan_kept(&funcs, &live);
    check_entry_calls(&image, text_idx, &funcs, &relocs, &kept, &mut work)?;
    check_data_refs(&image, text_idx, &relocs, &kept, &mut work)?;
    let mut out = bytes.to_vec();
    compact_text(&image, text_idx, &kept, cursor, &mut out, &mut work)?;
    let map = rewrite_symtab(
        &image, symtab_idx, &funcs, &live, &kept, &mut out, &mut work,
    )?;
    rewrite_relocs(&image, text_idx, &relocs, &kept, &map, &mut out, &mut work)?;
    let removed: Vec<String> = dead.iter().map(|func| func.name.clone()).collect();
    let report = PruneReport {
        removed,
        text_before: text_len,
        text_after: cursor,
        original_sha256: digest_of(bytes),
        output_sha256: digest_of(&out),
    };
    verify(&out, contract, limits, &report)?;
    Ok((out, report))
}

fn collect_funcs(
    image: &Image<'_>,
    text_idx: usize,
    work: &mut u64,
    retained: &mut usize,
    limits: &Limits,
) -> Result<Vec<Func>, OperationError> {
    let len = image.sections[text_idx].len;
    if len % 8 != 0 {
        return Err(refuse(
            ErrorKind::Malformed,
            format!(".text length {len} is not insn-aligned"),
        ));
    }
    let mut funcs = Vec::new();
    for (sym_idx, sym) in image.symbols.iter().enumerate() {
        charge(work, 1)?;
        if sym.shndx as usize != text_idx || sym.kind() != STT_FUNC {
            continue;
        }
        let name = sym.display();
        if sym.size == 0 {
            return Err(refuse(
                ErrorKind::Malformed,
                format!("function '{name}' has zero size"),
            ));
        }
        if sym.value % 8 != 0 || sym.size % 8 != 0 {
            return Err(refuse(
                ErrorKind::Malformed,
                format!("function '{name}' is not insn-aligned"),
            ));
        }
        let end = sym.value.checked_add(sym.size).ok_or_else(|| {
            refuse(
                ErrorKind::Malformed,
                format!("function '{name}' runs past .text"),
            )
        })?;
        if end > len {
            return Err(refuse(
                ErrorKind::Malformed,
                format!("function '{name}' runs past .text"),
            ));
        }
        retain(
            retained,
            limits,
            size_of::<Func>().saturating_add(name.len()),
        )?;
        funcs.push(Func {
            name,
            value: sym.value,
            size: sym.size,
            sym_idx,
        });
    }
    if funcs.is_empty() {
        return Err(refuse(
            ErrorKind::InvalidInput,
            "no function symbols in .text",
        ));
    }
    funcs.sort_by_key(|func| func.value);
    // Functions must tile `.text` exactly: no overlap, no gaps.
    let mut end = 0;
    for func in &funcs {
        if func.value != end {
            return Err(refuse(
                ErrorKind::Malformed,
                format!(
                    "function '{}' at {:#x} breaks .text tiling (want {end:#x})",
                    func.name, func.value,
                ),
            ));
        }
        end = func.value + func.size;
    }
    if end != len {
        return Err(refuse(
            ErrorKind::Malformed,
            format!(".text has unclaimed trailing bytes ({end:#x}..{len:#x})"),
        ));
    }
    Ok(funcs)
}

fn collect_relocs(
    image: &Image<'_>,
    work: &mut u64,
    retained: &mut usize,
    limits: &Limits,
) -> Result<Vec<Reloc>, OperationError> {
    let mut out = Vec::new();
    for section in &image.sections {
        if section.kind != SHT_REL {
            continue;
        }
        if section.info as usize >= image.sections.len() {
            return Err(refuse(
                ErrorKind::Malformed,
                format!(
                    "reloc section targets section {} (nonexistent)",
                    section.info
                ),
            ));
        }
        if section.entsize != 16 {
            return Err(refuse(ErrorKind::Malformed, "reloc entry size is not 16"));
        }
        let body = image.body(section)?;
        if body.len() % 16 != 0 {
            return Err(refuse(
                ErrorKind::Malformed,
                "reloc section length is not a multiple of 16",
            ));
        }
        let target = &image.sections[section.info as usize];
        let target_btf = matches!(target.name.as_deref(), Some(".BTF") | Some(".BTF.ext"));
        for entry in body.chunks_exact(16) {
            charge(work, 1)?;
            let offset = image.data.u64(&entry[0..8]);
            let info = image.data.u64(&entry[8..16]);
            let typ = (info & 0xffff_ffff) as u32;
            match typ {
                R_BPF_NONE | R_BPF_64_64 | R_BPF_64_ABS64 | R_BPF_64_ABS32 | R_BPF_64_32 => {}
                R_BPF_64_NODYLD32 => {
                    if !target_btf {
                        return Err(refuse(
                            ErrorKind::InvalidInput,
                            "nodyld relocation outside .BTF sections",
                        ));
                    }
                }
                _ => {
                    return Err(refuse(
                        ErrorKind::InvalidInput,
                        format!("unknown relocation type {typ}"),
                    ))
                }
            }
            if typ == R_BPF_NONE {
                continue;
            }
            retain(retained, limits, size_of::<Reloc>())?;
            out.push(Reloc {
                rel_sect: section.index,
                target_sect: section.info as usize,
                offset,
                sym_idx: (info >> 32) as usize,
                typ,
            });
        }
    }
    Ok(out)
}

/// Every static-edge-shaped call site must carry a covering call
/// relocation: a linked-style immediate call the reachability pass cannot
/// see would be misread as dead, changing program semantics. Helper
/// calls (src 0) carry no static edge; reserved forms refuse.
fn check_call_coverage(
    image: &Image<'_>,
    relocs: &[Reloc],
    work: &mut u64,
    retained: &mut usize,
    limits: &Limits,
) -> Result<(), OperationError> {
    // S09-round4: index once (charged per build step, admitted
    // per entry) so the coverage walk stays proportional to
    // instructions instead of calls-times-relocs — the repair
    // entry matches the guard scan's discipline (S65 retention
    // admission included).
    // S65-round5: sorted Vec with exactly pre-admitted geometry
    // (see the guard site): capacity for every reloc row is
    // admitted before allocation. Only R_BPF_64_32 rows are
    // pushed, so mixed inputs over-admit the non-call rows —
    // fail-closed, bounded by the input ceiling (each row decodes
    // from input bytes), and independent of Vec growth policy
    // (unlike per-push growth charges, which would bake in
    // std-internal doubling).
    let mut covered_offsets: Vec<(usize, u64)> = Vec::with_capacity(relocs.len());
    retain(
        retained,
        limits,
        relocs.len().saturating_mul(size_of::<(usize, u64)>()),
    )?;
    for reloc in relocs.iter().filter(|reloc| reloc.typ == R_BPF_64_32) {
        charge(work, 1)?;
        covered_offsets.push((reloc.target_sect, reloc.offset));
    }
    covered_offsets.sort_unstable();
    for section in &image.sections {
        if !section.executable() {
            continue;
        }
        let body = image.body(section)?;
        let mut slot = 0u64;
        let mut skip_next = false;
        while slot * 8 < section.len {
            charge(work, 1)?;
            let at = (slot * 8) as usize;
            slot += 1;
            if at + 8 > body.len() {
                return Err(refuse(ErrorKind::Malformed, "truncated instruction stream"));
            }
            if skip_next {
                skip_next = false;
                continue;
            }
            let code = body[at];
            if code == OP_LD_IMM64 {
                skip_next = true;
                continue;
            }
            if code != OP_CALL {
                continue;
            }
            let source = image.data.src_reg(body[at + 1]);
            if source != 0 && source != 1 {
                return Err(refuse(
                    ErrorKind::Unsupported,
                    format!("unknown call form at {}+{:#x}", section.label(), at),
                ));
            }
            if source == 0 {
                continue;
            }
            // S65-round5: membership on the sorted Vec index.
            if covered_offsets
                .binary_search(&(section.index, at as u64))
                .is_err()
            {
                return Err(refuse(
                    ErrorKind::Unsupported,
                    format!("unrelocated call site at {}+{at:#x}", section.label()),
                ));
            }
        }
    }
    Ok(())
}

/// Resolve one call reloc to the referenced symbol plus the destination
/// byte offset, using loader call semantics (aya-obj `relocation.rs`:
/// a call against a function symbol resolves to the symbol value; a
/// call against a section symbol resolves to the symbol value plus
/// `(imm + 1)` instruction slots). LLVM's unresolved `-1` therefore
/// means a zero addend in both forms. Any other symbol kind is refused:
/// pruning must agree with the loader, never guess a destination.
fn call_dest(
    image: &Image<'_>,
    target: &Section,
    reloc: &Reloc,
) -> Result<(usize, u64), OperationError> {
    let sym = image
        .symbols
        .get(reloc.sym_idx)
        .filter(|_| reloc.sym_idx != 0)
        .ok_or_else(|| refuse(ErrorKind::InvalidInput, "dangling relocation symbol"))?;
    let body = image.body(target)?;
    let end = reloc.offset.checked_add(8).ok_or_else(|| {
        refuse(
            ErrorKind::InvalidInput,
            format!("call reloc at {:#x} runs past its section", reloc.offset),
        )
    })?;
    if end > target.len {
        return Err(refuse(
            ErrorKind::InvalidInput,
            format!("call reloc at {:#x} runs past its section", reloc.offset),
        ));
    }
    let at = reloc.offset as usize;
    if body[at] != OP_CALL || image.data.src_reg(body[at + 1]) != 1 {
        return Err(refuse(
            ErrorKind::InvalidInput,
            format!("call reloc at {:#x} is not a call", reloc.offset),
        ));
    }
    let raw = image.data.u32(&body[at + 4..at + 8]) as i32;
    let base: i64 = sym
        .value
        .try_into()
        .map_err(|_| refuse(ErrorKind::InvalidInput, "call reloc target overflows"))?;
    let addend: i64 = match sym.kind() {
        STT_FUNC => 0,
        STT_SECTION => i64::from(raw)
            .checked_add(1)
            .and_then(|slots| slots.checked_mul(8))
            .ok_or_else(|| {
                refuse(
                    ErrorKind::InvalidInput,
                    format!("call reloc at {:#x} target overflows", reloc.offset),
                )
            })?,
        _ => {
            return Err(refuse(
                ErrorKind::Unsupported,
                format!(
                    "call reloc at {:#x} targets unsupported symbol kind {}",
                    reloc.offset,
                    sym.kind()
                ),
            ))
        }
    };
    let dest = base
        .checked_add(addend)
        .ok_or_else(|| refuse(ErrorKind::InvalidInput, "call reloc target overflows"))?;
    if dest < 0 {
        return Err(refuse(
            ErrorKind::InvalidInput,
            format!("call reloc target {dest} is negative"),
        ));
    }
    Ok((reloc.sym_idx, dest as u64))
}

/// Resolve one call reloc to a `.text` byte offset for the repair.
fn call_target(image: &Image<'_>, text_idx: usize, reloc: &Reloc) -> Result<u64, OperationError> {
    let (sym_idx, dest) = call_dest(image, &image.sections[reloc.target_sect], reloc)?;
    let sym = &image.symbols[sym_idx];
    if sym.shndx as usize != text_idx {
        return Err(refuse(
            ErrorKind::InvalidInput,
            format!("call reloc target outside .text: '{}'", sym.display()),
        ));
    }
    let text_len = image.sections[text_idx].len;
    if dest % 8 != 0 || dest >= text_len {
        return Err(refuse(
            ErrorKind::InvalidInput,
            format!("call reloc target {dest:#x} misaligned/short"),
        ));
    }
    Ok(dest)
}

/// Entry roots: call relocs in non-`.text` program sections.
fn entry_roots(
    image: &Image<'_>,
    text_idx: usize,
    relocs: &[Reloc],
    work: &mut u64,
) -> Result<Vec<u64>, OperationError> {
    let mut roots = Vec::new();
    for reloc in relocs {
        if reloc.typ != R_BPF_64_32 || reloc.target_sect == text_idx {
            continue;
        }
        charge(work, 1)?;
        roots.push(call_target(image, text_idx, reloc)?);
    }
    if roots.is_empty() {
        return Err(refuse(ErrorKind::InvalidInput, "no entry call into .text"));
    }
    Ok(roots)
}

fn func_at(funcs: &[Func], offset: u64) -> Option<usize> {
    funcs
        .iter()
        .position(|func| offset >= func.value && offset < func.value + func.size)
}

/// Functions reachable from the entry roots over call edges, keyed by
/// symbol index so the rewrite tests liveness without another lookup.
fn reachable(
    image: &Image<'_>,
    text_idx: usize,
    funcs: &[Func],
    relocs: &[Reloc],
    roots: &[u64],
    work: &mut u64,
) -> Result<Vec<bool>, OperationError> {
    let mut live = vec![false; image.symbols.len()];
    let mut stack = Vec::new();
    for root in roots {
        charge(work, 1)?;
        let Some(pos) = func_at(funcs, *root) else {
            return Err(refuse(
                ErrorKind::InvalidInput,
                format!("entry call targets {root:#x} (no function there)"),
            ));
        };
        if funcs[pos].value != *root {
            return Err(refuse(
                ErrorKind::InvalidInput,
                format!(
                    "entry call targets {root:#x} (inside '{}')",
                    funcs[pos].name
                ),
            ));
        }
        stack.push(pos);
    }
    while let Some(pos) = stack.pop() {
        if live[funcs[pos].sym_idx] {
            continue;
        }
        live[funcs[pos].sym_idx] = true;
        for reloc in relocs {
            if reloc.typ != R_BPF_64_32 || reloc.target_sect != text_idx {
                continue;
            }
            if func_at(funcs, reloc.offset) != Some(pos) {
                continue;
            }
            charge(work, 1)?;
            let dest = call_target(image, text_idx, reloc)?;
            let Some(next) = func_at(funcs, dest) else {
                return Err(refuse(
                    ErrorKind::InvalidInput,
                    format!("call targets {dest:#x} (no function there)"),
                ));
            };
            if funcs[next].value != dest {
                return Err(refuse(
                    ErrorKind::InvalidInput,
                    format!("call targets {dest:#x} (inside '{}')", funcs[next].name),
                ));
            }
            stack.push(next);
        }
    }
    Ok(live)
}

/// BTF gates: `.BTF.ext` carries section-relative `func_info` offsets the
/// strip would shift, and a `.BTF` body naming a removed function may
/// reference it by FUNC/FUNC_PROTO/DATASEC records this repair never
/// rewrites. Both refuse; a BTF body without the names cannot reference
/// them.
fn check_btf_gates(
    image: &Image<'_>,
    dead: &[&Func],
    work: &mut u64,
) -> Result<(), OperationError> {
    for section in &image.sections {
        match section.name.as_deref() {
            Some(".BTF.ext") => {
                return Err(refuse(
                    ErrorKind::Unsupported,
                    "BTF.ext present; func_info offset rewrite unsupported",
                ))
            }
            Some(".BTF") => {
                let body = image.body(section)?;
                charge(work, body.len() as u64)?;
                for func in dead {
                    if contains_name(body, &func.name) {
                        return Err(refuse(
                            ErrorKind::Unsupported,
                            format!(
                                "BTF names removed function '{}'; btf rewrite unsupported",
                                func.name
                            ),
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Kept ranges in address order; new offsets pack from zero.
/// Returns the ranges plus the packed `.text` length.
fn plan_kept(funcs: &[Func], live: &[bool]) -> (Vec<(u64, u64, u64)>, u64) {
    let mut kept = Vec::new();
    let mut cursor = 0;
    for func in funcs {
        if live[func.sym_idx] {
            kept.push((func.value, func.value + func.size, cursor));
            cursor += func.size;
        }
    }
    (kept, cursor)
}

/// New `.text` offset for an old one; `None` when the byte is dropped.
fn remap(kept: &[(u64, u64, u64)], old: u64) -> Option<u64> {
    for (start, end, new) in kept {
        if old >= *start && old < *end {
            return Some(new + (old - start));
        }
    }
    None
}

/// Entry calls carry a raw byte addend against the `.text` section
/// symbol, so a shifted root would silently retarget: refuse loudly.
/// Intra-text calls through function symbols resolve via values
/// rewritten below and therefore survive any shift; intra-text calls
/// through a SECTION symbol carry the same raw immediate, which no
/// rewrite pass touches (R01), so a shifted section destination
/// refuses wherever its site lives.
fn check_entry_calls(
    image: &Image<'_>,
    text_idx: usize,
    funcs: &[Func],
    relocs: &[Reloc],
    kept: &[(u64, u64, u64)],
    work: &mut u64,
) -> Result<(), OperationError> {
    for reloc in relocs {
        if reloc.typ != R_BPF_64_32 {
            continue;
        }
        charge(work, 1)?;
        let dest = call_target(image, text_idx, reloc)?;
        let Some(new) = remap(kept, dest) else {
            let owner = funcs
                .iter()
                .find(|func| dest >= func.value && dest < func.value + func.size);
            match owner {
                Some(func) => {
                    return Err(refuse(
                        ErrorKind::InvalidInput,
                        format!("call to stripped function '{}'", func.name),
                    ))
                }
                None => {
                    return Err(refuse(
                        ErrorKind::InvalidInput,
                        format!("call targets {dest:#x} (no function there)"),
                    ))
                }
            }
        };
        // R01: a shifted destination is only safe when a rewritten
        // function-symbol value carries it. Entry sites refuse on any
        // shift (F01, unchanged); intra-text sites refuse when the call
        // resolves through a section symbol, whose raw immediate no
        // rewrite pass updates.
        let section_call = image
            .symbols
            .get(reloc.sym_idx)
            .is_some_and(|sym| sym.kind() == STT_SECTION);
        if new != dest && (reloc.target_sect != text_idx || section_call) {
            let edge = if reloc.target_sect != text_idx {
                "entry call"
            } else {
                "section-symbol call"
            };
            return Err(refuse(
                ErrorKind::InvalidInput,
                format!("{edge} target {dest:#x} shifted to {new:#x}"),
            ));
        }
    }
    Ok(())
}

/// S02: data references (wide loads, absolute fixups) against the
/// `.text` section symbol carry a raw addend no rewrite pass touches:
/// `rewrite_relocs` remaps the site and the symbol index only. After
/// compaction the stale addend silently retargets (a moved callback
/// still in bounds selects the wrong function), so a stripped or
/// shifted section-symbol data reference refuses, mirroring R01's
/// rule for section-symbol calls. Function-symbol references ride
/// the rewritten values; references into unmoved sections are safe.
fn check_data_refs(
    image: &Image<'_>,
    text_idx: usize,
    relocs: &[Reloc],
    kept: &[(u64, u64, u64)],
    work: &mut u64,
) -> Result<(), OperationError> {
    for reloc in relocs {
        if reloc.typ == R_BPF_64_32 {
            continue;
        }
        charge(work, 1)?;
        let Some(sym) = image.symbols.get(reloc.sym_idx) else {
            continue;
        };
        if sym.kind() != STT_SECTION || sym.shndx as usize != text_idx {
            continue;
        }
        let target = image
            .sections
            .get(reloc.target_sect)
            .ok_or_else(|| refuse(ErrorKind::InvalidInput, "data reloc outside sections"))?;
        let body = image.body(target)?;
        let site = reloc.offset as usize;
        let end = site
            .checked_add(8)
            .ok_or_else(|| refuse(ErrorKind::InvalidInput, "data reloc site overflows"))?;
        let addend = match reloc.typ {
            R_BPF_64_64 if target.executable() => {
                let slot = body.get(site..end).ok_or_else(|| {
                    refuse(ErrorKind::InvalidInput, "data reloc site outside section")
                })?;
                if slot[0] != OP_LD_IMM64 {
                    return Err(refuse(
                        ErrorKind::InvalidInput,
                        "section-symbol address fixup is not a wide load",
                    ));
                }
                u64::from(image.data.u32(&slot[4..8]))
            }
            R_BPF_64_64 | R_BPF_64_ABS64 => {
                let slot = body.get(site..end).ok_or_else(|| {
                    refuse(ErrorKind::InvalidInput, "data reloc site outside section")
                })?;
                image.data.u64(slot)
            }
            R_BPF_64_ABS32 => {
                let quad = site
                    .checked_add(4)
                    .ok_or_else(|| refuse(ErrorKind::InvalidInput, "data reloc site overflows"))?;
                let slot = body.get(site..quad).ok_or_else(|| {
                    refuse(ErrorKind::InvalidInput, "data reloc site outside section")
                })?;
                u64::from(image.data.u32(slot))
            }
            _ => continue,
        };
        let dest = sym.value.checked_add(addend).ok_or_else(|| {
            refuse(
                ErrorKind::InvalidInput,
                "section-symbol data reference overflows",
            )
        })?;
        let Some(new) = remap(kept, dest) else {
            return Err(refuse(
                ErrorKind::InvalidInput,
                format!("section-symbol data reference {dest:#x} dangles over stripped code"),
            ));
        };
        if new != dest {
            return Err(refuse(
                ErrorKind::InvalidInput,
                format!("section-symbol data reference {dest:#x} shifted to {new:#x}"),
            ));
        }
    }
    Ok(())
}

/// Compact `.text` in ascending order (ranges only move down) and zero
/// the slack so no stale bytes survive past the new end.
fn compact_text(
    image: &Image<'_>,
    text_idx: usize,
    kept: &[(u64, u64, u64)],
    cursor: u64,
    out: &mut [u8],
    work: &mut u64,
) -> Result<(), OperationError> {
    let section = &image.sections[text_idx];
    let text_off = section.off as usize;
    let text_old = section.len as usize;
    if text_off
        .checked_add(text_old)
        .is_none_or(|end| end > image.bytes.len())
    {
        return Err(refuse(ErrorKind::Malformed, ".text outside file"));
    }
    for (start, end, new) in kept {
        charge(work, 1)?;
        out.copy_within(
            text_off + *start as usize..text_off + *end as usize,
            text_off + *new as usize,
        );
    }
    out[text_off + cursor as usize..text_off + text_old].fill(0);
    write_shdr_u64(image, out, text_idx, 32, cursor)?;
    Ok(())
}

fn section_header_offset(image: &Image<'_>) -> Result<usize, OperationError> {
    let shoff = image.data.u64(&image.bytes[0x28..0x30]) as usize;
    shoff
        .checked_add(image.sections.len() * 64)
        .filter(|end| *end <= image.bytes.len())
        .map(|_| shoff)
        .ok_or_else(|| refuse(ErrorKind::Malformed, "truncated section table"))
}

fn write_shdr_u64(
    image: &Image<'_>,
    out: &mut [u8],
    idx: usize,
    field: usize,
    value: u64,
) -> Result<(), OperationError> {
    let shoff = section_header_offset(image)?;
    let at = shoff + idx * 64 + field;
    out.get_mut(at..at + 8)
        .ok_or_else(|| refuse(ErrorKind::Malformed, "section header outside file"))?
        .copy_from_slice(&image.data.encode_u64(value));
    Ok(())
}

fn write_shdr_u32(
    image: &Image<'_>,
    out: &mut [u8],
    idx: usize,
    field: usize,
    value: u32,
) -> Result<(), OperationError> {
    let shoff = section_header_offset(image)?;
    let at = shoff + idx * 64 + field;
    out.get_mut(at..at + 4)
        .ok_or_else(|| refuse(ErrorKind::Malformed, "section header outside file"))?
        .copy_from_slice(&image.data.encode_u32(value));
    Ok(())
}

/// Rewrite kept function values, then compact the symtab. Returns the
/// old-to-new symbol map for the reloc phase. The first-global boundary
/// is recomputed over kept globals (the donor reads the uncompacted
/// index here, which agrees only when no local shifts).
fn rewrite_symtab(
    image: &Image<'_>,
    symtab_idx: usize,
    funcs: &[Func],
    live: &[bool],
    kept: &[(u64, u64, u64)],
    out: &mut [u8],
    work: &mut u64,
) -> Result<Vec<Option<usize>>, OperationError> {
    let symtab = &image.sections[symtab_idx];
    let sym_off = symtab.off as usize;
    let sym_len = symtab.len as usize;
    if sym_off
        .checked_add(sym_len)
        .is_none_or(|end| end > image.bytes.len())
    {
        return Err(refuse(ErrorKind::Malformed, "symtab outside file"));
    }
    for func in funcs {
        if live[func.sym_idx] {
            charge(work, 1)?;
            let new = remap(kept, func.value).ok_or_else(|| {
                refuse(
                    ErrorKind::InvalidInput,
                    format!("live function '{}' has no remap", func.name),
                )
            })?;
            let at = sym_off + func.sym_idx * 24 + 8;
            out.get_mut(at..at + 8)
                .ok_or_else(|| refuse(ErrorKind::Malformed, "symtab outside file"))?
                .copy_from_slice(&image.data.encode_u64(new));
        }
    }
    let sym_count = image.symbols.len();
    let dead_sym: Vec<bool> = (0..sym_count)
        .map(|index| {
            funcs
                .iter()
                .any(|func| func.sym_idx == index && !live[func.sym_idx])
        })
        .collect();
    let mut map: Vec<Option<usize>> = vec![None; sym_count];
    let mut next = 0;
    for old in 0..sym_count {
        if !dead_sym[old] {
            if next != old {
                out.copy_within(
                    sym_off + old * 24..sym_off + old * 24 + 24,
                    sym_off + next * 24,
                );
            }
            map[old] = Some(next);
            next += 1;
        }
    }
    write_shdr_u64(image, out, symtab_idx, 32, (next * 24) as u64)?;
    let mut first_global = next;
    for (old, new) in map.iter().enumerate() {
        if let Some(new) = new {
            if image.symbols[old].bind() != 0 {
                first_global = first_global.min(*new);
            }
        }
    }
    write_shdr_u32(image, out, symtab_idx, 44, first_global as u32)?;
    Ok(map)
}

/// Decide every reloc entry: kept (with new symbol and offset) or dropped
/// with its dead function. Map fixups patch an 8-byte `ld_imm64` pair, so
/// both halves must survive inside kept code. Sections that lose every
/// entry shrink to zero. A call site in dead code is always dropped: its
/// caller cannot be live, because kept ranges tile the live functions
/// exactly and `check_entry_calls` already refused dead-to-dead edges.
fn rewrite_relocs(
    image: &Image<'_>,
    text_idx: usize,
    relocs: &[Reloc],
    kept: &[(u64, u64, u64)],
    map: &[Option<usize>],
    out: &mut [u8],
    work: &mut u64,
) -> Result<(), OperationError> {
    struct KeptEntry {
        rel_sect: usize,
        offset: u64,
        sym: usize,
        typ: u32,
    }
    let mut kept_entries: Vec<KeptEntry> = Vec::with_capacity(relocs.len());
    for reloc in relocs {
        charge(work, 1)?;
        let mut drop = false;
        let mut offset = reloc.offset;
        if reloc.target_sect == text_idx {
            match remap(kept, offset) {
                Some(new) => {
                    if reloc.typ != R_BPF_64_32 {
                        let pair_end = offset.checked_add(8).ok_or_else(|| {
                            refuse(ErrorKind::InvalidInput, "reloc pair offset overflows")
                        })?;
                        if remap(kept, pair_end) != Some(new + 8) {
                            return Err(refuse(
                                ErrorKind::InvalidInput,
                                format!("reloc pair straddles stripped code at {offset:#x}"),
                            ));
                        }
                    }
                    offset = new;
                }
                None => {
                    drop = true;
                }
            }
        }
        if drop {
            continue;
        }
        let new_sym = map.get(reloc.sym_idx).copied().flatten().ok_or_else(|| {
            let name = image
                .symbols
                .get(reloc.sym_idx)
                .map(|sym| sym.display())
                .unwrap_or_else(|| "?".to_owned());
            refuse(
                ErrorKind::InvalidInput,
                format!("reloc references removed symbol '{name}'"),
            )
        })?;
        kept_entries.push(KeptEntry {
            rel_sect: reloc.rel_sect,
            offset,
            sym: new_sym,
            typ: reloc.typ,
        });
    }
    let mut sections: Vec<usize> = kept_entries.iter().map(|entry| entry.rel_sect).collect();
    sections.sort_unstable();
    sections.dedup();
    for rel_sect in sections {
        charge(work, 1)?;
        let section = &image.sections[rel_sect];
        let rel_off = section.off as usize;
        let rel_len = section.len as usize;
        if rel_off
            .checked_add(rel_len)
            .is_none_or(|end| end > image.bytes.len())
        {
            return Err(refuse(ErrorKind::Malformed, "reloc section outside file"));
        }
        let mut at = rel_off;
        let mut count = 0;
        for entry in kept_entries
            .iter()
            .filter(|entry| entry.rel_sect == rel_sect)
        {
            let info = ((entry.sym as u64) << 32) | u64::from(entry.typ);
            out.get_mut(at..at + 8)
                .ok_or_else(|| refuse(ErrorKind::Malformed, "reloc section outside file"))?
                .copy_from_slice(&image.data.encode_u64(entry.offset));
            out.get_mut(at + 8..at + 16)
                .ok_or_else(|| refuse(ErrorKind::Malformed, "reloc section outside file"))?
                .copy_from_slice(&image.data.encode_u64(info));
            at += 16;
            count += 1;
        }
        write_shdr_u64(image, out, rel_sect, 32, count * 16)?;
    }
    for reloc in relocs {
        if !kept_entries
            .iter()
            .any(|entry| entry.rel_sect == reloc.rel_sect)
        {
            write_shdr_u64(image, out, reloc.rel_sect, 32, 0)?;
        }
    }
    Ok(())
}

/// Structural re-check of the rewritten object.
fn verify(
    out: &[u8],
    contract: &ObjectContract,
    limits: &Limits,
    report: &PruneReport,
) -> Result<(), OperationError> {
    let mut work = limits.work_steps;
    let (image, mut retained) = decode(out, contract, limits, &mut work)?;
    let text_idx = image.find_text()?;
    if image.sections[text_idx].len != report.text_after {
        return Err(refuse(
            ErrorKind::InvalidInput,
            "verify: .text length mismatch",
        ));
    }
    for sym in &image.symbols {
        if sym.kind() != STT_FUNC {
            continue;
        }
        if let Some(name) = &sym.name {
            if report.removed.iter().any(|removed| removed == name) {
                return Err(refuse(
                    ErrorKind::InvalidInput,
                    format!("verify: '{name}' was not removed"),
                ));
            }
        }
    }
    let relocs = collect_relocs(&image, &mut work, &mut retained, limits)?;
    for reloc in &relocs {
        if reloc.sym_idx >= image.symbols.len() {
            return Err(refuse(
                ErrorKind::InvalidInput,
                "verify: reloc symbol out of range",
            ));
        }
        let target = &image.sections[reloc.target_sect];
        if reloc.offset >= target.len {
            return Err(refuse(
                ErrorKind::InvalidInput,
                "verify: reloc offset out of range",
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Verifier-sensitive rule checker
// ---------------------------------------------------------------------------

/// Check one final object against admitted rule manifests.
///
/// Structural truncation, target contradiction and budget exhaustion
/// refuse typed; every evaluated semantic finding returns as a
/// [`RuleViolation`] with a stable rule id. BTF-backed rules report a
/// `*.btf-missing` finding when no view is supplied: an unevaluated rule
/// is never a silent pass.
pub fn check_verifier_rules(
    bytes: &[u8],
    contract: &ObjectContract,
    manifests: &[VerifierRules],
    btf: Option<&BtfView>,
    limits: &Limits,
) -> Result<Vec<RuleViolation>, OperationError> {
    let mut work = limits.work_steps;
    let (image, mut retained) = decode(bytes, contract, limits, &mut work)?;
    let relocs = collect_relocs(&image, &mut work, &mut retained, limits)?;
    let mut violations = Vec::new();
    for manifest in manifests {
        for rule in &manifest.rules {
            charge(&mut work, 1)?;
            match rule {
                Rule::PadNamed {
                    ty,
                    member,
                    offset,
                    size,
                    struct_size,
                } => check_pad(
                    &mut violations,
                    &mut retained,
                    limits,
                    btf,
                    ty,
                    member,
                    *offset,
                    *size,
                    *struct_size,
                )?,
                Rule::LinkageGlobal { symbol, section } => {
                    check_linkage(
                        &image,
                        &mut violations,
                        &mut retained,
                        limits,
                        btf,
                        symbol,
                        section,
                    )?;
                }
                Rule::FrameMinimum {
                    min_frame_bytes,
                    max_total_bytes,
                } => check_frames(
                    &image,
                    &mut violations,
                    &mut retained,
                    limits,
                    *min_frame_bytes,
                    *max_total_bytes,
                    &mut work,
                )?,
                Rule::MaxParams {
                    function,
                    max_params,
                } => {
                    check_arity(
                        &mut violations,
                        &mut retained,
                        limits,
                        btf,
                        function,
                        *max_params,
                    )?;
                }
                Rule::Bundled { function, pointers } => {
                    check_bundled(
                        &mut violations,
                        &mut retained,
                        limits,
                        btf,
                        function,
                        pointers,
                    )?;
                }
                Rule::PathGuard { path, forbidden } => {
                    check_path_guard(
                        &image,
                        &relocs,
                        &mut violations,
                        &mut retained,
                        limits,
                        path,
                        forbidden,
                        &mut work,
                    )?;
                }
                Rule::OptOut {
                    sections,
                    arrays,
                    opt_out_index,
                    continuations,
                    multi_loaded,
                    pair,
                    pair_array,
                    plain_array,
                    multi_array,
                } => check_opt_out(
                    &image,
                    &relocs,
                    &mut violations,
                    &mut retained,
                    limits,
                    sections,
                    arrays,
                    *opt_out_index,
                    continuations,
                    multi_loaded,
                    pair.as_deref(),
                    pair_array,
                    plain_array,
                    multi_array,
                    &mut work,
                )?,
            }
        }
    }
    Ok(violations)
}

fn btf_or_missing(
    violations: &mut Vec<RuleViolation>,
    retained: &mut usize,
    limits: &Limits,
    btf: Option<&BtfView>,
    rule: &'static str,
) -> Result<Option<()>, OperationError> {
    if btf.is_none() {
        push_finding(violations, retained, limits, rule, None, None)?;
        return Ok(None);
    }
    Ok(Some(()))
}

#[allow(clippy::too_many_arguments)]
fn check_pad(
    violations: &mut Vec<RuleViolation>,
    retained: &mut usize,
    limits: &Limits,
    btf: Option<&BtfView>,
    ty: &str,
    member: &str,
    offset: u64,
    size: u64,
    struct_size: u64,
) -> Result<(), OperationError> {
    let Some(()) = btf_or_missing(violations, retained, limits, btf, "padding.btf-missing")? else {
        return Ok(());
    };
    let view = btf.expect("checked present");
    let candidates = view.types_named(ty).map_err(|error| {
        if error.kind() == ErrorKind::LimitExceeded {
            error
        } else {
            refuse(ErrorKind::InvalidInput, "padding query failed")
        }
    })?;
    let mut composite = None;
    let mut ambiguous = false;
    for candidate in candidates {
        let resolved = view.canonical(candidate);
        let Ok(canonical) = resolved else {
            if matches!(resolved, Err(ref error) if error.kind() == ErrorKind::LimitExceeded) {
                return Err(resolved.unwrap_err());
            }
            continue;
        };
        let shaped = view.shape(canonical);
        let Ok(shape) = shaped else {
            if matches!(shaped, Err(ref error) if error.kind() == ErrorKind::LimitExceeded) {
                return Err(shaped.unwrap_err());
            }
            continue;
        };
        match shape.kind {
            TypeKind::Struct | TypeKind::Union => {
                if composite.replace((canonical, shape.size_bytes)).is_some() {
                    ambiguous = true;
                    break;
                }
            }
            _ => continue,
        }
    }
    if ambiguous {
        push_finding(
            violations,
            retained,
            limits,
            "padding.type-ambiguous",
            None,
            None,
        )?;
        return Ok(());
    }
    let Some((parent, actual_size)) = composite else {
        push_finding(
            violations,
            retained,
            limits,
            "padding.type-missing",
            None,
            None,
        )?;
        return Ok(());
    };
    if actual_size != Some(struct_size) {
        push_finding(
            violations,
            retained,
            limits,
            "padding.named-pad-required",
            None,
            None,
        )?;
        return Ok(());
    }
    match view.member(parent, &[member]) {
        Ok(extent) => {
            if extent.byte_offset != offset
                || extent.bit_offset != 0
                || extent.bit_width.is_some()
                || extent.size_bytes != size
            {
                push_finding(
                    violations,
                    retained,
                    limits,
                    "padding.named-pad-required",
                    None,
                    None,
                )?;
            }
        }
        Err(error) if error.kind() == ErrorKind::LimitExceeded => return Err(error),
        Err(_) => {
            push_finding(
                violations,
                retained,
                limits,
                "padding.named-pad-required",
                None,
                None,
            )?;
        }
    }
    Ok(())
}

/// Shared unique-FUNC resolution behind the linkage and call rules.
enum FuncResolution {
    Missing,
    Ambiguous,
    BadProto,
    NotFunction,
    Resolved(scopebase_bpf::btf::FunctionShape),
}

fn resolve_function(btf: &BtfView, name: &str) -> Result<FuncResolution, OperationError> {
    let candidates = btf.types_named(name).map_err(|error| {
        if error.kind() == ErrorKind::LimitExceeded {
            error
        } else {
            refuse(ErrorKind::InvalidInput, "function query failed")
        }
    })?;
    if candidates.is_empty() {
        return Ok(FuncResolution::Missing);
    }
    let mut resolved = None;
    let mut ambiguous = false;
    let mut bad_proto = false;
    for candidate in candidates {
        match btf.function(candidate) {
            Ok(shape) => {
                if resolved.replace(shape).is_some() {
                    ambiguous = true;
                    break;
                }
            }
            Err(error) if error.kind() == ErrorKind::Incompatible => continue,
            Err(error) if error.kind() == ErrorKind::LimitExceeded => return Err(error),
            Err(_) => {
                bad_proto = true;
            }
        }
    }
    if ambiguous {
        Ok(FuncResolution::Ambiguous)
    } else if let Some(shape) = resolved {
        Ok(FuncResolution::Resolved(shape))
    } else if bad_proto {
        Ok(FuncResolution::BadProto)
    } else {
        Ok(FuncResolution::NotFunction)
    }
}

fn check_linkage(
    image: &Image<'_>,
    violations: &mut Vec<RuleViolation>,
    retained: &mut usize,
    limits: &Limits,
    btf: Option<&BtfView>,
    symbol: &str,
    section: &str,
) -> Result<(), OperationError> {
    let section_idx = image
        .sections
        .iter()
        .position(|candidate| candidate.name.as_deref() == Some(section));
    let mut matches = 0;
    let mut exact = false;
    if let Some(index) = section_idx {
        for sym in &image.symbols {
            if sym.name.as_deref() != Some(symbol) || sym.shndx as usize != index {
                continue;
            }
            matches += 1;
            if sym.info == ST_INFO_GLOBAL_FUNC && sym.other == 0 && sym.size > 0 {
                exact = true;
            }
        }
    }
    if matches != 1 || !exact {
        push_finding(
            violations,
            retained,
            limits,
            "linkage.global-required",
            Some(section),
            None,
        )?;
        return Ok(());
    }
    let Some(()) = btf_or_missing(violations, retained, limits, btf, "linkage.btf-missing")? else {
        return Ok(());
    };
    match resolve_function(btf.expect("checked present"), symbol)? {
        FuncResolution::Resolved(shape) => {
            // F21: GLOBAL is required in BTF as well as in the symbol
            // table; a STATIC or EXTERN twin must fail this rule.
            if shape.linkage != Some(scopebase_bpf::btf::FuncLinkage::Global) {
                push_finding(
                    violations,
                    retained,
                    limits,
                    "linkage.btf-not-global",
                    None,
                    None,
                )?;
            }
        }
        FuncResolution::Missing => {
            push_finding(
                violations,
                retained,
                limits,
                "linkage.btf-missing",
                None,
                None,
            )?;
        }
        FuncResolution::Ambiguous => {
            push_finding(
                violations,
                retained,
                limits,
                "linkage.btf-ambiguous",
                None,
                None,
            )?;
        }
        FuncResolution::BadProto => {
            push_finding(
                violations,
                retained,
                limits,
                "linkage.btf-bad-prototype",
                None,
                None,
            )?;
        }
        FuncResolution::NotFunction => {
            push_finding(
                violations,
                retained,
                limits,
                "linkage.btf-not-function",
                None,
                None,
            )?;
        }
    }
    Ok(())
}

fn check_frames(
    image: &Image<'_>,
    violations: &mut Vec<RuleViolation>,
    retained: &mut usize,
    limits: &Limits,
    min_frame_bytes: u64,
    max_total_bytes: u64,
    work: &mut u64,
) -> Result<(), OperationError> {
    let mut frames = 0u64;
    for sym in &image.symbols {
        charge(work, 1)?;
        if sym.kind() != STT_FUNC || sym.size == 0 {
            continue;
        }
        let Some(section) = image.sections.get(sym.shndx as usize) else {
            continue;
        };
        if section.executable() {
            frames += 1;
        }
    }
    let total = frames
        .checked_mul(min_frame_bytes)
        .ok_or_else(|| refuse(ErrorKind::Overflow, "frame budget overflows"))?;
    if total > max_total_bytes {
        push_finding(
            violations,
            retained,
            limits,
            "stack.per-frame-minimum",
            None,
            None,
        )?;
    }
    Ok(())
}

fn check_arity(
    violations: &mut Vec<RuleViolation>,
    retained: &mut usize,
    limits: &Limits,
    btf: Option<&BtfView>,
    function: &str,
    max_params: u64,
) -> Result<(), OperationError> {
    let Some(()) = btf_or_missing(violations, retained, limits, btf, "call.btf-missing")? else {
        return Ok(());
    };
    match resolve_function(btf.expect("checked present"), function)? {
        FuncResolution::Resolved(shape) => {
            if shape.parameters.len() as u64 > max_params || shape.variadic {
                push_finding(
                    violations,
                    retained,
                    limits,
                    "call.arity-exceeded",
                    None,
                    None,
                )?;
            }
        }
        FuncResolution::Missing => {
            push_finding(
                violations,
                retained,
                limits,
                "call.function-missing",
                None,
                None,
            )?;
        }
        FuncResolution::Ambiguous => {
            push_finding(
                violations,
                retained,
                limits,
                "call.func-ambiguous",
                None,
                None,
            )?;
        }
        FuncResolution::BadProto => {
            push_finding(
                violations,
                retained,
                limits,
                "call.bad-prototype",
                None,
                None,
            )?;
        }
        FuncResolution::NotFunction => {
            push_finding(
                violations,
                retained,
                limits,
                "call.not-function",
                None,
                None,
            )?;
        }
    }
    Ok(())
}

fn check_bundled(
    violations: &mut Vec<RuleViolation>,
    retained: &mut usize,
    limits: &Limits,
    btf: Option<&BtfView>,
    function: &str,
    pointers: &[bool],
) -> Result<(), OperationError> {
    let Some(()) = btf_or_missing(violations, retained, limits, btf, "call.btf-missing")? else {
        return Ok(());
    };
    let view = btf.expect("checked present");
    let shape = match resolve_function(view, function)? {
        FuncResolution::Resolved(shape) => shape,
        FuncResolution::Missing => {
            push_finding(
                violations,
                retained,
                limits,
                "call.function-missing",
                None,
                None,
            )?;
            return Ok(());
        }
        FuncResolution::Ambiguous => {
            push_finding(
                violations,
                retained,
                limits,
                "call.func-ambiguous",
                None,
                None,
            )?;
            return Ok(());
        }
        FuncResolution::BadProto => {
            push_finding(
                violations,
                retained,
                limits,
                "call.bad-prototype",
                None,
                None,
            )?;
            return Ok(());
        }
        FuncResolution::NotFunction => {
            push_finding(
                violations,
                retained,
                limits,
                "call.not-function",
                None,
                None,
            )?;
            return Ok(());
        }
    };
    if shape.variadic || shape.parameters.len() != pointers.len() {
        push_finding(
            violations,
            retained,
            limits,
            "call.bundle-mismatch",
            None,
            None,
        )?;
        return Ok(());
    }
    for (param, want_pointer) in shape.parameters.iter().zip(pointers) {
        let canonical = match view.canonical(*param) {
            Ok(resolved) => resolved,
            Err(error) if error.kind() == ErrorKind::LimitExceeded => return Err(error),
            Err(_) => {
                push_finding(
                    violations,
                    retained,
                    limits,
                    "call.bundle-mismatch",
                    None,
                    None,
                )?;
                return Ok(());
            }
        };
        let shaped = match view.shape(canonical) {
            Ok(shape) => shape,
            Err(error) if error.kind() == ErrorKind::LimitExceeded => return Err(error),
            Err(_) => {
                push_finding(
                    violations,
                    retained,
                    limits,
                    "call.bundle-mismatch",
                    None,
                    None,
                )?;
                return Ok(());
            }
        };
        if matches!(shaped.kind, TypeKind::Pointer { .. }) != *want_pointer {
            push_finding(
                violations,
                retained,
                limits,
                "call.bundle-mismatch",
                None,
                None,
            )?;
            return Ok(());
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn check_path_guard(
    image: &Image<'_>,
    relocs: &[Reloc],
    violations: &mut Vec<RuleViolation>,
    retained: &mut usize,
    limits: &Limits,
    path: &str,
    forbidden: &str,
    work: &mut u64,
) -> Result<(), OperationError> {
    // R09: index call relocs by site section once, so per-function
    // scans cover only the section's own relocs. S09: every
    // inspected row is charged below, so the walk is bounded by the
    // work ceiling rather than linear by construction.
    let mut by_sect: std::collections::BTreeMap<usize, Vec<&Reloc>> =
        std::collections::BTreeMap::new();
    for reloc in relocs {
        if reloc.typ != R_BPF_64_32 {
            continue;
        }
        charge(work, 1)?;
        retain(retained, limits, size_of::<&Reloc>())?;
        by_sect.entry(reloc.target_sect).or_default().push(reloc);
    }
    // R09: bounded reachable-function traversal from every root named
    // `path`. The visited set (section, value) terminates cycles and
    // shares work across same-named roots; findings carry no root, so
    // sharing loses nothing. Unreachable functions are never visited:
    // the guard stays scoped, never object-wide.
    let mut visited: std::collections::BTreeSet<(usize, u64)> = std::collections::BTreeSet::new();
    let mut stack: Vec<(usize, u64, u64)> = Vec::new();
    let mut found = false;
    for sym in &image.symbols {
        // S09: charge every root candidate inspected.
        charge(work, 1)?;
        if sym.name.as_deref() != Some(path) || sym.kind() != STT_FUNC {
            continue;
        }
        let Some(section) = image.sections.get(sym.shndx as usize) else {
            continue;
        };
        if !section.executable() {
            continue;
        }
        // S08: a zero-size path root has an unknown extent — legal
        // in ELF, unprovable for the guard — so that is a finding,
        // not a silent skip. The path EXISTS, so it still counts
        // as found; only its body is unprovable.
        if sym.size == 0 {
            found = true;
            push_section_finding(
                violations,
                retained,
                limits,
                "init.unresolved-extent",
                section,
                Some(sym.value),
            )?;
            continue;
        }
        found = true;
        stack.push((section.index, sym.value, sym.size));
    }
    if !found {
        push_finding(
            violations,
            retained,
            limits,
            "init.path-missing",
            None,
            None,
        )?;
        return Ok(());
    }
    let empty: Vec<&Reloc> = Vec::new();
    while let Some((sect_idx, value, size)) = stack.pop() {
        if !visited.insert((sect_idx, value)) {
            continue;
        }
        charge(work, 1)?;
        let Some(section) = image.sections.get(sect_idx) else {
            continue;
        };
        if !section.executable() {
            continue;
        }
        // S08: validate the popped extent BEFORE scanning. A root
        // whose extent runs past its section clamps to a short or
        // empty scan under a plain `min`, silently "proving" bodies
        // it never read. (Followed callees are validated at push
        // time, so a popped-invalid extent is necessarily a root.)
        // The subtraction cannot underflow: `value >= section.len`
        // short-circuits first.
        if value >= section.len || size > section.len - value {
            push_section_finding(
                violations,
                retained,
                limits,
                "init.unresolved-extent",
                section,
                Some(value),
            )?;
            continue;
        }
        let end = value.saturating_add(size);
        let site_relocs: &[&Reloc] = by_sect.get(&sect_idx).map(Vec::as_slice).unwrap_or(&empty);
        // S09: index once (charged per entry) so the coverage
        // check below is O(log n) per call site. The old per-call
        // linear scan was uncharged O(N) per call — quadratic in
        // one function with many relocated calls.
        // S65-round5: the index is a sorted Vec with exactly
        // pre-admitted geometry: `site_relocs.len()` entries of
        // `u64` are admitted BEFORE `with_capacity` allocates
        // them. A BTreeSet's boxed nodes and spare slots have no
        // such bound (B=6, CAPACITY=11, node metadata), so
        // per-key charges under-admitted the authorized
        // allocation.
        let mut reloc_offsets = Vec::with_capacity(site_relocs.len());
        retain(
            retained,
            limits,
            site_relocs.len().saturating_mul(size_of::<u64>()),
        )?;
        for reloc in site_relocs.iter() {
            charge(work, 1)?;
            reloc_offsets.push(reloc.offset);
        }
        reloc_offsets.sort_unstable();
        for reloc in site_relocs {
            // S09: charge every inspected row, in or out of range:
            // the per-function filter scans the section's relocs.
            charge(work, 1)?;
            if reloc.offset < value || reloc.offset >= end {
                continue;
            }
            let target = &image.sections[reloc.target_sect];
            let (callee, dest) = call_dest(image, target, reloc)?;
            let target_sym = &image.symbols[callee];
            // F23: match by resolved destination, not by reloc spelling,
            // so a section-symbol call landing in `forbidden` (or inside
            // it) is the same guarded edge as a direct call.
            // S09: the destination match scans the symbol table per
            // edge; every inspected candidate is charged.
            let mut hits = false;
            for cand in &image.symbols {
                charge(work, 1)?;
                if cand.kind() == STT_FUNC
                    && cand.shndx == target_sym.shndx
                    && cand.name.as_deref() == Some(forbidden)
                    && (cand.value == dest
                        || (cand.size > 0
                            && dest > cand.value
                            && dest < cand.value.saturating_add(cand.size)))
                {
                    hits = true;
                    break;
                }
            }
            if hits {
                push_section_finding(
                    violations,
                    retained,
                    limits,
                    "init.path-guard",
                    section,
                    Some(reloc.offset),
                )?;
            }
            // R09: follow the edge into its containing function, in the
            // callee symbol's own section (cross-section calls included).
            // Interior destinations enqueue their container; padding with
            // no function is a dead end, not a new finding.
            // S09: charged per inspected candidate like the match above.
            // S08: a callee whose extent is unknown (zero-size FUNC) or
            // invalid (past its section) is a finding — the guard cannot
            // prove the subtree avoids `forbidden` — never a silent stop.
            // A usable aliased extent still wins over an unusable one.
            let mut usable: Option<&Symbol> = None;
            let mut unusable = false;
            for cand in &image.symbols {
                charge(work, 1)?;
                if cand.kind() != STT_FUNC || cand.shndx != target_sym.shndx {
                    continue;
                }
                let contains = if cand.size == 0 {
                    dest == cand.value
                } else {
                    dest >= cand.value && dest < cand.value.saturating_add(cand.size)
                };
                if !contains {
                    continue;
                }
                let extent_ok = cand.size > 0
                    && image.sections.get(cand.shndx as usize).is_some_and(|sect| {
                        cand.value < sect.len && cand.size <= sect.len - cand.value
                    });
                if extent_ok {
                    usable = Some(cand);
                    break;
                }
                unusable = true;
            }
            if let Some(next) = usable {
                stack.push((next.shndx as usize, next.value, next.size));
            } else if unusable {
                push_section_finding(
                    violations,
                    retained,
                    limits,
                    "init.unresolved-extent",
                    section,
                    Some(reloc.offset),
                )?;
            }
        }
        // F23: linked-style static calls without a covering relocation
        // are invisible to the reloc walk; the guard cannot prove they
        // avoid `forbidden`, so each is its own finding. Applies to
        // every REACHABLE body (R09), never to dead code.
        let body = image.body(section)?;
        let scan_end = end.min(section.len);
        let mut at = value;
        while at.saturating_add(8) <= scan_end {
            charge(work, 1)?;
            let off = at as usize;
            let slot = &body[off..off + 8];
            if slot[0] == OP_LD_IMM64 {
                at = at.saturating_add(16);
                continue;
            }
            if slot[0] == OP_CALL && image.data.src_reg(slot[1]) != 0 {
                // S65-round5: membership on the sorted Vec index.
                let covered = reloc_offsets.binary_search(&at).is_ok();
                if !covered {
                    push_section_finding(
                        violations,
                        retained,
                        limits,
                        "init.unresolved-call",
                        section,
                        Some(at),
                    )?;
                }
            }
            at = at.saturating_add(8);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn check_opt_out(
    image: &Image<'_>,
    relocs: &[Reloc],
    violations: &mut Vec<RuleViolation>,
    retained: &mut usize,
    limits: &Limits,
    sections: &[String],
    arrays: &[String],
    opt_out_index: u64,
    continuations: &[(String, u64)],
    multi_loaded: &[String],
    pair: Option<&str>,
    pair_array: &str,
    plain_array: &str,
    multi_array: &str,
    work: &mut u64,
) -> Result<(), OperationError> {
    // Array loads: map relocs in executable sections against known arrays.
    // A known array named by any other reloc form cannot be attributed.
    let mut references: Vec<(usize, u64, String)> = Vec::new();
    for reloc in relocs {
        let Some(sym) = image.symbols.get(reloc.sym_idx) else {
            continue;
        };
        let Some(name) = sym.name.as_deref() else {
            continue;
        };
        if !arrays.iter().any(|known| known == name) {
            continue;
        }
        let Some(target) = image.sections.get(reloc.target_sect) else {
            continue;
        };
        if !target.executable() {
            continue;
        }
        charge(work, 1)?;
        if reloc.typ != R_BPF_64_64 {
            push_section_finding(
                violations,
                retained,
                limits,
                "private-stack.bad-relocation",
                target,
                Some(reloc.offset),
            )?;
            continue;
        }
        // R08: the collected reference retains its name; charge the
        // record plus the string like every other retained clone.
        retain(
            retained,
            limits,
            size_of::<(usize, u64, String)>().saturating_add(name.len()),
        )?;
        references.push((reloc.target_sect, reloc.offset, name.to_owned()));
    }
    // F22: every collected reference reconciles against the selected
    // sections; a program-array load in any other executable section is
    // outside the validated bodies and fails instead of escaping review.
    let selected: std::collections::BTreeSet<usize> = sections
        .iter()
        .filter_map(|name| {
            image
                .sections
                .iter()
                .position(|candidate| candidate.name.as_deref() == Some(name.as_str()))
        })
        .collect();
    for (sect, address, _) in &references {
        if !selected.contains(sect) {
            charge(work, 1)?;
            push_section_finding(
                violations,
                retained,
                limits,
                "private-stack.unselected-reference",
                &image.sections[*sect],
                Some(*address),
            )?;
        }
    }
    for section_name in sections {
        let Some(section) = image
            .sections
            .iter()
            .find(|candidate| candidate.name.as_deref() == Some(section_name.as_str()))
        else {
            continue;
        };
        let body = image.body(section)?;
        let programs: Vec<&Symbol> = image
            .symbols
            .iter()
            .filter(|sym| {
                sym.kind() == STT_FUNC && sym.size > 0 && sym.shndx as usize == section.index
            })
            .collect();
        for address in references
            .iter()
            .filter(|(sect, _, _)| *sect == section.index)
            .map(|(_, address, _)| *address)
        {
            let owners = programs
                .iter()
                .filter(|program| {
                    address >= program.value && address < program.value.saturating_add(program.size)
                })
                .count();
            if owners != 1 {
                push_section_finding(
                    violations,
                    retained,
                    limits,
                    "private-stack.unowned-reference",
                    section,
                    Some(address),
                )?;
            }
        }
        for program in programs {
            check_program(
                violations,
                retained,
                limits,
                image.data,
                body,
                section,
                program,
                &references,
                opt_out_index,
                continuations,
                multi_loaded,
                pair,
                pair_array,
                plain_array,
                multi_array,
                work,
            )?;
        }
    }
    Ok(())
}

/// S03: whether the instruction may overwrite register `target`.
/// Stores address memory through dst instead of writing it. Both
/// atomic widths (0xDB DW and 0xC3 W) decode by full-width imm
/// selector (filter.h BPF_ATOMIC): plain ALU (ADD/OR/AND/XOR)
/// and STORE_REL write memory only, FETCH/XCHG overwrite SRC
/// with the old value, LOAD_ACQ overwrites DST, CMPXCHG
/// overwrites R0, and an unrecognized selector conservatively
/// clobbers. Absolute loads write R0, never dst. Jumps never
/// reach here (they abort the walk first) and report a clobber
/// if they do.
fn writes_reg(op: u8, regs: u8, imm: i32, data: Data, target: u8) -> bool {
    match op & 7 {
        0 => {
            if op == OP_LD_IMM64 {
                data.dst_reg(regs) == target
            } else {
                // Absolute/indirect loads write R0; anything else
                // in class 0 is rejected by the kernel, and R0 is
                // the sound over-approximation for our r2/r3 walks.
                target == 0
            }
        }
        1 | 4 | 7 => data.dst_reg(regs) == target,
        2 => false,
        3 => {
            // S03-round4: W-width atomics (0xC3) clobber SRC on
            // FETCH/XCHG exactly like DW (0xDB); plain STX stores
            // only touch memory. S63: match the full imm —
            // truncating to u8 misreads LOAD_ACQ (0x100) as ADD.
            // S64: XCHG is 0xe0|BPF_FETCH = 0xe1; bare 0xe0 is
            // not a valid selector and stays conservative.
            if op != 0xDB && op != 0xC3 {
                return false;
            }
            match imm {
                0x00 | 0x40 | 0x50 | 0xa0 | 0x110 => false,
                0xf1 => target == 0,
                0x100 => data.dst_reg(regs) == target,
                0x01 | 0x41 | 0x51 | 0xa1 | 0xe1 => data.src_reg(regs) == target,
                _ => true,
            }
        }
        _ => true,
    }
}

/// S03: control leaves straight-line attribution here. JMP class (any
/// jump, exit 0x95) can skip the textual register load, and any call
/// clobbers r1-r5, so a register value inferred past one is unsound.
fn breaks_straight_line(op: u8) -> bool {
    matches!(op & 7, 5 | 6)
}

/// Second slot of a wide `ld_imm64` pair: decode as data, not code.
fn is_wide_second(slots: &[(u8, u8, i16, i32)], position: usize) -> bool {
    position > 0 && slots[position - 1].0 == OP_LD_IMM64
}

/// S03: a jump lands strictly between the attributed register load and
/// the tail call (or on the call itself), so some path reaches the
/// call without executing the load. BPF has no indirect jumps: every
/// static target is enumerable, and any landing in `(def, call]` kills
/// the attribution. Out-of-range targets cannot land there; a landing
/// on a wide second slot is malformed and kills attribution too.
fn jump_lands_between(
    slots: &[(u8, u8, i16, i32)],
    def: usize,
    call: usize,
    work: &mut u64,
) -> Result<bool, OperationError> {
    for (index, (op, _, off, imm)) in slots.iter().enumerate() {
        charge(work, 1)?;
        if !matches!(op & 7, 5 | 6) || *op == OP_CALL || *op == 0x95 {
            continue;
        }
        // S50: JMP32 long jump (0x06) displaces by imm32 with
        // off==0 (filter.h:446-454); every other jump uses off16.
        // Decoding 0x06 by off certifies a skipped definition.
        let target = if *op == 0x06 {
            index as i64 + 1 + i64::from(*imm)
        } else {
            index as i64 + 1 + i64::from(*off)
        };
        if target > def as i64 && target <= call as i64 {
            return Ok(true);
        }
    }
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
fn check_program(
    violations: &mut Vec<RuleViolation>,
    retained: &mut usize,
    limits: &Limits,
    data: Data,
    body: &[u8],
    section: &Section,
    program: &Symbol,
    references: &[(usize, u64, String)],
    opt_out_index: u64,
    continuations: &[(String, u64)],
    multi_loaded: &[String],
    pair: Option<&str>,
    pair_array: &str,
    plain_array: &str,
    multi_array: &str,
    work: &mut u64,
) -> Result<(), OperationError> {
    let name = program.display();
    let end = program.value.saturating_add(program.size);
    if program.size % 8 != 0 || end > section.len {
        push_section_finding(
            violations,
            retained,
            limits,
            "private-stack.bad-extent",
            section,
            Some(program.value),
        )?;
        return Ok(());
    }
    let start = program.value as usize;
    let code = &body[start..start + program.size as usize];
    let slots: Vec<(u8, u8, i16, i32)> = code
        .chunks_exact(8)
        .map(|slot| {
            (
                slot[0],
                slot[1],
                data.u16(&slot[2..4]) as i16,
                data.u32(&slot[4..8]) as i32,
            )
        })
        .collect();
    let owned: Vec<(u64, String)> = references
        .iter()
        .filter(|(sect, address, _)| {
            *sect == section.index && *address >= program.value && *address < end
        })
        .map(|(_, address, array)| (*address, array.clone()))
        .collect();
    let arrays_at: std::collections::BTreeMap<u64, String> = owned
        .into_iter()
        .map(|(address, array)| ((address - program.value) / 8, array))
        .collect();
    let mut tail_calls = 0u32;
    for (position, (op, regs, _, imm)) in slots.iter().enumerate() {
        charge(work, 1)?;
        if *op != OP_CALL || *regs != 0 || *imm != TAIL_CALL_HELPER {
            continue;
        }
        tail_calls += 1;
        let call_off = program.value + position as u64 * 8;
        // S03: the index constant and the map load are only sound on a
        // straight-line path. A branch can skip the textual MOV (the
        // executed slot is then certified wrongly), a call clobbers
        // r1-r5, and any other r3/r2 write between the load and the
        // tail call replaces the attributed value. The walk gives up
        // (unknown slot/array) on any branch, exit, call, or foreign
        // write instead of inferring across it. S04: dst/src decode
        // per object endianness.
        let floor = position.saturating_sub(16);
        let mut index: Option<u64> = None;
        let mut index_def = 0usize;
        for previous in (floor..position).rev() {
            if is_wide_second(&slots, previous) {
                continue;
            }
            let (prev_op, prev_regs, _, prev_imm) = slots[previous];
            if breaks_straight_line(prev_op) {
                break;
            }
            if !writes_reg(prev_op, prev_regs, prev_imm, data, 3) {
                continue;
            }
            if prev_op == 0xB7 || prev_op == 0xB4 {
                index = Some(prev_imm as u32 as u64);
                index_def = previous;
            } else if prev_op == OP_LD_IMM64
                && data.src_reg(prev_regs) == 0
                && previous + 1 < position
            {
                let high = slots[previous + 1].3;
                index = Some(prev_imm as u32 as u64 | ((high as u32 as u64) << 32));
                index_def = previous;
            }
            break;
        }
        if index.is_some() && jump_lands_between(&slots, index_def, position, work)? {
            index = None;
        }
        let mut array: Option<&str> = None;
        let mut array_def = 0usize;
        for previous in (floor..position).rev() {
            if is_wide_second(&slots, previous) {
                continue;
            }
            let (prev_op, prev_regs, _, prev_imm) = slots[previous];
            if breaks_straight_line(prev_op) {
                break;
            }
            if !writes_reg(prev_op, prev_regs, prev_imm, data, 2) {
                continue;
            }
            if prev_op == OP_LD_IMM64 && data.src_reg(prev_regs) == 0 {
                array = arrays_at.get(&(previous as u64)).map(String::as_str);
                array_def = previous;
            }
            break;
        }
        if array.is_some() && jump_lands_between(&slots, array_def, position, work)? {
            array = None;
        }
        let Some(array) = array else {
            push_section_finding(
                violations,
                retained,
                limits,
                "private-stack.unknown-array",
                section,
                Some(call_off),
            )?;
            continue;
        };
        let known = index == Some(opt_out_index)
            || continuations
                .iter()
                .any(|(known, slot)| known == array && Some(*slot) == index);
        if !known {
            push_section_finding(
                violations,
                retained,
                limits,
                "private-stack.unknown-slot",
                section,
                Some(call_off),
            )?;
        }
    }
    let mut used: Vec<&str> = arrays_at.values().map(String::as_str).collect();
    used.sort_unstable();
    used.dedup();
    let allowed = if pair == Some(name.as_str()) {
        pair_array
    } else if multi_loaded.iter().any(|known| known == &name) {
        multi_array
    } else {
        plain_array
    };
    if used.iter().any(|array| *array != allowed) {
        push_section_finding(
            violations,
            retained,
            limits,
            "private-stack.wrong-array",
            section,
            Some(program.value),
        )?;
    }
    // Only a program that never addresses its frame and calls no BPF
    // subprogram is provably exempt from the private stack.
    let stackless = !slots.iter().any(|(op, regs, _, _)| {
        (data.dst_reg(*regs) == 10 || data.src_reg(*regs) == 10) && *op != 0x95
            || (*op == OP_CALL && data.dst_reg(*regs) == 0 && data.src_reg(*regs) == 1)
    });
    // A program with tail calls that all fail already reports its slot
    // or array defect above (the donor aborts there too); the missing
    // prologue fires only when no tail call exists at all.
    if tail_calls == 0 && !stackless {
        push_section_finding(
            violations,
            retained,
            limits,
            "private-stack.opt-out-required",
            section,
            Some(program.value),
        )?;
    }
    Ok(())
}
