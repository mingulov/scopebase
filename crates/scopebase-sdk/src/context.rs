// SPDX-License-Identifier: Apache-2.0
//! Bounded application context (SDK02).
//!
//! An [`AppContext`] owns inert, bounded metadata for one application: its
//! [`Profile`](crate::profile::Profile), [`Limits`](crate::limits::Limits),
//! declared capability observations, exact component bindings and retained
//! diagnostics. Actual component owners -- sessions, files, links -- stay
//! outside the context with their callers; dropping a context touches no
//! external resource.
//!
//! Validation order is structural bounds first, then content, matching the
//! profile constructors: a full observation or binding store reports
//! [`ContextError::Capacity`] even when the refused entry is also unknown,
//! duplicate or malformed. Failed operations check before any mutation, so
//! the prior context is unchanged.
//!
//! SDK03 adds [`AppContext::capture`]: one bounded immutable snapshot of a
//! CP10-validated neutral observation per context, sharing the `retained_bytes`
//! allowance with binding payload. Only pre-validated snapshots are accepted;
//! capture preserves evidence strength and mints no closure authority.

use std::error::Error;
use std::fmt;

#[cfg(feature = "capture")]
use scopebase_capture::neutral::ValidatedNeutralV1;

use crate::diagnostic::RetainedDiagnostic;
use crate::diagnostic::{Diagnostic, DiagnosticDisposition, DiagnosticStore, OmittedDiagnostics};
use crate::limits::{Limits, LimitsError};
use crate::profile::{Admission, CapabilityObservation, Profile};

/// Maximum capability observations per context.
pub const MAX_OBSERVATIONS: usize = 64;
/// Maximum component bindings per context.
pub const MAX_BINDINGS: usize = 8;
/// Maximum binding package name length in bytes.
pub const MAX_BINDING_PACKAGE_BYTES: usize = 128;
/// Maximum binding version length in bytes.
pub const MAX_BINDING_VERSION_BYTES: usize = 64;
/// Maximum binding backend name length in bytes.
pub const MAX_BINDING_BACKEND_BYTES: usize = 64;
/// Maximum feature names per binding.
pub const MAX_BINDING_FEATURES: usize = 16;
/// Maximum feature name length in bytes.
pub const MAX_BINDING_FEATURE_BYTES: usize = 64;
/// Fixed retained-payload cost of the one capture snapshot in bytes.
#[cfg(feature = "capture")]
pub const CAPTURE_SNAPSHOT_BASE_BYTES: u64 = 128;
/// Retained-payload cost per validated counter in bytes.
#[cfg(feature = "capture")]
pub const CAPTURE_COUNTER_BYTES: u64 = 32;
/// Retained-payload cost per validated claim in bytes.
#[cfg(feature = "capture")]
pub const CAPTURE_CLAIM_BYTES: u64 = 8;
/// Retained-payload cost per validated claim reason in bytes.
#[cfg(feature = "capture")]
pub const CAPTURE_REASON_BYTES: u64 = 4;

/// One bound component: the actual package coordinate plus optional artifact
/// evidence. Coordinates are owned strings so applications can bind
/// dynamically resolved builds; the profile's static identifiers stay static.
/// A binding without [`ComponentBinding::artifact_sha256`] stores honestly
/// but never admits [`Admission::Ready`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ComponentBinding {
    pub package: String,
    pub version: String,
    pub features: Vec<String>,
    pub backend: Option<String>,
    pub artifact_sha256: Option<[u8; 32]>,
}

impl ComponentBinding {
    /// UTF-8 string payload charged against `retained_bytes`: package plus
    /// version plus backend plus feature bytes, with checked arithmetic.
    /// Fixed-size fields (the optional digest) and container overhead are
    /// not payload bytes.
    fn payload_bytes(&self) -> Option<u64> {
        let mut total = self.package.len() as u64;
        total = total.checked_add(self.version.len() as u64)?;
        if let Some(ref backend) = self.backend {
            total = total.checked_add(backend.len() as u64)?;
        }
        for feature in &self.features {
            total = total.checked_add(feature.len() as u64)?;
        }
        Some(total)
    }

    /// Whether `other` names the same package coordinate: package, version,
    /// backend and features. Digest evidence is excluded: one coordinate
    /// binds once, however its evidence reads.
    fn same_coordinate(&self, other: &ComponentBinding) -> bool {
        self.package == other.package
            && self.version == other.version
            && self.backend == other.backend
            && self.features == other.features
    }
}

/// Borrowed application report over existing context storage. Borrows only;
/// callers cloning out of the borrow assume their own memory custody. The
/// capture borrow is validated metadata, never a closure receipt: the report
/// exposes no close/drain/quiesce route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextReport<'a> {
    pub profile: &'static str,
    pub admission: Admission,
    pub limits: &'a Limits,
    pub observations: &'a [CapabilityObservation],
    pub bindings: &'a [ComponentBinding],
    pub diagnostics: &'a [RetainedDiagnostic],
    pub omitted: OmittedDiagnostics,
    /// The retained capture snapshot, when the `capture` feature is enabled
    /// and one was consumed.
    #[cfg(feature = "capture")]
    pub capture: Option<&'a ValidatedNeutralV1>,
}

/// Bounded application context. Not [`Clone`]: evidence changes require a
/// new explicit context rather than a copied one.
#[derive(Debug)]
pub struct AppContext {
    profile: Profile,
    limits: Limits,
    observations: Vec<CapabilityObservation>,
    bindings: Vec<ComponentBinding>,
    diagnostics: DiagnosticStore,
    retained_payload_bytes: u64,
    #[cfg(feature = "capture")]
    capture: Option<ValidatedNeutralV1>,
}

/// Application context failure. Variants stay structured and carry no
/// caller payloads beyond the wrapped [`LimitsError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ContextError {
    Limits(LimitsError),
    InvalidBinding,
    DuplicateBinding,
    DuplicateObservation,
    UnknownCapability,
    Capacity,
    /// A capture snapshot is already present; later snapshots use a new
    /// explicit context. Present in every feature mode so matches stay
    /// exhaustive; only reachable through `capture` with `capture` enabled.
    CaptureAlreadyPresent,
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContextError::Limits(error) => {
                write!(f, "invalid application context limits: {error}")
            }
            ContextError::InvalidBinding => write!(f, "invalid component binding"),
            ContextError::DuplicateBinding => write!(f, "duplicate component binding"),
            ContextError::DuplicateObservation => {
                write!(f, "duplicate capability observation")
            }
            ContextError::UnknownCapability => {
                write!(f, "capability not declared in profile")
            }
            ContextError::Capacity => {
                write!(f, "application context capacity exceeded")
            }
            ContextError::CaptureAlreadyPresent => {
                write!(f, "capture snapshot already present")
            }
        }
    }
}

impl Error for ContextError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ContextError::Limits(error) => Some(error),
            _ => None,
        }
    }
}

impl AppContext {
    /// Build an empty context for `profile` within `limits`. Refuses invalid
    /// limits before any storage is created and performs no external effect.
    pub fn new(profile: Profile, limits: Limits) -> Result<Self, ContextError> {
        limits.validate().map_err(ContextError::Limits)?;
        Ok(AppContext {
            profile,
            limits,
            observations: Vec::new(),
            bindings: Vec::new(),
            diagnostics: DiagnosticStore::new(),
            retained_payload_bytes: 0,
            #[cfg(feature = "capture")]
            capture: None,
        })
    }

    /// The validated application profile.
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Record one capability observation. The id must be declared in the
    /// profile -- optional capabilities must be declared too -- and must not
    /// be observed already; evidence changes require a new explicit context,
    /// so a failed required observation can never be replaced with a green
    /// retry. Structural capacity is checked first: a full store reports
    /// [`ContextError::Capacity`] for unknown and duplicate ids alike.
    pub fn observe(&mut self, report: CapabilityObservation) -> Result<(), ContextError> {
        if self.observations.len() >= MAX_OBSERVATIONS {
            return Err(ContextError::Capacity);
        }
        if !self.profile.declares(report.id) {
            return Err(ContextError::UnknownCapability);
        }
        if self.observations.iter().any(|prior| prior.id == report.id) {
            return Err(ContextError::DuplicateObservation);
        }
        self.observations.push(report);
        Ok(())
    }

    /// Bind one actual component. Package, version and present backend are
    /// nonempty and bounded to 128/64/64 bytes; at most sixteen feature
    /// names of at most 64 bytes arrive sorted and unique; package
    /// coordinates are unique per context. Structural count capacity is
    /// checked first, then field validity, then coordinate duplication, and
    /// finally the cumulative binding payload against `retained_bytes` with
    /// checked arithmetic before cloning. Any refusal leaves the prior
    /// bindings unchanged.
    pub fn bind(&mut self, binding: ComponentBinding) -> Result<(), ContextError> {
        if self.bindings.len() >= MAX_BINDINGS {
            return Err(ContextError::Capacity);
        }
        if !valid_binding(&binding) {
            return Err(ContextError::InvalidBinding);
        }
        if self
            .bindings
            .iter()
            .any(|prior| prior.same_coordinate(&binding))
        {
            return Err(ContextError::DuplicateBinding);
        }
        let payload = binding.payload_bytes().ok_or(ContextError::Capacity)?;
        let total = self
            .retained_payload_bytes
            .checked_add(payload)
            .ok_or(ContextError::Capacity)?;
        if total > self.limits.retained_bytes {
            return Err(ContextError::Capacity);
        }
        self.retained_payload_bytes = total;
        self.bindings.push(binding);
        Ok(())
    }

    /// Fold stored observations through the profile admission table, then
    /// gate on exact bindings: `Refused` for a required explicit
    /// unsupported/denied/incompatible observation; otherwise `Incomplete`
    /// for a required missing/unknown observation, zero bindings, or any
    /// binding without an artifact digest; otherwise `Ready`. Optional
    /// failures stay present in the report without moving the verdict, and
    /// diagnostics never move it either.
    pub fn admission(&self) -> Admission {
        match self.profile.admission(&self.observations) {
            Admission::Refused => Admission::Refused,
            capability => {
                if self.bindings.is_empty() {
                    return Admission::Incomplete;
                }
                if self.bindings.iter().any(|b| b.artifact_sha256.is_none()) {
                    return Admission::Incomplete;
                }
                capability
            }
        }
    }

    /// Retain one diagnostic within the configured count and aggregate byte
    /// allowance plus the host per-diagnostic and aggregate caps. Over-cap
    /// and invalid-code diagnostics are omitted whole with
    /// [`DiagnosticDisposition::Truncated`] and an explicit omitted count;
    /// retained storage is then unchanged. Never moves admission.
    pub fn diagnostic(&mut self, value: Diagnostic<'_>) -> DiagnosticDisposition {
        self.diagnostics.push(
            self.limits.diagnostic_count,
            self.limits.diagnostic_bytes,
            value,
        )
    }

    /// Retain one validated capture snapshot as bounded immutable metadata.
    /// The snapshot is an exact copy: source, epoch, binding, origin, units,
    /// magnitudes and per-claim reasons pass through unchanged. Unknown stays
    /// unknown and query-partial stays query-partial; nothing is upgraded,
    /// merged or converted into closure authority, and admission never moves.
    ///
    /// A context holds at most one snapshot: a second `capture` -- identical
    /// or different-epoch -- is refused with
    /// [`ContextError::CaptureAlreadyPresent`], checked before the budget. A
    /// snapshot whose deterministic cost (`128 + 32*counters + 8*claims +
    /// 4*reasons`) does not fit the `retained_bytes` allowance shared with
    /// binding payload is refused with [`ContextError::Capacity`]; checked
    /// arithmetic runs before cloning. Either refusal leaves the prior
    /// context unchanged.
    ///
    /// ```rust
    /// use scopebase_capture::neutral::{
    ///     validate_v1, NeutralLimits, NeutralObservationV1, NeutralOrigin,
    ///     NeutralSource, NeutralUnit,
    /// };
    /// use scopebase_sdk::context::{AppContext, ComponentBinding};
    /// use scopebase_sdk::limits::Limits;
    /// use scopebase_sdk::profile::{Admission, Profile};
    /// use std::time::Duration;
    ///
    /// let profile = Profile::new("capture-demo", vec![], vec![]).unwrap();
    /// let limits = Limits {
    ///     input_bytes: 65_536,
    ///     retained_bytes: 65_536,
    ///     work_items: 64,
    ///     live_owners: 8,
    ///     diagnostic_count: 32,
    ///     diagnostic_bytes: 65_536,
    ///     wait: Duration::from_secs(2),
    /// };
    /// let mut context = AppContext::new(profile, limits).unwrap();
    /// context.bind(ComponentBinding {
    ///     package: "scopebase-capture".to_owned(),
    ///     version: "0.1.0".to_owned(),
    ///     features: Vec::new(),
    ///     backend: None,
    ///     artifact_sha256: Some([0x42; 32]),
    /// }).unwrap();
    /// let raw = NeutralObservationV1 {
    ///     source: NeutralSource {
    ///         capture: [0x11; 16],
    ///         producer: [0x22; 16],
    ///         ordinal: 1,
    ///         binding: [0x33; 32],
    ///         origin: NeutralOrigin::AdapterReported,
    ///     },
    ///     unit: NeutralUnit::Events,
    ///     counters: Vec::new(),
    ///     losses: Vec::new(),
    ///     signals: Vec::new(),
    ///     claims: Vec::new(),
    ///     partitions: Vec::new(),
    ///     corrections: Vec::new(),
    /// };
    /// let validated = validate_v1(&raw, NeutralLimits::default()).unwrap();
    /// context.capture(&validated).unwrap();
    /// assert_eq!(context.admission(), Admission::Ready);
    /// assert!(context.report().capture.is_some());
    /// ```
    #[cfg(feature = "capture")]
    pub fn capture(&mut self, report: &ValidatedNeutralV1) -> Result<(), ContextError> {
        if self.capture.is_some() {
            return Err(ContextError::CaptureAlreadyPresent);
        }
        let cost = snapshot_cost(report).ok_or(ContextError::Capacity)?;
        let total = self
            .retained_payload_bytes
            .checked_add(cost)
            .ok_or(ContextError::Capacity)?;
        if total > self.limits.retained_bytes {
            return Err(ContextError::Capacity);
        }
        self.retained_payload_bytes = total;
        self.capture = Some(report.clone());
        Ok(())
    }

    /// Borrow the retained capture snapshot, if one was consumed.
    #[cfg(feature = "capture")]
    pub fn capture_snapshot(&self) -> Option<&ValidatedNeutralV1> {
        self.capture.as_ref()
    }

    /// Borrow the current report over existing storage. Allocates nothing.
    pub fn report(&self) -> ContextReport<'_> {
        ContextReport {
            profile: self.profile.id(),
            admission: self.admission(),
            limits: &self.limits,
            observations: &self.observations,
            bindings: &self.bindings,
            diagnostics: self.diagnostics.retained(),
            omitted: self.diagnostics.omitted(),
            #[cfg(feature = "capture")]
            capture: self.capture.as_ref(),
        }
    }
}

/// Deterministic retained-payload cost of one validated snapshot: `128 +
/// 32*counters + 8*claims + 4*reasons`, with checked arithmetic over the
/// validated cardinalities. `None` on arithmetic overflow.
#[cfg(feature = "capture")]
fn snapshot_cost(report: &ValidatedNeutralV1) -> Option<u64> {
    let mut total = CAPTURE_SNAPSHOT_BASE_BYTES;
    total =
        total.checked_add((report.counters().len() as u64).checked_mul(CAPTURE_COUNTER_BYTES)?)?;
    total = total.checked_add((report.claims().len() as u64).checked_mul(CAPTURE_CLAIM_BYTES)?)?;
    let mut reasons: u64 = 0;
    for claim in report.claims() {
        reasons = reasons.checked_add(claim.reasons().len() as u64)?;
    }
    total.checked_add(reasons.checked_mul(CAPTURE_REASON_BYTES)?)
}

/// Whether `binding` is well-formed: nonempty package/version within
/// 128/64 bytes, a present backend nonempty within 64 bytes, at most
/// sixteen nonempty feature names within 64 bytes each, arriving strictly
/// sorted and unique. The context refuses to reorder or deduplicate the
/// caller's record.
fn valid_binding(binding: &ComponentBinding) -> bool {
    if binding.package.is_empty() || binding.package.len() > MAX_BINDING_PACKAGE_BYTES {
        return false;
    }
    if binding.version.is_empty() || binding.version.len() > MAX_BINDING_VERSION_BYTES {
        return false;
    }
    if let Some(ref backend) = binding.backend {
        if backend.is_empty() || backend.len() > MAX_BINDING_BACKEND_BYTES {
            return false;
        }
    }
    if binding.features.len() > MAX_BINDING_FEATURES {
        return false;
    }
    for feature in &binding.features {
        if feature.is_empty() || feature.len() > MAX_BINDING_FEATURE_BYTES {
            return false;
        }
    }
    if binding.features.windows(2).any(|pair| pair[0] >= pair[1]) {
        return false;
    }
    true
}
