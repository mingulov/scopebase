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

use std::error::Error;
use std::fmt;

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
/// callers cloning out of the borrow assume their own memory custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextReport<'a> {
    pub profile: &'static str,
    pub admission: Admission,
    pub limits: &'a Limits,
    pub observations: &'a [CapabilityObservation],
    pub bindings: &'a [ComponentBinding],
    pub diagnostics: &'a [RetainedDiagnostic],
    pub omitted: OmittedDiagnostics,
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
        }
    }
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
