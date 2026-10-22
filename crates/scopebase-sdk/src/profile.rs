// SPDX-License-Identifier: Apache-2.0
//! Explicit profile, capability and effects admission (SDK01).
//!
//! A [`Profile`] declares an application's prerequisite capabilities and
//! admitted effects before any environment is probed. [`Profile::admission`]
//! folds capability observations through the Ready/Incomplete/Refused table.
//! These are report metadata only: an admission verdict cannot mint an attach
//! handle, mapping proof, process capability or close receipt, and no
//! constructor probes environments, performs I/O, logs, spawns threads or
//! touches global state.
//!
//! Validation order is structural bounds first, then content: profile id,
//! requirement count, effect count, per-requirement id validity and
//! duplicates, then duplicate effects. All checks run before any copy of the
//! validated vectors into the profile.

use std::error::Error;
use std::fmt;

/// Maximum identifier length in bytes for profile and requirement ids.
pub const MAX_PROFILE_ID_BYTES: usize = 64;
/// Maximum number of capability requirements per profile.
pub const MAX_REQUIREMENTS: usize = 64;
/// Maximum number of admitted effects per profile.
pub const MAX_EFFECTS: usize = 5;

/// Observed support state of one declared capability. The failure states
/// stay distinct: none of them upgrades to [`CapabilityState::Supported`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CapabilityState {
    Supported,
    Unsupported,
    Denied,
    Unknown,
    Incompatible,
}

/// Application effect the profile may admit. Membership is explicit policy
/// checked by the caller before its selected operation; it is not a sandbox
/// capable of blocking arbitrary caller code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Effect {
    ReadOwnedFiles,
    WriteOwnedFixtures,
    PrivateReadOnlyCalibration,
    SpawnOwnedChild,
    LoadBpf,
}

/// One declared prerequisite capability. Optional capabilities must be
/// declared too; undeclared ids never participate in admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CapabilityRequirement {
    pub id: &'static str,
    pub required: bool,
}

/// One reported observation of a declared capability. `source` names the
/// report provenance and never carries executable authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CapabilityObservation {
    pub id: &'static str,
    pub state: CapabilityState,
    pub source: &'static str,
}

/// Prerequisite admission verdict over the observed capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Admission {
    Ready,
    Incomplete,
    Refused,
}

/// Validated application profile with private fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    id: &'static str,
    requirements: Vec<CapabilityRequirement>,
    effects: Vec<Effect>,
}

/// Profile construction failure. Variants stay structured and carry no
/// identifier payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProfileError {
    InvalidId,
    DuplicateId,
    DuplicateEffect,
    Capacity,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileError::InvalidId => {
                write!(f, "invalid profile or capability identifier")
            }
            ProfileError::DuplicateId => {
                write!(f, "duplicate capability identifier")
            }
            ProfileError::DuplicateEffect => {
                write!(f, "duplicate effect entry")
            }
            ProfileError::Capacity => {
                write!(f, "profile requirement or effect capacity exceeded")
            }
        }
    }
}

impl Error for ProfileError {}

impl Profile {
    /// Build a validated profile. Rejects empty or overlong ids (more than
    /// [`MAX_PROFILE_ID_BYTES`] bytes), duplicate requirement ids, duplicate
    /// effect entries, more than [`MAX_REQUIREMENTS`] requirements and more
    /// than [`MAX_EFFECTS`] effects. Performs no external effects.
    pub fn new(
        id: &'static str,
        requirements: Vec<CapabilityRequirement>,
        effects: Vec<Effect>,
    ) -> Result<Self, ProfileError> {
        if id.is_empty() || id.len() > MAX_PROFILE_ID_BYTES {
            return Err(ProfileError::InvalidId);
        }
        if requirements.len() > MAX_REQUIREMENTS {
            return Err(ProfileError::Capacity);
        }
        if effects.len() > MAX_EFFECTS {
            return Err(ProfileError::Capacity);
        }
        for (index, requirement) in requirements.iter().enumerate() {
            if requirement.id.is_empty() || requirement.id.len() > MAX_PROFILE_ID_BYTES {
                return Err(ProfileError::InvalidId);
            }
            if requirements[..index]
                .iter()
                .any(|prior| prior.id == requirement.id)
            {
                return Err(ProfileError::DuplicateId);
            }
        }
        for (index, effect) in effects.iter().enumerate() {
            if effects[..index].contains(effect) {
                return Err(ProfileError::DuplicateEffect);
            }
        }
        Ok(Profile {
            id,
            requirements,
            effects,
        })
    }

    /// Validated profile identifier.
    pub fn id(&self) -> &'static str {
        self.id
    }

    /// Whether the profile admits `effect`. The caller checks this before
    /// its selected component operation and owns ordering and recovery.
    pub fn permits(&self, effect: Effect) -> bool {
        self.effects.contains(&effect)
    }

    /// Fold `observations` through the admission table:
    ///
    /// * `Refused` when a required capability has an explicit
    ///   [`CapabilityState::Unsupported`], [`CapabilityState::Denied`] or
    ///   [`CapabilityState::Incompatible`] observation;
    /// * otherwise `Incomplete` when a required capability is missing or
    ///   [`CapabilityState::Unknown`];
    /// * otherwise `Ready`.
    ///
    /// Optional observations never move the verdict and stay in the caller's
    /// report input. Observations for undeclared ids are ignored: they name
    /// no prerequisite. Every observation for a declared required id folds,
    /// so a denial is never masked by a sibling Supported report. Runs in
    /// O(requirements x observations) time with O(1) extra storage.
    ///
    /// This is capability-prerequisite admission only. Binding completeness
    /// (zero bindings, or any binding without an artifact digest, refusing
    /// Ready) belongs to the later SDK02 application context, not here.
    pub fn admission(&self, observations: &[CapabilityObservation]) -> Admission {
        let mut incomplete = false;
        for requirement in &self.requirements {
            if !requirement.required {
                continue;
            }
            let mut seen = false;
            for observation in observations {
                if observation.id != requirement.id {
                    continue;
                }
                seen = true;
                match observation.state {
                    CapabilityState::Unsupported
                    | CapabilityState::Denied
                    | CapabilityState::Incompatible => return Admission::Refused,
                    CapabilityState::Unknown => incomplete = true,
                    CapabilityState::Supported => {}
                }
            }
            if !seen {
                incomplete = true;
            }
        }
        if incomplete {
            Admission::Incomplete
        } else {
            Admission::Ready
        }
    }
}
