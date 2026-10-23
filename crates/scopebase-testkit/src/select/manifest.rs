// SPDX-License-Identifier: Apache-2.0
//! TT08 change manifests: causal inputs to affected-check selection.
//!
//! A manifest names changed catalog nodes (cases, cells, profiles,
//! extensions, obligations, executable-registration roles) or declares
//! unknown/environment impact that must broaden a named boundary. Manifests
//! are pure data; validation against an admitted [`CaseCatalog`] happens in
//! [`select_affected`](crate::select::select_affected).

use crate::{CaseId, ProfileId};

/// One executable-registration role whose bytes changed without a production
/// change. Any role change invalidates every dependent verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RegistrationRole {
    Executable,
    Fixture,
    Oracle,
    BadControl,
}

/// A platform-level attribute whose change cannot name precise catalog nodes
/// and therefore broadens its boundary like unknown impact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum EnvironmentAttribute {
    Source,
    Dependency,
    Features,
    Compiler,
}

/// One causal input to selection. Constructors are infallible; malformed or
/// unadmitted targets are rejected by [`select_affected`](crate::select::select_affected).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Change {
    Case {
        case_id: CaseId,
        case_version: u32,
    },
    Cell {
        cell_id: String,
    },
    Profile {
        profile: ProfileId,
    },
    Extension {
        extension: ProfileId,
    },
    Obligation {
        kind: String,
        id: String,
    },
    RegistrationRole {
        case_id: CaseId,
        case_version: u32,
        role: RegistrationRole,
    },
    Unknown {
        boundary: Option<ProfileId>,
        reason: String,
    },
    Environment {
        attribute: EnvironmentAttribute,
        boundary: Option<ProfileId>,
    },
}

impl Change {
    pub fn case(case_id: CaseId, case_version: u32) -> Self {
        Self::Case {
            case_id,
            case_version,
        }
    }
    pub fn cell(cell_id: &str) -> Self {
        Self::Cell {
            cell_id: cell_id.to_owned(),
        }
    }
    pub fn profile(profile: ProfileId) -> Self {
        Self::Profile { profile }
    }
    pub fn extension(extension: ProfileId) -> Self {
        Self::Extension { extension }
    }
    pub fn obligation(kind: &str, id: &str) -> Self {
        Self::Obligation {
            kind: kind.to_owned(),
            id: id.to_owned(),
        }
    }
    pub fn registration_role(case_id: CaseId, case_version: u32, role: RegistrationRole) -> Self {
        Self::RegistrationRole {
            case_id,
            case_version,
            role,
        }
    }
    pub fn unknown(boundary: Option<ProfileId>, reason: &str) -> Self {
        Self::Unknown {
            boundary,
            reason: reason.to_owned(),
        }
    }
    pub fn environment(attribute: EnvironmentAttribute, boundary: Option<ProfileId>) -> Self {
        Self::Environment {
            attribute,
            boundary,
        }
    }
}

/// The ordered causal inputs to one selection. Order is significant only for
/// deterministic explanation attribution (first affecting change wins).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ChangeManifest {
    changes: Vec<Change>,
}

impl ChangeManifest {
    pub fn new(changes: Vec<Change>) -> Self {
        Self { changes }
    }
    pub fn changes(&self) -> &[Change] {
        &self.changes
    }
}
