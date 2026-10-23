// SPDX-License-Identifier: Apache-2.0
//! TC03: final-object inventory. Every emitted `.o`/`.elf` is hashed and
//! attributed before inspection: manifest id, rel/exec role, producer,
//! contract refs and ISA profile refs. Admission binds bytes to exactly one
//! entry by id and refuses hash mismatch and uninventoried ids with typed
//! errors. Hashes identify upstream/tool artifacts; no third-party bytes are
//! copied here.
//!
//! Donor slice (p11scope-ws w000 @ 6f97aa47, frozen tree):
//! `llvm-bpf-toolchain-experiment.md` lines 77-100 (user-authored H30 preset
//! warning; motivates hash-bound admission instead of preset-name trust).
//! Grant: OWNER-2026-10-23.
use scopebase_bpf::{ErrorKind, Limits, OperationError};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{
    check_no_unknown, check_version, get_str, limited, parse_label, parse_sha256, strict_value,
    tc03_refuse,
};
use crate::ids::ProfileId;

const MANIFEST_FIELDS: &[&str] = &["schema_version", "kind", "objects"];
const ENTRY_FIELDS: &[&str] = &[
    "id",
    "kind",
    "path",
    "sha256",
    "producer_name",
    "producer_version",
    "artifact",
    "profile",
    "isa_profile",
    "isa_version",
    "license_declared",
];

/// Final-object role: relocatable `.o` or linked `.elf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// Relocatable object (`ET_REL`).
    Rel,
    /// Linked executable object (`ET_EXEC`).
    Exec,
}

impl ObjectKind {
    /// Canonical role name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rel => "rel",
            Self::Exec => "exec",
        }
    }

    fn parse(text: &str) -> Result<Self, OperationError> {
        match text {
            "rel" => Ok(Self::Rel),
            "exec" => Ok(Self::Exec),
            _ => Err(tc03_refuse(ErrorKind::InvalidInput, "object kind")),
        }
    }
}

/// Admitted final-object identity: manifest label plus exact content hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactId {
    id: String,
    sha256: [u8; 32],
}

impl ArtifactId {
    /// Bind a label to an exact content hash. The id alone admits nothing;
    /// [`FinalObjectManifest::admit`] and `check_object` verify the hash
    /// against the presented bytes.
    pub fn new(id: String, sha256: [u8; 32]) -> Self {
        Self { id, sha256 }
    }

    /// Manifest label (or content hex for bare inspections).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Exact SHA-256 of the admitted bytes.
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

/// One inventoried final object with full attribution.
#[derive(Debug, Clone)]
pub struct ObjectEntry {
    id: ArtifactId,
    kind: ObjectKind,
    path: String,
    producer_name: String,
    producer_version: String,
    artifact: String,
    profile: String,
    isa_profile: String,
    isa_version: String,
    license_declared: Option<String>,
}

impl ObjectEntry {
    /// Manifest label.
    pub fn id(&self) -> &str {
        self.id.id()
    }

    /// Full object identity (label plus hash).
    pub fn object_id(&self) -> &ArtifactId {
        &self.id
    }

    /// Declared rel/exec role; verified against the ELF type at check time.
    pub fn kind(&self) -> ObjectKind {
        self.kind
    }

    /// Informational source path of the emitted file.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Exact content hash.
    pub fn sha256(&self) -> &[u8; 32] {
        self.id.sha256()
    }

    /// Emitting tool name.
    pub fn producer_name(&self) -> &str {
        &self.producer_name
    }

    /// Exact emitting tool version.
    pub fn producer_version(&self) -> &str {
        &self.producer_version
    }

    /// Referenced contract artifact.
    pub fn artifact(&self) -> &str {
        &self.artifact
    }

    /// Referenced conformance profile id.
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Referenced ISA profile name.
    pub fn isa_profile(&self) -> &str {
        &self.isa_profile
    }

    /// Referenced ISA profile version.
    pub fn isa_version(&self) -> &str {
        &self.isa_version
    }

    /// License token the manifest attributes to the object, if any. The
    /// bytes govern: a declared token absent from or differing from the
    /// object refuses at check time.
    pub fn license_declared(&self) -> Option<&str> {
        self.license_declared.as_deref()
    }
}

/// Strict versioned final-object manifest.
#[derive(Debug, Clone)]
pub struct FinalObjectManifest {
    objects: Vec<ObjectEntry>,
}

fn bounded_text(
    root: &serde_json::Map<String, Value>,
    field: &'static str,
    max: usize,
) -> Result<String, OperationError> {
    let text = get_str(root, field)?;
    if text.is_empty() || text.len() > max {
        return Err(tc03_refuse(ErrorKind::InvalidInput, field));
    }
    Ok(text.to_owned())
}

impl FinalObjectManifest {
    /// Admit one strict versioned final-object manifest document.
    pub fn from_json(bytes: &[u8], limits: &Limits) -> Result<Self, OperationError> {
        let value = strict_value(bytes, limits)?;
        let root = value
            .as_object()
            .ok_or_else(|| tc03_refuse(ErrorKind::InvalidInput, "manifest object"))?;
        check_version(root)?;
        check_no_unknown(root, MANIFEST_FIELDS)?;
        if get_str(root, "kind")? != "tc03_final_object_manifest" {
            return Err(tc03_refuse(ErrorKind::InvalidInput, "kind"));
        }
        let objects = root
            .get("objects")
            .and_then(Value::as_array)
            .ok_or_else(|| tc03_refuse(ErrorKind::InvalidInput, "objects"))?;
        let mut out = Vec::with_capacity(objects.len());
        for object in objects {
            let entry = object
                .as_object()
                .ok_or_else(|| tc03_refuse(ErrorKind::InvalidInput, "object"))?;
            check_no_unknown(entry, ENTRY_FIELDS)?;
            let id = get_str(entry, "id")?;
            parse_label(id, "object id")?;
            if out.iter().any(|seen: &ObjectEntry| seen.id() == id) {
                return Err(tc03_refuse(ErrorKind::InvalidInput, "duplicate object id"));
            }
            let kind = ObjectKind::parse(get_str(entry, "kind")?)?;
            let path = bounded_text(entry, "path", 512)?;
            let sha256 = parse_sha256(get_str(entry, "sha256")?, "object sha256")?;
            let producer_name = bounded_text(entry, "producer_name", 128)?;
            let producer_version = bounded_text(entry, "producer_version", 128)?;
            let artifact = get_str(entry, "artifact")?;
            parse_label(artifact, "artifact")?;
            let profile = get_str(entry, "profile")?;
            ProfileId::parse(profile)
                .map_err(|_| tc03_refuse(ErrorKind::InvalidInput, "profile"))?;
            let isa_profile = get_str(entry, "isa_profile")?;
            parse_label(isa_profile, "isa_profile")?;
            let isa_version = bounded_text(entry, "isa_version", 64)?;
            let license_declared = match entry.get("license_declared") {
                None | Some(Value::Null) => None,
                Some(Value::String(text)) => {
                    if text.is_empty() || text.len() > 128 {
                        return Err(tc03_refuse(ErrorKind::InvalidInput, "license_declared"));
                    }
                    Some(text.clone())
                }
                Some(_) => return Err(tc03_refuse(ErrorKind::InvalidInput, "license_declared")),
            };
            out.push(ObjectEntry {
                id: ArtifactId::new(id.to_owned(), sha256),
                kind,
                path,
                producer_name,
                producer_version,
                artifact: artifact.to_owned(),
                profile: profile.to_owned(),
                isa_profile: isa_profile.to_owned(),
                isa_version,
                license_declared,
            });
        }
        Ok(Self { objects: out })
    }

    /// Admitted entries.
    pub fn objects(&self) -> &[ObjectEntry] {
        &self.objects
    }

    /// Number of admitted entries.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Whether the manifest holds no entries.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Find one entry by id.
    pub fn find(&self, id: &str) -> Option<&ObjectEntry> {
        self.objects.iter().find(|entry| entry.id() == id)
    }

    /// Bind presented bytes to exactly one inventoried id.
    ///
    /// Unknown ids refuse [`ErrorKind::InvalidInput`]; bytes whose hash
    /// differs from the entry refuse [`ErrorKind::Incompatible`]. The entry
    /// carries attribution only: kind, contract and profile refs are
    /// verified by `check_object` against the decoded inspection.
    pub fn admit(
        &self,
        id: &str,
        bytes: &[u8],
        limits: &Limits,
    ) -> Result<AdmittedObject<'_>, OperationError> {
        limits.validate()?;
        if bytes.len() > limits.input_bytes || bytes.len() > limits.retained_bytes {
            return Err(limited());
        }
        if bytes.len() as u64 > limits.work_steps {
            return Err(limited());
        }
        let entry = self
            .find(id)
            .ok_or_else(|| tc03_refuse(ErrorKind::InvalidInput, "uninventoried object id"))?;
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&Sha256::digest(bytes));
        if sha256 != *entry.sha256() {
            return Err(tc03_refuse(ErrorKind::Incompatible, "object hash mismatch"));
        }
        Ok(AdmittedObject { entry, sha256 })
    }
}

/// Bytes bound to one manifest entry by exact hash.
#[derive(Debug, Clone, Copy)]
pub struct AdmittedObject<'a> {
    entry: &'a ObjectEntry,
    sha256: [u8; 32],
}

impl<'a> AdmittedObject<'a> {
    /// The matched manifest entry.
    pub fn entry(&self) -> &'a ObjectEntry {
        self.entry
    }

    /// The matched entry identity.
    pub fn object_id(&self) -> &'a ArtifactId {
        self.entry.object_id()
    }

    /// Verified content hash of the presented bytes.
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}
