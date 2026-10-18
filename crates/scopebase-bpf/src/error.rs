// SPDX-License-Identifier: Apache-2.0
//! Caller-classified errors for operations without retained partial owners.
use std::{error::Error, fmt};

/// Operation classification supplied by the caller, independent of errno.
///
/// Variant ordering and numeric discriminants are not a wire contract.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidInput,
    Malformed,
    Incompatible,
    Unsupported,
    Denied,
    Disappeared,
    Changed,
    LimitExceeded,
    Overflow,
    Backend,
    Poisoned,
}

/// The operation stage supplied by the caller.
///
/// Variant ordering and numeric discriminants are not a wire contract.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Admission,
    Metadata,
    Allocate,
    Read,
    Attach,
    Drain,
    Retire,
    BtfQuery,
    Compile,
    Inspect,
    Execute,
}

/// Lossless error transport without native-resource authority.
///
/// The kind, stage, errno and original source remain independent. There is no
/// errno classifier or inference from the source. Effectful operations with
/// partial owners must return their explicit owner-bearing result types.
///
/// Display and Debug emit at most 256 ASCII bytes and never format the source,
/// including alternate formatting. Diagnostics are human text, not a schema.
/// Explicit source traversal/downcasting and source creation/drop may execute
/// caller code and have no library time or memory guarantee.
///
/// The error is Send + Sync and move-only, with no Clone or Default.
/// ```compile_fail,E0599
/// use scopebase_bpf::{ErrorKind, OperationError, Stage};
/// let error = OperationError::new(ErrorKind::Backend, Stage::Read, None, None);
/// let duplicate = error.clone();
/// ```
pub struct OperationError {
    kind: ErrorKind,
    stage: Stage,
    raw_errno: Option<i32>,
    source: Option<Box<dyn Error + Send + Sync>>,
    required_size: Option<usize>,
}

impl OperationError {
    /// Store exactly the caller's classification, optional errno and source.
    ///
    /// Even zero, negative or unknown errno values are preserved. Disagreement
    /// with a source errno is not reconciled; this carrier verifies no evidence.
    /// The byte requirement starts absent. Moving the box preserves its pointee.
    pub fn new(
        kind: ErrorKind,
        stage: Stage,
        raw_errno: Option<i32>,
        source: Option<Box<dyn Error + Send + Sync>>,
    ) -> Self {
        Self {
            kind,
            stage,
            raw_errno,
            source,
            required_size: None,
        }
    }

    /// Return the caller-supplied classification.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
    /// Return the caller-supplied operation stage.
    pub fn stage(&self) -> Stage {
        self.stage
    }
    /// Return the verbatim caller-supplied errno, without source inference.
    pub fn raw_os_error(&self) -> Option<i32> {
        self.raw_errno
    }
    /// Return an operation-supplied byte requirement, if present.
    pub fn required_size(&self) -> Option<usize> {
        self.required_size
    }
    /// Replace the byte requirement, preserving all other fields and the source.
    ///
    /// Zero and `usize::MAX` are retained. This report authorizes no allocation.
    pub fn with_required_size(mut self, required: usize) -> Self {
        self.required_size = Some(required);
        self
    }
}

impl fmt::Display for OperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "scopebase-bpf {:?}/{:?}", self.stage, self.kind)?;
        if let Some(errno) = self.raw_errno {
            write!(f, " (os error {errno})")?;
        }
        if let Some(required) = self.required_size {
            write!(f, " (required bytes {required})")?;
        }
        Ok(())
    }
}

impl fmt::Debug for OperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)?;
        write!(f, " source_present={}", self.source.is_some())
    }
}

impl Error for OperationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}
