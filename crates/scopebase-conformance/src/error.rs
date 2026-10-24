// SPDX-License-Identifier: Apache-2.0
//! TT07 operator errors: typed refusals with stable exit codes.
//!
//! NEW (TT07): no donor lines copied.
//!
//! Exit contract (documented in `docs/conformance.md`):
//!
//! | Exit | Meaning |
//! |---|---|
//! | 0 | success: describe/plan emitted, run qualified, receipt valid, cleanup done |
//! | 1 | verdict failure: cases failed, receipt invalid or tampered |
//! | 2 | usage error: bad argv, unknown flags or mapping policy |
//! | 3 | incomplete: missing input, unknown profile, no bound adapter, refused cleanup |
//! | 64 | broken package: tampered closure, missing notices, subject mismatch |

/// Success: the requested operator action completed.
pub const EXIT_OK: i32 = 0;
/// Verdict failure: executed work failed or a receipt is invalid.
pub const EXIT_FAILURE: i32 = 1;
/// CLI usage error.
pub const EXIT_USAGE: i32 = 2;
/// Incomplete: a required input, profile or binding is missing.
pub const EXIT_INCOMPLETE: i32 = 3;
/// Broken package: tampered bytes, missing notices or mismatched subject.
pub const EXIT_BROKEN_PACKAGE: i32 = 64;
/// Marker carried by `describe`/`plan` outputs: they perform no evaluation
/// and claim no behavioral support.
pub const NO_QUALIFICATION: &str = "not_evaluated";

/// Machine-stable operator failure kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorErrorKind {
    /// Bad command line or unknown option value.
    Usage,
    /// A required input path cannot be read.
    MissingInput,
    /// Fixture closure files are absent (run refused before any effect).
    ClosureIncomplete,
    /// Closure bytes, notices or bindings do not match their pins.
    BrokenPackage,
    /// The linked adapter's subject does not match the template coordinates.
    SubjectMismatch,
    /// The requested profile is not in the supplied catalog.
    UnknownProfile,
    /// No contract template binds the requested profile to this adapter.
    NoBoundAdapter,
    /// The testkit engine rejected the run.
    Engine,
    /// A receipt is malformed, tampered or internally inconsistent.
    ReceiptInvalid,
    /// A cleanup target is not an identity-checked run directory.
    CleanupRefused,
    /// R04: a report or usage line could not be written to its stream.
    OutputFailed,
    /// S42: a failed run left effects that rollback could not remove;
    /// the detail names the path and the blocking cause. Neither
    /// retry (the name exists) nor cleanup (no valid manifest) owns
    /// it — an operator must inspect and remove it by hand.
    UnresolvedCustody,
}

/// A typed operator refusal with a human-readable detail.
#[derive(Clone, Debug)]
pub struct OperatorError {
    kind: OperatorErrorKind,
    detail: String,
}

impl OperatorError {
    /// Build a typed refusal.
    pub fn new(kind: OperatorErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    /// The machine-stable failure kind.
    pub fn kind(&self) -> OperatorErrorKind {
        self.kind
    }

    /// Human-readable detail (bounded by the caller).
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// The stable process exit code for this refusal.
    pub fn exit_code(&self) -> i32 {
        exit_for_kind(self.kind)
    }
}

impl std::fmt::Display for OperatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for OperatorError {}

/// Map a failure kind to its stable exit code.
pub fn exit_for_kind(kind: OperatorErrorKind) -> i32 {
    match kind {
        OperatorErrorKind::Usage => EXIT_USAGE,
        OperatorErrorKind::MissingInput
        | OperatorErrorKind::ClosureIncomplete
        | OperatorErrorKind::UnknownProfile
        | OperatorErrorKind::NoBoundAdapter
        | OperatorErrorKind::CleanupRefused => EXIT_INCOMPLETE,
        OperatorErrorKind::BrokenPackage | OperatorErrorKind::SubjectMismatch => {
            EXIT_BROKEN_PACKAGE
        }
        OperatorErrorKind::Engine
        | OperatorErrorKind::ReceiptInvalid
        | OperatorErrorKind::OutputFailed
        | OperatorErrorKind::UnresolvedCustody => EXIT_FAILURE,
    }
}
