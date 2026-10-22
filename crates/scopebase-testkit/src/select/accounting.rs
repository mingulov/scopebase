// SPDX-License-Identifier: Apache-2.0
//! TT08 scheduling/accounting records: executed-vs-plan accounting and the
//! retry qualification gate.
//!
//! [`RunAccounting`] derives selected/declared cells from the actual
//! selection: unchanged required gates are enumerated explicitly with their
//! inherited evidence, and `full_matrix_complete` holds only after the
//! complete declared denominator executes. Status (work done) and scope
//! (full vs narrowed) are separate assertions; a narrowed run can be complete
//! without completing the matrix. [`attest_complete`](RunAccounting::attest_complete)
//! rejects falsely claimed full results.
//!
//! [`qualification_gate`] keeps retry semantics honest: a semantic failure
//! stays unresolved until an explicit cause/fix/new-candidate resolution is
//! recorded and a later passing attempt evidences the resolved candidate; a
//! history with zero passes never resolves. Infrastructure retries retain
//! their attempt history without erasing semantic failures.

use super::selector::{CellKey, SelectionPlan};
use std::collections::{BTreeMap, BTreeSet};
use std::{error::Error, fmt};

/// Selected-work execution status. `Complete` means every selected cell
/// executed; it says nothing about unselected denominator cells.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountingStatus {
    Complete,
    Incomplete,
}

/// Selection scope relative to the declared denominator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountingScope {
    Full,
    Narrowed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountingErrorKind {
    InvalidEvidence,
    IncompleteDenominator,
}

#[derive(Debug)]
pub struct AccountingError(pub(crate) AccountingErrorKind);

impl AccountingError {
    pub fn kind(&self) -> AccountingErrorKind {
        self.0
    }
}

impl fmt::Display for AccountingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "accounting rejected: {:?}", self.0)
    }
}

impl Error for AccountingError {}

/// Reference to inherited evidence (e.g. a prior receipt id) covering one
/// unchanged required cell. The reference is opaque: accounting checks
/// presence, never validity, which stays with the evidence owner.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct EvidenceRef(String);

impl EvidenceRef {
    pub fn new(label: &str) -> Result<Self, AccountingError> {
        if label.is_empty() || label.len() > 4096 {
            return Err(AccountingError(AccountingErrorKind::InvalidEvidence));
        }
        Ok(Self(label.to_owned()))
    }
    pub fn label(&self) -> &str {
        &self.0
    }
}

/// Executed-vs-plan accounting for one selection. All lists sorted.
#[derive(Debug)]
pub struct RunAccounting {
    declared: Vec<CellKey>,
    selected: Vec<CellKey>,
    executed_selected: Vec<CellKey>,
    missing_selected: Vec<CellKey>,
    unchanged_with_evidence: Vec<(CellKey, EvidenceRef)>,
    unchanged_missing_evidence: Vec<CellKey>,
    unexpected_executed: Vec<CellKey>,
    has_unresolved: bool,
    status: AccountingStatus,
    scope: AccountingScope,
    full_matrix_complete: bool,
}

impl RunAccounting {
    /// Account `executed` results and `inherited` evidence against `plan`.
    /// `executed` cells outside the plan are reported as unexpected; they
    /// never contribute to completeness.
    pub fn account(
        plan: &SelectionPlan,
        executed: &BTreeSet<CellKey>,
        inherited: &BTreeMap<CellKey, EvidenceRef>,
    ) -> Self {
        let declared: BTreeSet<&CellKey> = plan.declared().iter().collect();
        let selected: BTreeSet<&CellKey> =
            plan.selected().iter().map(|c| c.key()).collect();
        let executed_selected: Vec<CellKey> = selected
            .intersection(&executed.iter().collect())
            .map(|k| (*k).clone())
            .collect();
        let missing_selected: Vec<CellKey> = selected
            .difference(&executed.iter().collect())
            .map(|k| (*k).clone())
            .collect();
        let mut unchanged_with_evidence = Vec::new();
        let mut unchanged_missing_evidence = Vec::new();
        for key in declared.difference(&selected) {
            match inherited.get(*key) {
                Some(reference) => {
                    unchanged_with_evidence.push(((*key).clone(), reference.clone()));
                }
                None => unchanged_missing_evidence.push((*key).clone()),
            }
        }
        let planned: BTreeSet<&CellKey> = declared.union(&selected).copied().collect();
        let unexpected_executed: Vec<CellKey> = executed
            .iter()
            .filter(|k| !planned.contains(*k))
            .cloned()
            .collect();
        let status = if missing_selected.is_empty() {
            AccountingStatus::Complete
        } else {
            AccountingStatus::Incomplete
        };
        let has_unresolved = plan.has_unresolved();
        // Full scope and full-matrix completion attest coverage of a real,
        // fully resolved required boundary: an empty denominator or any
        // unresolved (broadened) impact keeps the run narrowed and
        // incomplete-attested, never Full/complete. Only the complete
        // declared denominator executing sets the flag; a full selection
        // summary reused unchanged for a narrowed member run cannot set it,
        // because narrowed runs leave declared cells unexecuted.
        let resolved_nonempty = !declared.is_empty() && !has_unresolved;
        let scope = if resolved_nonempty && declared.iter().all(|k| selected.contains(*k)) {
            AccountingScope::Full
        } else {
            AccountingScope::Narrowed
        };
        let full_matrix_complete =
            resolved_nonempty && declared.iter().all(|k| executed.contains(*k));
        Self {
            declared: plan.declared().to_vec(),
            selected: plan.selected().iter().map(|c| c.key().clone()).collect(),
            executed_selected,
            missing_selected,
            unchanged_with_evidence,
            unchanged_missing_evidence,
            unexpected_executed,
            has_unresolved,
            status,
            scope,
            full_matrix_complete,
        }
    }

    pub fn declared(&self) -> &[CellKey] {
        &self.declared
    }
    pub fn selected(&self) -> &[CellKey] {
        &self.selected
    }
    pub fn executed_selected(&self) -> &[CellKey] {
        &self.executed_selected
    }
    pub fn missing_selected(&self) -> &[CellKey] {
        &self.missing_selected
    }
    pub fn unchanged_with_evidence(&self) -> &[(CellKey, EvidenceRef)] {
        &self.unchanged_with_evidence
    }
    pub fn unchanged_missing_evidence(&self) -> &[CellKey] {
        &self.unchanged_missing_evidence
    }
    pub fn unexpected_executed(&self) -> &[CellKey] {
        &self.unexpected_executed
    }
    /// Whether the accounted plan carried unresolved (broadened) impact.
    /// Unresolved runs never report [`AccountingScope::Full`] and never
    /// attest complete.
    pub fn has_unresolved(&self) -> bool {
        self.has_unresolved
    }
    pub fn status(&self) -> AccountingStatus {
        self.status
    }
    pub fn scope(&self) -> AccountingScope {
        self.scope
    }
    pub fn full_matrix_complete(&self) -> bool {
        self.full_matrix_complete
    }

    /// Attest full-matrix completion. Succeeds only when the plan is fully
    /// resolved over a nonempty denominator, every selected cell executed,
    /// and the complete declared denominator executed. A falsely claimed
    /// full result — including an empty or unresolved boundary attesting
    /// coverage of nothing or of the unknown — fails here.
    pub fn attest_complete(&self) -> Result<(), AccountingError> {
        if self.full_matrix_complete && self.missing_selected.is_empty() {
            Ok(())
        } else {
            Err(AccountingError(
                AccountingErrorKind::IncompleteDenominator,
            ))
        }
    }
}

/// One attempt's outcome. Semantic failures (wrong value, violated contract)
/// block qualification until explicitly resolved; infrastructure failures
/// (denied lease, provisioning) retain history without blocking once a later
/// attempt passes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptOutcome {
    Pass,
    SemanticFailure,
    InfrastructureFailure,
}

/// One recorded attempt: 1-based consecutive numbering, outcome, bounded
/// diagnostic detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptRecord {
    attempt: u32,
    outcome: AttemptOutcome,
    detail: String,
}

impl AttemptRecord {
    pub fn new(
        attempt: u32,
        outcome: AttemptOutcome,
        detail: &str,
    ) -> Result<Self, GateError> {
        if attempt == 0 || detail.len() > 4096 {
            return Err(GateError(GateErrorKind::InvalidAttempt));
        }
        Ok(Self {
            attempt,
            outcome,
            detail: detail.to_owned(),
        })
    }
    pub fn attempt(&self) -> u32 {
        self.attempt
    }
    pub fn outcome(&self) -> AttemptOutcome {
        self.outcome
    }
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Explicit reviewed resolution closing one semantic failure: its cause, the
/// fix, and the new candidate the fix was verified against. All three are
/// mandatory; an empty field cannot close a failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionRecord {
    failed_attempt: u32,
    cause: String,
    fix: String,
    new_candidate: String,
}

impl ResolutionRecord {
    pub fn new(
        failed_attempt: u32,
        cause: &str,
        fix: &str,
        new_candidate: &str,
    ) -> Result<Self, GateError> {
        if failed_attempt == 0
            || cause.len() > 4096
            || fix.len() > 4096
            || new_candidate.len() > 4096
        {
            return Err(GateError(GateErrorKind::InvalidAttempt));
        }
        Ok(Self {
            failed_attempt,
            cause: cause.to_owned(),
            fix: fix.to_owned(),
            new_candidate: new_candidate.to_owned(),
        })
    }
    pub fn failed_attempt(&self) -> u32 {
        self.failed_attempt
    }
    pub fn cause(&self) -> &str {
        &self.cause
    }
    pub fn fix(&self) -> &str {
        &self.fix
    }
    pub fn new_candidate(&self) -> &str {
        &self.new_candidate
    }
}

/// Retry gate verdict. `Resolved` retains the full attempt count; retries
/// never erase history. `Unresolved` names every attempt still blocking
/// qualification: semantic failures without a resolution, resolutions
/// without a later qualifying pass, and — when no pass exists at all —
/// every attempt of the pass-less history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GateVerdict {
    Resolved { attempts: usize },
    Unresolved { failed_attempts: Vec<u32> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateErrorKind {
    InvalidAttempt,
    HollowResolution,
    UnmatchedResolution,
}

#[derive(Debug)]
pub struct GateError(pub(crate) GateErrorKind);

impl GateError {
    pub fn kind(&self) -> GateErrorKind {
        self.0
    }
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "retry gate rejected: {:?}", self.0)
    }
}

impl Error for GateError {}

/// Evaluate attempt history against explicit resolutions. Attempts must be
/// numbered 1..=n in order; an empty history resolves nothing. Every semantic
/// failure needs a matching non-hollow resolution, and every resolution
/// needs a qualifying pass bound to the resolved candidate: a `Pass` attempt
/// numbered later than the failure, evidencing the fix (attempt numbering is
/// consecutive execution order, so a later number ran after the failure on
/// the putative new candidate). A resolution string with zero passes — a
/// lone infrastructure failure, or a failure closed only on paper — never
/// resolves. Resolutions must reference actual semantic failures.
pub fn qualification_gate(
    attempts: &[AttemptRecord],
    resolutions: &[ResolutionRecord],
) -> Result<GateVerdict, GateError> {
    if attempts.is_empty() {
        return Err(GateError(GateErrorKind::InvalidAttempt));
    }
    for (index, attempt) in attempts.iter().enumerate() {
        if attempt.attempt != (index as u32) + 1 {
            return Err(GateError(GateErrorKind::InvalidAttempt));
        }
    }
    let semantic: BTreeSet<u32> = attempts
        .iter()
        .filter(|a| a.outcome == AttemptOutcome::SemanticFailure)
        .map(|a| a.attempt)
        .collect();
    let passes: BTreeSet<u32> = attempts
        .iter()
        .filter(|a| a.outcome == AttemptOutcome::Pass)
        .map(|a| a.attempt)
        .collect();
    let mut resolved = BTreeSet::new();
    for resolution in resolutions {
        if resolution.cause.is_empty()
            || resolution.fix.is_empty()
            || resolution.new_candidate.is_empty()
        {
            return Err(GateError(GateErrorKind::HollowResolution));
        }
        if !semantic.contains(&resolution.failed_attempt) {
            return Err(GateError(GateErrorKind::UnmatchedResolution));
        }
        resolved.insert(resolution.failed_attempt);
    }
    let mut blocking: BTreeSet<u32> = semantic.difference(&resolved).copied().collect();
    for resolution in resolutions {
        if !passes.iter().any(|pass| *pass > resolution.failed_attempt) {
            blocking.insert(resolution.failed_attempt);
        }
    }
    if passes.is_empty() {
        blocking.extend(attempts.iter().map(|a| a.attempt));
    }
    let failed_attempts: Vec<u32> = blocking.into_iter().collect();
    if failed_attempts.is_empty() {
        Ok(GateVerdict::Resolved {
            attempts: attempts.len(),
        })
    } else {
        Ok(GateVerdict::Unresolved { failed_attempts })
    }
}
