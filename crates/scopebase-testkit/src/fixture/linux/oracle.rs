// SPDX-License-Identifier: Apache-2.0
//! Ported donor oracle facets for the TT03 first increment.
//!
//! Grant: OWNER-2026-10-23 (user-owned donor slices to Apache-2.0).
//!
//! | Facet | Donor slice | Disposition |
//! |---|---|---|
//! | TT03-SF-06 `exited_unreaped` | P `src/process.rs:2343-2367` @ `2c2713e66292b0d2688508a25f79e813ae823d81` | ADAPT: finite EINTR budget, rustix waitid, no raw-PID reacquisition |
//! | TT03-SF-09 generation vectors | P `src/process.rs:1555-1617` @ `2c2713e6` | VECTORS_ONLY: literal Current/Reused/Exited + Interrupted/denied/missing counterexamples |
//! | TT03-SF-10 absence vectors | P `src/process.rs:1745-1760` @ `2c2713e6` | VECTORS_ONLY: NotFound differs from denied/malformed/live |
//! | TT03-SF-11 tricky comm | P `src/process.rs:1883-1917` @ `2c2713e6` | ADAPT: same literal name + live/zombie/reaped birth invariant, owned worker naming |
//!
//! SF-07 lifecycle order (P `src/process.rs:2381-2384,2388-2392,2396-2400,2404-2410`)
//! and SF-14 no-control (O `tests/target_lifecycle.rs:359-375` @ `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a`)
//! are preserved through the driver schedule and integration tests; see driver.rs.
//!
//! The collect/retire oracles below (`verify_retirement_exactly_once`,
//! `verify_unknown_sticky`, `clean_shutdown_gate`) are NEW: no donor
//! mechanism models TT02 Pending → Retired transitions, and the P
//! `ReapOnDrop` destructor is explicitly REFERENCE_ONLY (never copied).
//! They encode frozen r4 `Native ownership, errors and retirement` §280-375.
use crate::{EffectBatch, EffectRegistration, EffectTransition, Label, PendingEffectRef};
use std::fmt;
use std::io;

/// Exact tricky comm from SF-11: nine bytes `a) Z 1 (b`.
pub const TRICKY_COMM: &str = "a) Z 1 (b";
/// Lowercase hex of [`TRICKY_COMM`]: `6129205a2031202862`.
pub const TRICKY_COMM_HEX: &str = "6129205a2031202862";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleError {
    detail: String,
}
impl OracleError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
    pub fn detail(&self) -> &str {
        &self.detail
    }
}
impl fmt::Display for OracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "oracle: {}", self.detail)
    }
}
impl std::error::Error for OracleError {}

/// Original-owned-child WNOWAIT witness (SF-06, adapted).
///
/// `Some(si_code)` once the owned child has exited but is unreaped,
/// `None` while it still runs. EINTR retries are bounded by
/// `max_attempts`; there is no unbounded loop and no wait-any fallback.
/// Reaped or foreign PIDs surface the kernel errno (ECHILD after the
/// exact recorded reap).
pub fn exited_unreaped_owned(pid: u32, max_attempts: u32) -> io::Result<Option<i32>> {
    if max_attempts == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "max_attempts must be positive",
        ));
    }
    let raw = i32::try_from(pid)
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))?;
    let target = rustix::process::Pid::from_raw(raw).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "pid must be positive")
    })?;
    let options = rustix::process::WaitIdOptions::EXITED
        | rustix::process::WaitIdOptions::NOHANG
        | rustix::process::WaitIdOptions::NOWAIT;
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        match rustix::process::waitid(rustix::process::WaitId::Pid(target), options) {
            Ok(None) => return Ok(None),
            Ok(Some(status)) => return Ok(Some(status.raw_code())),
            Err(rustix::io::Errno::INTR) if attempts < max_attempts => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

/// Classified original-generation evidence (SF-09, vectors only).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationState {
    Current,
    Reused,
    Exited,
}

/// Independent generation oracle over the SF-09 counterexample vectors.
///
/// `exited` is the original pidfd poll outcome when one was taken,
/// `retained` the birth captured at spawn, `read_current` the fresh
/// same-generation read. A live pidfd decides Current without reading;
/// an exited pidfd decides Exited even for a same-generation zombie;
/// otherwise equal birth is Current, changed birth Reused, NotFound
/// Exited, and every other failure (including missing retained birth)
/// stays an error, never exit proof.
pub fn generation_of(
    exited: Option<io::Result<bool>>,
    retained: Option<u64>,
    read_current: impl FnOnce() -> io::Result<u64>,
) -> Result<GenerationState, OracleError> {
    match exited {
        Some(Ok(false)) => return Ok(GenerationState::Current),
        Some(Ok(true)) => return Ok(GenerationState::Exited),
        Some(Err(e)) => {
            return Err(OracleError::new(format!(
                "pidfd poll kept its error: {}",
                e.kind().as_str()
            )))
        }
        None => {}
    }
    let Some(retained) = retained else {
        return Err(OracleError::new("missing retained start time is unknown, never exit"));
    };
    match read_current() {
        Ok(current) => Ok(if current == retained {
            GenerationState::Current
        } else {
            GenerationState::Reused
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(GenerationState::Exited),
        Err(e) => Err(OracleError::new(format!(
            "current read kept its error: {}",
            e.kind().as_str()
        ))),
    }
}

trait KindStr {
    fn as_str(&self) -> &'static str;
}
impl KindStr for io::ErrorKind {
    fn as_str(&self) -> &'static str {
        match self {
            io::ErrorKind::NotFound => "not_found",
            io::ErrorKind::PermissionDenied => "permission_denied",
            io::ErrorKind::Interrupted => "interrupted",
            _ => "other",
        }
    }
}

/// Only a missing process proves exit (SF-10, vectors only).
///
/// `Ok` (live birth), EACCES refusal and malformed-stat errors are not
/// exit; only NotFound is.
pub fn gone_from_result(read: &io::Result<u64>) -> bool {
    matches!(read, Err(e) if e.kind() == io::ErrorKind::NotFound)
}

/// Final-delimiter stat parse: comm between the first `(` and the LAST
/// `)`, then state plus starttime from fixed post-comm positions
/// (SF-11 oracle shape). Returns `(comm, state, starttime_ticks)`.
pub fn parse_stat_comm_state_starttime(stat: &[u8]) -> Result<(Vec<u8>, u8, u64), OracleError> {
    let open = stat
        .iter()
        .position(|b| *b == b'(')
        .ok_or_else(|| OracleError::new("stat lacks comm open delimiter"))?;
    let close = stat
        .iter()
        .rposition(|b| *b == b')')
        .ok_or_else(|| OracleError::new("stat lacks comm close delimiter"))?;
    if close <= open {
        return Err(OracleError::new("stat comm delimiters cross"));
    }
    let comm = stat[open + 1..close].to_vec();
    let rest: Vec<&[u8]> = stat[close + 1..].split(|b| b.is_ascii_whitespace()).collect();
    let rest: Vec<&[u8]> = rest.into_iter().filter(|f| !f.is_empty()).collect();
    if rest.len() < 20 {
        return Err(OracleError::new("stat has too few post-comm fields"));
    }
    if rest[0].len() != 1 {
        return Err(OracleError::new("stat state is not one byte"));
    }
    let start = std::str::from_utf8(rest[19])
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| OracleError::new("stat starttime is not decimal"))?;
    Ok((comm, rest[0][0], start))
}

/// True only for actual zombie state, never for a live fake-Z comm.
pub fn stat_is_zombie(stat: &[u8]) -> Result<bool, OracleError> {
    Ok(parse_stat_comm_state_starttime(stat)?.1 == b'Z')
}

/// Exactly-once retirement accounting across Prepare/Collect/Retire.
///
/// Every registration id may be returned exactly once across the three
/// sources; every transition must reference a registered id with an
/// exactly matching [`PendingEffectRef`] (owner, origin and identity),
/// and no resource may transition twice. Mirrors the runner ledger's
/// `response` checks without requiring a live run.
pub fn verify_retirement_exactly_once(
    prepare: &EffectBatch,
    collect: &EffectBatch,
    discovered: &[EffectRegistration],
    transitions: &[EffectTransition],
) -> Result<(), OracleError> {
    let mut seen: Vec<(&Label, &EffectRegistration)> = Vec::new();
    for registration in prepare
        .registrations()
        .iter()
        .chain(collect.registrations().iter())
        .chain(discovered.iter())
    {
        if seen.iter().any(|(id, _)| *id == registration.resource_id()) {
            return Err(OracleError::new(format!(
                "registration {} returned more than once",
                registration.resource_id().as_str()
            )));
        }
        seen.push((registration.resource_id(), registration));
    }
    let mut transitioned: Vec<&Label> = Vec::new();
    for transition in transitions {
        let pending = transition.effect();
        let Some((_, original)) = seen.iter().find(|(id, _)| *id == pending.resource_id()) else {
            return Err(OracleError::new(format!(
                "transition {} references unregistered {}",
                transition.transition_id().as_str(),
                pending.resource_id().as_str()
            )));
        };
        if PendingEffectRef::registration(original) != *pending {
            return Err(OracleError::new(format!(
                "transition {} identity mismatch for {}",
                transition.transition_id().as_str(),
                pending.resource_id().as_str()
            )));
        }
        if transitioned.contains(&pending.resource_id()) {
            return Err(OracleError::new(format!(
                "resource {} transitioned more than once",
                pending.resource_id().as_str()
            )));
        }
        transitioned.push(pending.resource_id());
    }
    Ok(())
}

/// Unknown inventory is sticky: later reports may add labels but must
/// never clear an earlier unknown, even after known owners settle.
pub fn verify_unknown_sticky(prior: &[Label], next: &[Label]) -> Result<(), OracleError> {
    let cleared: Vec<&str> = prior
        .iter()
        .filter(|id| !next.contains(id))
        .map(Label::as_str)
        .collect();
    if cleared.is_empty() {
        Ok(())
    } else {
        Err(OracleError::new(format!(
            "unknown inventory cleared: {}",
            cleared.join(",")
        )))
    }
}

/// A claimed shutdown custody outcome for the clean-shutdown gate.
#[derive(Clone, Debug)]
pub struct CustodyClaim {
    /// An actual retirement report exists (not Drop-only silence).
    pub retired_report: bool,
    /// The claim rests only on an exit status, without per-owner proof.
    pub exit_status_only: bool,
    /// Removal proof is relative to the original retained root.
    pub original_root: bool,
    /// Owners are the original retained owners, not reopened substitutes.
    pub original_owners: bool,
    /// Registered resource ids.
    pub registered: Vec<Label>,
    /// Transitioned (Pending → Retired) resource ids.
    pub transitioned: Vec<Label>,
    /// Sticky unknown inventory labels.
    pub unknown: Vec<Label>,
    /// Retained (owner, errno) cleanup errors.
    pub cleanup_errors: Vec<(String, i32)>,
}

/// The frozen clean-shutdown gate: all original owners/created names
/// settled, no cleanup errors and no sticky unknown inventory. Each
/// custody-fail mutant violates exactly one predicate and fails with
/// its own diagnostic.
pub fn clean_shutdown_gate(claim: &CustodyClaim) -> Result<(), OracleError> {
    if claim.exit_status_only {
        return Err(OracleError::new(
            "exit status is not custody proof".to_string(),
        ));
    }
    if !claim.retired_report {
        return Err(OracleError::new(
            "no retirement report: Drop-only is failed shutdown".to_string(),
        ));
    }
    if !claim.original_root {
        return Err(OracleError::new(
            "foreign root: removal proof is not relative to the original retained root".to_string(),
        ));
    }
    if !claim.original_owners {
        return Err(OracleError::new(
            "substituted owner: original retained owner required".to_string(),
        ));
    }
    if !claim.cleanup_errors.is_empty() {
        let names: Vec<String> = claim
            .cleanup_errors
            .iter()
            .map(|(owner, errno)| format!("{owner}:{errno}"))
            .collect();
        return Err(OracleError::new(format!(
            "cleanup errors retained: {}",
            names.join(",")
        )));
    }
    if !claim.unknown.is_empty() {
        let names: Vec<&str> = claim.unknown.iter().map(Label::as_str).collect();
        return Err(OracleError::new(format!(
            "sticky unknown inventory: {}",
            names.join(",")
        )));
    }
    let unsettled: Vec<&str> = claim
        .registered
        .iter()
        .filter(|id| !claim.transitioned.contains(id))
        .map(Label::as_str)
        .collect();
    if claim.transitioned.is_empty() && !claim.registered.is_empty() {
        return Err(OracleError::new(format!(
            "cleanup skipped: {} registered owners, zero transitioned",
            claim.registered.len()
        )));
    }
    if !unsettled.is_empty() {
        return Err(OracleError::new(format!(
            "unsettled owners: {}",
            unsettled.join(",")
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CaseKey, CaseKeyValues, Digest256, EffectBatch, EffectBatchValues, EffectRegistration,
        EffectRegistrationValues, EffectTransition, EffectTransitionValues, InvocationKey,
        InvocationKeyValues, Label, Owner, PendingEffectRef, PendingEffectRefValues, RunId,
        RunLimits, TransitionTo,
    };
    use std::cell::Cell;

    fn test_key(operation_id: u64) -> InvocationKey {
        let limits = RunLimits::default();
        InvocationKey::new(
            InvocationKeyValues {
                run_id: RunId::parse("0123456789abcdef0123456789abcdef").unwrap(),
                case_key: CaseKey::new(
                    CaseKeyValues {
                        case_id: crate::CaseId::parse("TT03.retire").unwrap(),
                        case_version: 1,
                        cell_id: "host".to_string(),
                    },
                    &limits,
                )
                .unwrap(),
                attempt: 1,
                operation_id,
            },
            &limits,
        )
        .unwrap()
    }

    fn test_reg(id: &str, origin: &InvocationKey, identity: &[u8]) -> EffectRegistration {
        let limits = RunLimits::default();
        EffectRegistration::new(
            EffectRegistrationValues {
                resource_id: Label::parse(id).unwrap(),
                owner: Owner::Fixture,
                origin: origin.clone(),
                kind: Label::parse("linux-test").unwrap(),
                identity_sha256: Digest256::of_bytes(identity),
                recovery_evidence_id: None,
            },
            &limits,
        )
        .unwrap()
    }

    fn test_batch(ids: &[(&str, &InvocationKey, &[u8])]) -> EffectBatch {
        let limits = RunLimits::default();
        let mut registrations: Vec<EffectRegistration> = ids
            .iter()
            .map(|(id, origin, identity)| test_reg(id, origin, identity))
            .collect();
        registrations.sort_by(|a, b| a.resource_id().cmp(b.resource_id()));
        EffectBatch::new(
            EffectBatchValues {
                registrations,
                complete: true,
            },
            &limits,
        )
        .unwrap()
    }

    fn test_ref_of(registration: &EffectRegistration) -> PendingEffectRef {
        let limits = RunLimits::default();
        PendingEffectRef::new(
            PendingEffectRefValues {
                resource_id: registration.resource_id().clone(),
                owner: *registration.owner(),
                origin: registration.origin().clone(),
                identity_sha256: *registration.identity_sha256(),
            },
            &limits,
        )
        .unwrap()
    }

    fn test_transition(tid: &str, effect: PendingEffectRef, evidence: &[&str]) -> EffectTransition {
        let limits = RunLimits::default();
        let mut evidence_ids: Vec<Label> =
            evidence.iter().map(|e| Label::parse(e).unwrap()).collect();
        evidence_ids.sort();
        EffectTransition::new(
            EffectTransitionValues {
                transition_id: Label::parse(tid).unwrap(),
                effect,
                to: TransitionTo::Retired,
                evidence_ids,
            },
            &limits,
        )
        .unwrap()
    }

    fn clean_claim() -> CustodyClaim {
        CustodyClaim {
            retired_report: true,
            exit_status_only: false,
            original_root: true,
            original_owners: true,
            registered: vec![Label::parse("linux.case-root").unwrap()],
            transitioned: vec![Label::parse("linux.case-root").unwrap()],
            unknown: vec![],
            cleanup_errors: vec![],
        }
    }

    #[test]
    fn tricky_literal_bytes() {
        assert_eq!(TRICKY_COMM.as_bytes().len(), 9);
        let mut hex = String::new();
        for b in TRICKY_COMM.as_bytes() {
            hex.push_str(&format!("{b:02x}"));
        }
        assert_eq!(hex, TRICKY_COMM_HEX);
        assert_eq!(TRICKY_COMM_HEX, "6129205a2031202862");
    }

    #[test]
    fn generation_vectors_current_reused_exited() {
        let reads = Cell::new(0);
        assert_eq!(
            generation_of(Some(Ok(false)), None, || {
                reads.set(reads.get() + 1);
                Ok(10)
            })
            .unwrap(),
            GenerationState::Current
        );
        assert_eq!(reads.get(), 0, "a live pidfd needs no current read");
        assert_eq!(
            generation_of(None, Some(10), || Ok(10)).unwrap(),
            GenerationState::Current
        );
        assert_eq!(
            generation_of(None, Some(10), || Ok(11)).unwrap(),
            GenerationState::Reused
        );
        assert_eq!(
            generation_of(None, Some(10), || Err(io::Error::from(
                io::ErrorKind::NotFound
            )))
            .unwrap(),
            GenerationState::Exited
        );
        assert_eq!(
            generation_of(Some(Ok(true)), Some(10), || Ok(10)).unwrap(),
            GenerationState::Exited,
            "same-generation zombie with exited pidfd is exited"
        );
    }

    #[test]
    fn generation_vectors_keep_errors_and_missing() {
        assert_eq!(
            generation_of(
                Some(Err(io::Error::from(io::ErrorKind::Interrupted))),
                Some(10),
                || Ok(10)
            )
            .unwrap_err()
            .detail(),
            "pidfd poll kept its error: interrupted"
        );
        assert_eq!(
            generation_of(None, Some(10), || Err(io::Error::from(
                io::ErrorKind::PermissionDenied
            )))
            .unwrap_err()
            .detail(),
            "current read kept its error: permission_denied"
        );
        assert_eq!(
            generation_of(None, None, || Ok(10)).unwrap_err().detail(),
            "missing retained start time is unknown, never exit"
        );
    }

    #[test]
    fn absence_vectors() {
        assert!(gone_from_result(&Err(io::Error::from(io::ErrorKind::NotFound))));
        assert!(!gone_from_result(&Ok(12345)));
        assert!(!gone_from_result(&Err(io::Error::from_raw_os_error(13))));
        assert!(!gone_from_result(&Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stat comm"
        ))));
        assert!(!gone_from_result(&Err(io::Error::from(
            io::ErrorKind::PermissionDenied
        ))));
    }

    #[test]
    fn stat_parser_vectors() {
        let live = b"4242 (a) Z 1 (b) R 1 1 1 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 987654 100 200";
        let (comm, state, start) = parse_stat_comm_state_starttime(live).unwrap();
        assert_eq!(comm, b"a) Z 1 (b");
        assert_eq!(state, b'R');
        assert_eq!(start, 987654);
        assert!(!stat_is_zombie(live).unwrap());
        let zombie =
            b"4242 (a) Z 1 (b) Z 1 1 1 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 987654 100 200";
        assert!(stat_is_zombie(zombie).unwrap());
        assert_eq!(
            parse_stat_comm_state_starttime(zombie).unwrap().2,
            987654
        );
        assert!(parse_stat_comm_state_starttime(b"12 (oops R 1 2").is_err());
        assert!(parse_stat_comm_state_starttime(b"12 (ok) R 1").is_err());
        assert!(parse_stat_comm_state_starttime(
            b"12 (ok) R 1 1 1 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 nope 1 2"
        )
        .is_err());
        let nested = b"7 ((x)) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 42 1 2";
        assert_eq!(parse_stat_comm_state_starttime(nested).unwrap().0, b"(x)");
    }

    #[test]
    fn wnowait_rejects_bad_inputs() {
        assert_eq!(
            exited_unreaped_owned(0, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            exited_unreaped_owned(1, 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            exited_unreaped_owned(u32::MAX, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn retirement_exactly_once_accepts_split_batches() {
        let key = test_key(1);
        let prepare = test_batch(&[
            ("linux.case-root", &key, b"root"),
            ("linux.child-a", &key, b"a"),
        ]);
        let collect = test_batch(&[]);
        let extra = test_reg("linux.inventory-positive", &key, b"inv");
        let transitions = vec![
            test_transition(
                "linux.retire.1.case-root",
                test_ref_of(&prepare.registrations()[0]),
                &["linux.proof.1.case-root"],
            ),
            test_transition(
                "linux.retire.1.child-a",
                test_ref_of(&prepare.registrations()[1]),
                &["linux.proof.1.child-a"],
            ),
            test_transition(
                "linux.retire.1.inventory-positive",
                test_ref_of(&extra),
                &["linux.proof.1.inventory-positive"],
            ),
        ];
        verify_retirement_exactly_once(&prepare, &collect, &[extra], &transitions).unwrap();
    }

    #[test]
    fn retirement_exactly_once_rejects_duplicate_registration() {
        let key = test_key(1);
        let prepare = test_batch(&[("linux.child-a", &key, b"a")]);
        let collect = test_batch(&[("linux.child-a", &key, b"a")]);
        let err = verify_retirement_exactly_once(&prepare, &collect, &[], &[]).unwrap_err();
        assert!(
            err.detail().contains("more than once") && err.detail().contains("linux.child-a"),
            "duplicate registration fails exactly-once: {}",
            err.detail()
        );
    }

    #[test]
    fn retirement_exactly_once_rejects_rediscovered_registration() {
        let key = test_key(1);
        let prepare = test_batch(&[("linux.child-a", &key, b"a")]);
        let collect = test_batch(&[]);
        let dup = test_reg("linux.child-a", &key, b"a");
        let err = verify_retirement_exactly_once(&prepare, &collect, &[dup], &[]).unwrap_err();
        assert!(
            err.detail().contains("more than once"),
            "rediscovery of a prepared id fails: {}",
            err.detail()
        );
    }

    #[test]
    fn retirement_exactly_once_rejects_unknown_transition() {
        let key = test_key(1);
        let prepare = test_batch(&[("linux.child-a", &key, b"a")]);
        let collect = test_batch(&[]);
        let ghost = test_reg("linux.ghost", &key, b"g");
        let transition = test_transition(
            "linux.retire.1.ghost",
            test_ref_of(&ghost),
            &["linux.proof.1.ghost"],
        );
        let err =
            verify_retirement_exactly_once(&prepare, &collect, &[], &[transition]).unwrap_err();
        assert!(
            err.detail().contains("unregistered"),
            "unknown transition resource fails: {}",
            err.detail()
        );
    }

    #[test]
    fn retirement_exactly_once_rejects_substituted_identity() {
        let key = test_key(1);
        let prepare = test_batch(&[("linux.child-a", &key, b"a")]);
        let collect = test_batch(&[]);
        let limits = RunLimits::default();
        let substituted = PendingEffectRef::new(
            PendingEffectRefValues {
                resource_id: Label::parse("linux.child-a").unwrap(),
                owner: Owner::Fixture,
                origin: key.clone(),
                identity_sha256: Digest256::of_bytes(b"reopened-substitute"),
            },
            &limits,
        )
        .unwrap();
        let transition = test_transition(
            "linux.retire.1.child-a",
            substituted,
            &["linux.proof.1.child-a"],
        );
        let err =
            verify_retirement_exactly_once(&prepare, &collect, &[], &[transition]).unwrap_err();
        assert!(
            err.detail().contains("identity mismatch"),
            "substituted identity fails: {}",
            err.detail()
        );
    }

    #[test]
    fn retirement_exactly_once_rejects_double_transition() {
        let key = test_key(1);
        let prepare = test_batch(&[("linux.child-a", &key, b"a")]);
        let collect = test_batch(&[]);
        let first = test_transition(
            "linux.retire.1.child-a",
            test_ref_of(&prepare.registrations()[0]),
            &["linux.proof.1.child-a"],
        );
        let second = test_transition(
            "linux.retire.1.child-a.again",
            test_ref_of(&prepare.registrations()[0]),
            &["linux.proof.1.child-a"],
        );
        let err =
            verify_retirement_exactly_once(&prepare, &collect, &[], &[first, second]).unwrap_err();
        assert!(
            err.detail().contains("more than once"),
            "double transition fails: {}",
            err.detail()
        );
    }

    #[test]
    fn unknown_inventory_is_sticky() {
        let prior = vec![Label::parse("linux.file-a").unwrap()];
        let grown = vec![
            Label::parse("linux.case-root").unwrap(),
            Label::parse("linux.file-a").unwrap(),
        ];
        verify_unknown_sticky(&[], &prior).unwrap();
        verify_unknown_sticky(&prior, &grown).unwrap();
        verify_unknown_sticky(&prior, &prior).unwrap();
        let err = verify_unknown_sticky(&prior, &[]).unwrap_err();
        assert!(
            err.detail().contains("cleared") && err.detail().contains("linux.file-a"),
            "cleared unknown fails stickiness: {}",
            err.detail()
        );
    }

    #[test]
    fn clean_shutdown_gate_accepts_settled_custody() {
        clean_shutdown_gate(&clean_claim()).unwrap();
    }

    #[test]
    fn clean_shutdown_gate_rejects_drop_only() {
        let mut claim = clean_claim();
        claim.retired_report = false;
        let err = clean_shutdown_gate(&claim).unwrap_err();
        assert!(
            err.detail().contains("no retirement report"),
            "drop-only fails custody: {}",
            err.detail()
        );
    }

    #[test]
    fn clean_shutdown_gate_rejects_exit_status_only() {
        let mut claim = clean_claim();
        claim.exit_status_only = true;
        let err = clean_shutdown_gate(&claim).unwrap_err();
        assert!(
            err.detail().contains("exit status is not custody proof"),
            "exit0-only fails custody: {}",
            err.detail()
        );
    }

    #[test]
    fn clean_shutdown_gate_rejects_skipped_cleanup() {
        let mut claim = clean_claim();
        claim.transitioned.clear();
        let err = clean_shutdown_gate(&claim).unwrap_err();
        assert!(
            err.detail().contains("cleanup skipped"),
            "skip-cleanup fails custody: {}",
            err.detail()
        );
    }

    #[test]
    fn clean_shutdown_gate_rejects_partial_cleanup() {
        let mut claim = clean_claim();
        claim
            .registered
            .push(Label::parse("linux.child-a").unwrap());
        let err = clean_shutdown_gate(&claim).unwrap_err();
        assert!(
            err.detail().contains("unsettled owners"),
            "partial cleanup fails custody: {}",
            err.detail()
        );
    }

    #[test]
    fn clean_shutdown_gate_rejects_substituted_owner() {
        let mut claim = clean_claim();
        claim.original_owners = false;
        let err = clean_shutdown_gate(&claim).unwrap_err();
        assert!(
            err.detail().contains("substituted owner"),
            "substituted owner fails custody: {}",
            err.detail()
        );
    }

    #[test]
    fn clean_shutdown_gate_rejects_foreign_root() {
        let mut claim = clean_claim();
        claim.original_root = false;
        let err = clean_shutdown_gate(&claim).unwrap_err();
        assert!(
            err.detail().contains("foreign root"),
            "foreign root fails custody: {}",
            err.detail()
        );
    }

    #[test]
    fn clean_shutdown_gate_rejects_unknown_and_errors() {
        let mut claim = clean_claim();
        claim.unknown.push(Label::parse("linux.file-a").unwrap());
        let err = clean_shutdown_gate(&claim).unwrap_err();
        assert!(
            err.detail().contains("unknown inventory"),
            "sticky unknown fails the gate: {}",
            err.detail()
        );
        let mut errors = clean_claim();
        errors.cleanup_errors.push(("linux.child-a".to_string(), 5));
        let err = clean_shutdown_gate(&errors).unwrap_err();
        assert!(
            err.detail().contains("cleanup errors"),
            "cleanup errors fail the gate: {}",
            err.detail()
        );
    }
}
