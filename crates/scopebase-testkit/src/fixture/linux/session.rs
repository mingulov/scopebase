// SPDX-License-Identifier: Apache-2.0
//! TT03 Linux fixture session: exact public admission/custody/finalizer API.
//!
//! The constructor validates and adopts the caller files plus the externally
//! bound manifest, acquires the retained creator context, reserves the full
//! admitted roster and one 1MiB terminal slot, and creates no child, thread,
//! directory, mount, filter or handler. TT02 prepare/collect native wiring is
//! a documented follow-up; those hooks return typed deferred errors.
use super::creator::CreatorContext;
use super::manifest::{admit_manifest, AdmittedManifest};
use crate::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

const TERMINAL_SLOT_BYTES: usize = 1048576;
const ADMISSION_CLEANUP_CAP: u64 = 524288;
const MAX_NATIVE_ATTEMPTS: u64 = 16384;
const MAX_RECORDS: u64 = 16384;
const TERMINAL_MIN_BYTES: u64 = 1024;

pub struct LinuxFixtureFiles {
    pub image_a: std::fs::File,
    pub image_a_path: std::path::PathBuf,
    pub image_b: std::fs::File,
    pub image_b_path: std::path::PathBuf,
    pub root: std::fs::File,
}

impl std::fmt::Debug for LinuxFixtureFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxFixtureFiles")
            .field("image_a_path", &self.image_a_path)
            .field("image_b_path", &self.image_b_path)
            .finish_non_exhaustive()
    }
}

pub struct LinuxFixtureAdmissionFailure {
    pub error: FixtureError,
    pub contract: RunContract,
    pub files: LinuxFixtureFiles,
    pub custody: LinuxFixtureAdmissionCustody,
}

impl std::fmt::Debug for LinuxFixtureAdmissionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxFixtureAdmissionFailure")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct LinuxOuterCleanupBudget {
    pub deadline: Instant,
    pub max_native_attempts: u64,
    pub max_records: u64,
    pub max_retained_bytes: u64,
}

struct SlotSet {
    early: OnceLock<Vec<u8>>,
    shared: OnceLock<Vec<u8>>,
    case_retire: OnceLock<Vec<u8>>,
    run_retire: OnceLock<Vec<u8>>,
}
impl SlotSet {
    fn empty() -> Self {
        Self {
            early: OnceLock::new(),
            shared: OnceLock::new(),
            case_retire: OnceLock::new(),
            run_retire: OnceLock::new(),
        }
    }
    fn sealed_count(&self) -> u32 {
        [ &self.early, &self.shared, &self.case_retire, &self.run_retire ]
            .iter()
            .filter(|s| s.get().is_some())
            .count() as u32
    }
    fn earliest(&self) -> Option<&[u8]> {
        self.early
            .get()
            .or_else(|| self.shared.get())
            .or_else(|| self.case_retire.get())
            .or_else(|| self.run_retire.get())
            .map(Vec::as_slice)
    }
}

struct Assets {
    image_a: std::fs::File,
    image_b: std::fs::File,
    root: std::fs::File,
    creator: CreatorContext,
    constructor_ledger: Vec<u8>,
    terminal_reserve: Vec<u8>,
}

pub struct LinuxFixtureSession {
    contract: RunContract,
    manifest: AdmittedManifest,
    assets: Option<Assets>,
    /// Reserved for the TT02 prepare wiring follow-up.
    #[allow(dead_code)]
    execution_deadline: Instant,
    cancellation: Arc<AtomicBool>,
    slots: Mutex<BTreeMap<u64, SlotSet>>,
    sealed: Option<LinuxOuterCleanupReport>,
    retained_fds: Vec<(&'static str, rustix::fd::OwnedFd)>,
    retained_creator: Option<CreatorContext>,
}

impl std::fmt::Debug for LinuxFixtureSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxFixtureSession")
            .field("finalized", &self.sealed.is_some())
            .finish_non_exhaustive()
    }
}

fn typed_error(
    limits: &RunLimits,
    key: Option<InvocationKey>,
    stage: FixtureStage,
    category: FixtureErrorCategory,
    diagnostic: &str,
) -> FixtureError {
    FixtureError::new(
        FixtureErrorValues {
            key,
            stage,
            category,
            errno: None,
            diagnostic_bytes: diagnostic.as_bytes().to_vec(),
            effects: EffectBatch::empty(limits),
            read_progress: None,
        },
        limits,
    )
    .expect("bounded typed fixture error")
}

fn check_image_path(path: &std::path::Path, what: &str) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute() {
        return Err(format!("{what} must be absolute"));
    }
    if bytes.is_empty() || bytes.len() > 4096 || bytes.contains(&0) {
        return Err(format!("{what} must be nonempty, NUL-free, at most 4096 bytes"));
    }
    Ok(())
}

fn empty_ledger(reason: &str) -> Vec<u8> {
    format!(
        "{{\"ledger\":\"constructor\",\"aux_acquired\":0,\"refusal\":{reason:?}}}"
    )
    .into_bytes()
}

impl LinuxFixtureSession {
    pub fn new(
        contract: RunContract,
        files: LinuxFixtureFiles,
        manifest: &[u8],
        execution_deadline: Instant,
        cancellation: Arc<AtomicBool>,
    ) -> Result<Self, LinuxFixtureAdmissionFailure> {
        let limits = contract.limits().clone();
        let mut files_opt = Some(files);
        macro_rules! fail {
            ($detail:expr, $ledger:expr) => {
                LinuxFixtureAdmissionFailure {
                    error: typed_error(
                        &limits,
                        None,
                        FixtureStage::Admission,
                        FixtureErrorCategory::InvalidProtocol,
                        &$detail,
                    ),
                    contract: contract.clone(),
                    files: files_opt.take().expect("files returned exactly once"),
                    custody: LinuxFixtureAdmissionCustody {
                        aux: Vec::new(),
                        ledger: $ledger,
                        report: None,
                    },
                }
            };
        }
        if execution_deadline <= Instant::now() {
            let detail = "execution deadline already expired".to_string();
            let ledger = empty_ledger(&detail);
            return Err(fail!(detail, ledger));
        }
        let refusal = (|| {
            let files = files_opt.as_ref().expect("files present");
            if let Err(detail) = check_image_path(&files.image_a_path, "image_a_path")
                .and_then(|_| check_image_path(&files.image_b_path, "image_b_path"))
            {
                return Some((detail.clone(), empty_ledger(&detail)));
            }
            for (file, what) in [
                (&files.image_a, "image_a"),
                (&files.image_b, "image_b"),
                (&files.root, "root"),
            ] {
                match file.metadata() {
                    Ok(m) if m.is_file() || m.is_dir() => {}
                    _ => {
                        let detail =
                            format!("{what} must be an accessible file or directory");
                        return Some((detail.clone(), empty_ledger(&detail)));
                    }
                }
            }
            None
        })();
        if let Some((detail, ledger)) = refusal {
            return Err(fail!(detail, ledger));
        }
        let admitted = match admit_manifest(manifest, contract.run_id().as_str()) {
            Ok(m) => m,
            Err(e) => {
                let detail = format!("fixture manifest refused: {}", e.detail());
                let ledger = empty_ledger(&detail);
                return Err(fail!(detail, ledger));
            }
        };
        let creator = match CreatorContext::acquire() {
            Ok(c) => {
                let evidence = c.constructor_evidence();
                let inventories_ok = evidence.aux_acquired == 6
                    && evidence.peak_aux_owners == 4
                    && evidence.retained == 3
                    && evidence.temp_closes == 3;
                let work_ok = evidence.native_attempts == 23 + evidence.data_attempts
                    && evidence.native_attempts >= 28;
                if !inventories_ok || !work_ok {
                    let detail =
                        "creator context inventories disagree with the contract".to_string();
                    let ledger = empty_ledger(&detail);
                    return Err(fail!(detail, ledger));
                }
                c
            }
            Err(e) => {
                let detail = format!("creator context refused: {}", e.detail());
                let ledger = format!(
                    "{{\"ledger\":\"constructor\",\"aux_acquired\":0,\
                     \"native_attempts\":\"{}\",\"stage\":\"{:?}\",\"reason\":\"{:?}\",\
                     \"errno\":{},\"refusal\":{detail:?}}}",
                    e.attempts,
                    e.stage,
                    e.reason,
                    e.errno.map(|n| n.to_string()).unwrap_or("null".to_string()),
                )
                .into_bytes();
                return Err(fail!(detail, ledger));
            }
        };
        let mut ledger = creator.ledger_bytes();
        let files = files_opt.take().expect("files present");
        ledger.extend_from_slice(
            format!(
                ",{{\"manifest_run\":{:?},\"invocations\":{},\
                 \"image_a_path\":{:?},\"image_b_path\":{:?}}}",
                admitted.run_hex,
                admitted.invocations.len(),
                files.image_a_path.to_string_lossy(),
                files.image_b_path.to_string_lossy(),
            )
            .as_bytes(),
        );
        let mut slots = BTreeMap::new();
        for invocation in &admitted.invocations {
            slots.insert(invocation.operation_id, SlotSet::empty());
        }
        Ok(Self {
            contract,
            manifest: admitted,
            assets: Some(Assets {
                image_a: files.image_a,
                image_b: files.image_b,
                root: files.root,
                creator,
                constructor_ledger: ledger,
                terminal_reserve: Vec::with_capacity(TERMINAL_SLOT_BYTES),
            }),
            execution_deadline,
            cancellation,
            slots: Mutex::new(slots),
            sealed: None,
            retained_fds: Vec::new(),
            retained_creator: None,
        })
    }

    fn invocation_admitted(&self, operation_id: u64) -> bool {
        self.manifest
            .invocations
            .iter()
            .any(|i| i.operation_id == operation_id)
    }

    pub fn raw_ledger(&self, invocation: &InvocationKey) -> Option<&[u8]> {
        let op = *invocation.operation_id();
        if !self.invocation_admitted(op) {
            return None;
        }
        let mut slots = self.slots.lock().expect("slot lock");
        let set = slots.get_mut(&op)?;
        if let Some(existing) = set.earliest() {
            let ptr = existing as *const [u8];
            drop(slots);
            // SAFETY: roster slots are never removed or reallocated after
            // publication; the sealed bytes are immutable for &self.
            return Some(unsafe { &*ptr });
        }
        if set.sealed_count() > 0 || self.sealed.is_some() {
            return None;
        }
        let bytes = format!(
            "{{\"schema\":\"tt03.linux.snapshot\",\"revision\":1,\"slot\":\"early_export\",\
             \"run_id\":{:?},\"operation_id\":\"{}\",\"hook_entries\":\
             {{\"prepare\":0,\"collect\":0,\"case_retire\":0,\"run_retire\":0}},\
             \"completed_steps\":[],\"raw\":[],\"status\":\"no_prepare\",\
             \"conformance\":\"subset-first-increment\"}}",
            invocation.run_id().as_str(),
            op,
        )
        .into_bytes();
        let _ = set.early.set(bytes);
        let ptr = set.early.get().unwrap().as_slice() as *const [u8];
        drop(slots);
        // SAFETY: as above; the just-sealed slot is immutable for &self.
        Some(unsafe { &*ptr })
    }

    pub fn finalize(
        &mut self,
        budget: LinuxOuterCleanupBudget,
    ) -> Result<&LinuxOuterCleanupReport, LinuxOuterCleanupAdmissionError> {
        if self.sealed.is_none() {
            self.finalize_inner(budget)?;
        }
        Ok(self.sealed.as_ref().expect("sealed by finalize_inner"))
    }

    fn finalize_inner(
        &mut self,
        budget: LinuxOuterCleanupBudget,
    ) -> Result<(), LinuxOuterCleanupAdmissionError> {
        let now = Instant::now();
        if budget.deadline <= now {
            return Err(LinuxOuterCleanupAdmissionError::new(
                LinuxOuterCleanupAdmissionErrorKind::ExpiredDeadline,
                "cleanup deadline already expired",
            ));
        }
        let remaining = budget.deadline.saturating_duration_since(now);
        let retirement = std::time::Duration::from_millis(self.contract.limits().retirement_ms());
        if remaining > retirement {
            return Err(LinuxOuterCleanupAdmissionError::new(
                LinuxOuterCleanupAdmissionErrorKind::DurationExceedsRetirement,
                "cleanup window exceeds contract retirement duration",
            ));
        }
        if budget.max_native_attempts > MAX_NATIVE_ATTEMPTS
            || budget.max_records == 0
            || budget.max_records > MAX_RECORDS
        {
            return Err(LinuxOuterCleanupAdmissionError::new(
                LinuxOuterCleanupAdmissionErrorKind::AllowanceOutOfRange,
                "attempts must be 0..16384 and records 1..16384",
            ));
        }
        if budget.max_retained_bytes > TERMINAL_SLOT_BYTES as u64
            || budget.max_retained_bytes < TERMINAL_MIN_BYTES
        {
            return Err(LinuxOuterCleanupAdmissionError::new(
                LinuxOuterCleanupAdmissionErrorKind::InsufficientTerminalCapacity,
                "retained bytes must fit the reserved terminal slot",
            ));
        }
        let reserve_ok = self
            .assets
            .as_ref()
            .map(|a| a.terminal_reserve.capacity() as u64 >= budget.max_retained_bytes)
            .unwrap_or(false);
        if !reserve_ok {
            return Err(LinuxOuterCleanupAdmissionError::new(
                LinuxOuterCleanupAdmissionErrorKind::InvalidSessionState,
                "terminal reserve missing",
            ));
        }
        let _charged = budget
            .max_native_attempts
            .checked_add(budget.max_records)
            .and_then(|n| n.checked_add(budget.max_retained_bytes))
            .ok_or_else(|| {
                LinuxOuterCleanupAdmissionError::new(
                    LinuxOuterCleanupAdmissionErrorKind::ArithmeticOverflow,
                    "budget totals overflow",
                )
            })?;
        let mut remaining_attempts = budget.max_native_attempts;
        let mut effects = 0u64;
        let mut close_errors: Vec<(String, i32)> = Vec::new();
        let mut unresolved: Vec<String> = Vec::new();
        let assets = self.assets.as_ref().expect("assets before seal");
        let guard_outcome = assets.creator.guard();
        let guard_attempts = match &guard_outcome {
            Ok(evidence) => evidence.native_attempts,
            Err(error) => error.attempts,
        };
        if guard_attempts > remaining_attempts {
            let report = self.seal_unresolved(
                budget.max_retained_bytes,
                "outer guard allowance exhausted before cleanup",
                guard_attempts,
                effects,
                Vec::new(),
                vec![
                    "image_a".to_string(),
                    "image_b".to_string(),
                    "root".to_string(),
                    "creator_context".to_string(),
                ],
            );
            self.sealed = Some(report);
            return Ok(());
        }
        remaining_attempts -= guard_attempts;
        let guard_ok = guard_outcome.is_ok();
        if !guard_ok {
            let report = self.seal_unresolved(
                budget.max_retained_bytes,
                "outer read-only guard refused; no cleanup effects",
                guard_attempts,
                0,
                Vec::new(),
                vec![
                    "image_a".to_string(),
                    "image_b".to_string(),
                    "root".to_string(),
                    "creator_context".to_string(),
                ],
            );
            self.sealed = Some(report);
            return Ok(());
        }
        let assets = self.assets.take().expect("assets before seal");
        let ordered: Vec<(&str, rustix::fd::OwnedFd)> = vec![
            ("image_a", assets.image_a.into()),
            ("image_b", assets.image_b.into()),
            ("root", assets.root.into()),
        ];
        for (name, fd) in ordered {
            if remaining_attempts == 0 {
                unresolved.push(name.to_string());
                self.retained_fds.push((name, fd));
                continue;
            }
            remaining_attempts -= 1;
            effects += 1;
            let _ = name;
            super::creator::explicit_close_fd(fd);
        }
        let context_outcome = if remaining_attempts >= 3 {
            effects += 3;
            Some(assets.creator.close())
        } else {
            unresolved.push("creator_context".to_string());
            self.retained_creator = Some(assets.creator);
            None
        };
        if let Some(outcome) = context_outcome {
            effects -= 3 - outcome.closed as u64;
            close_errors.extend(outcome.errors);
        }
        let kind = if unresolved.is_empty() && close_errors.is_empty() {
            "clean"
        } else if unresolved.is_empty() {
            "settled_with_errors"
        } else {
            "unresolved"
        };
        let mut report_bytes = Vec::new();
        report_bytes.extend_from_slice(
            format!(
                "{{\"schema\":\"tt03.linux.outer-report\",\"revision\":1,\"kind\":{kind:?},\
                 \"guard_attempts\":\"{guard_attempts}\",\
                 \"native_cleanup_effects\":{effects},\"close_errors\":[",
            )
            .as_bytes(),
        );
        for (i, (name, errno)) in close_errors.iter().enumerate() {
            if i > 0 {
                report_bytes.push(b',');
            }
            report_bytes.extend_from_slice(format!("{{\"owner\":{name:?},\"errno\":{errno}}}").as_bytes());
        }
        report_bytes.extend_from_slice(b"],\"unresolved_owners\":[");
        for (i, name) in unresolved.iter().enumerate() {
            if i > 0 {
                report_bytes.push(b',');
            }
            report_bytes.extend_from_slice(format!("{name:?}").as_bytes());
        }
        report_bytes.extend_from_slice(
            b"],\"conformance\":\"subset-first-increment\"}",
        );
        if report_bytes.len() as u64 > budget.max_retained_bytes {
            let report = self.seal_unresolved(
                budget.max_retained_bytes,
                "terminal report exceeds admitted bytes",
                guard_attempts,
                effects,
                close_errors,
                unresolved,
            );
            self.sealed = Some(report);
            return Ok(());
        }
        let mut slot = assets.terminal_reserve;
        slot.extend_from_slice(&report_bytes);
        let constructor_ledger_len = assets.constructor_ledger.len();
        self.sealed = Some(LinuxOuterCleanupReport {
            bytes: slot,
            kind: kind.to_string(),
            native_attempts: guard_attempts + effects,
            constructor_ledger_len,
        });
        Ok(())
    }

    fn seal_unresolved(
        &self,
        _cap: u64,
        reason: &str,
        guard_attempts: u64,
        effects: u64,
        close_errors: Vec<(String, i32)>,
        unresolved: Vec<String>,
    ) -> LinuxOuterCleanupReport {
        let mut bytes = format!(
            "{{\"schema\":\"tt03.linux.outer-report\",\"revision\":1,\"kind\":\"unresolved\",\
             \"reason\":{reason:?},\"guard_attempts\":\"{guard_attempts}\",\
             \"native_cleanup_effects\":{effects},\"close_errors\":["
        )
        .into_bytes();
        for (i, (name, errno)) in close_errors.iter().enumerate() {
            if i > 0 {
                bytes.push(b',');
            }
            bytes.extend_from_slice(format!("{{\"owner\":{name:?},\"errno\":{errno}}}").as_bytes());
        }
        bytes.extend_from_slice(b"],\"unresolved_owners\":[");
        for (i, name) in unresolved.iter().enumerate() {
            if i > 0 {
                bytes.push(b',');
            }
            bytes.extend_from_slice(format!("{name:?}").as_bytes());
        }
        bytes.extend_from_slice(b"],\"conformance\":\"subset-first-increment\"}");
        LinuxOuterCleanupReport {
            bytes,
            kind: "unresolved".to_string(),
            native_attempts: guard_attempts + effects,
            constructor_ledger_len: 0,
        }
    }

    pub fn outer_cleanup_report(&self) -> Option<&LinuxOuterCleanupReport> {
        self.sealed.as_ref()
    }
}

impl Drop for LinuxFixtureSession {
    fn drop(&mut self) {
        if let Some(assets) = self.assets.take() {
            for fd in [assets.image_a.into(), assets.image_b.into(), assets.root.into()] {
                super::creator::explicit_close_fd(fd);
            }
            let _ = assets.creator.close();
        }
        for (_, fd) in self.retained_fds.drain(..) {
            super::creator::explicit_close_fd(fd);
        }
        if let Some(creator) = self.retained_creator.take() {
            let _ = creator.close();
        }
    }
}

struct SessionProbe(Arc<AtomicBool>);
impl CancellationProbe for SessionProbe {
    fn cancellation_requested(&self) -> bool {
        self.cancellation_flag()
    }
}
impl SessionProbe {
    fn cancellation_flag(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

impl FixtureSession for LinuxFixtureSession {
    fn contract(&self) -> &RunContract {
        &self.contract
    }
    fn cancellation_probe(&mut self) -> Box<dyn CancellationProbe + 'static> {
        Box::new(SessionProbe(Arc::clone(&self.cancellation)))
    }
    fn prepare(&mut self, invocation: &CaseInvocation) -> Result<FixtureAccess<'_>, FixtureError> {
        Err(typed_error(
            self.contract.limits(),
            Some(invocation.key().clone()),
            FixtureStage::Prepare,
            FixtureErrorCategory::Other,
            "first increment defers native TT02 prepare to the developer driver",
        ))
    }
    fn collect(&mut self, invocation: &CaseInvocation) -> Result<ExpectedEvidence, FixtureError> {
        Err(typed_error(
            self.contract.limits(),
            Some(invocation.key().clone()),
            FixtureStage::Collect,
            FixtureErrorCategory::Other,
            "first increment defers native TT02 collect to the developer driver",
        ))
    }
    fn retire(&mut self, request: &RetireRequest) -> RetirementReport {
        RetirementReport::new(
            RetirementReportValues {
                call_id: request.call_id(),
                owner: request.owner(),
                scope: request.scope().clone(),
                discovered: vec![],
                transitions: vec![],
                pending_snapshot: request.known_pending().to_vec(),
                complete: true,
                diagnostic: None,
            },
            self.contract.limits(),
        )
        .expect("bounded empty linux retirement")
    }
}

pub struct LinuxFixtureAdmissionCustody {
    aux: Vec<(&'static str, rustix::fd::OwnedFd)>,
    ledger: Vec<u8>,
    report: Option<LinuxFixtureAdmissionCleanupReport>,
}

impl std::fmt::Debug for LinuxFixtureAdmissionCustody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxFixtureAdmissionCustody")
            .field("aux_owners", &self.aux.len())
            .field("finalized", &self.report.is_some())
            .finish_non_exhaustive()
    }
}

impl LinuxFixtureAdmissionCustody {
    pub fn constructor_ledger(&self) -> &[u8] {
        &self.ledger
    }
    pub fn finalize(
        &mut self,
        budget: LinuxOuterCleanupBudget,
    ) -> Result<&LinuxFixtureAdmissionCleanupReport, LinuxOuterCleanupAdmissionError> {
        if self.report.is_some() {
            return Ok(self.report.as_ref().expect("checked custody report"));
        }
        if budget.deadline <= Instant::now() {
            return Err(LinuxOuterCleanupAdmissionError::new(
                LinuxOuterCleanupAdmissionErrorKind::ExpiredDeadline,
                "custody deadline already expired",
            ));
        }
        if budget.max_native_attempts > MAX_NATIVE_ATTEMPTS
            || budget.max_records == 0
            || budget.max_records > MAX_RECORDS
        {
            return Err(LinuxOuterCleanupAdmissionError::new(
                LinuxOuterCleanupAdmissionErrorKind::AllowanceOutOfRange,
                "attempts must be 0..16384 and records 1..16384",
            ));
        }
        if budget.max_retained_bytes > ADMISSION_CLEANUP_CAP
            || budget.max_retained_bytes < TERMINAL_MIN_BYTES
        {
            return Err(LinuxOuterCleanupAdmissionError::new(
                LinuxOuterCleanupAdmissionErrorKind::InsufficientTerminalCapacity,
                "custody bytes must fit the 524288 admission-cleanup half",
            ));
        }
        let mut remaining = budget.max_native_attempts;
        let mut closed = 0u64;
        let errors: Vec<(String, i32)> = Vec::new();
        let mut pending: Vec<String> = Vec::new();
        while let Some((name, fd)) = self.aux.pop() {
            if remaining == 0 {
                pending.push(name.to_string());
                self.aux.push((name, fd));
                break;
            }
            remaining -= 1;
            closed += 1;
            let _ = name;
            super::creator::explicit_close_fd(fd);
        }
        for (name, _) in self.aux.iter() {
            if !pending.iter().any(|p| p == name) {
                pending.push(name.to_string());
            }
        }
        let kind = if pending.is_empty() && errors.is_empty() {
            "clean"
        } else if pending.is_empty() {
            "settled_with_errors"
        } else {
            "unresolved"
        };
        let mut bytes = format!(
            "{{\"schema\":\"tt03.linux.asset-guard-report\",\"revision\":1,\"kind\":{kind:?},\
             \"closed\":{closed},\"close_errors\":["
        )
        .into_bytes();
        for (i, (name, errno)) in errors.iter().enumerate() {
            if i > 0 {
                bytes.push(b',');
            }
            bytes.extend_from_slice(format!("{{\"owner\":{name:?},\"errno\":{errno}}}").as_bytes());
        }
        bytes.extend_from_slice(b"],\"pending\":[");
        for (i, name) in pending.iter().enumerate() {
            if i > 0 {
                bytes.push(b',');
            }
            bytes.extend_from_slice(format!("{name:?}").as_bytes());
        }
        bytes.extend_from_slice(b"],\"conformance\":\"subset-first-increment\"}");
        self.report = Some(LinuxFixtureAdmissionCleanupReport { bytes });
        Ok(self.report.as_ref().expect("sealed custody report"))
    }
    pub fn admission_cleanup_report(&self) -> Option<&LinuxFixtureAdmissionCleanupReport> {
        self.report.as_ref()
    }
}

impl Drop for LinuxFixtureAdmissionCustody {
    fn drop(&mut self) {
        while let Some((_, fd)) = self.aux.pop() {
            super::creator::explicit_close_fd(fd);
        }
    }
}

pub struct LinuxFixtureAdmissionCleanupReport {
    bytes: Vec<u8>,
}
impl LinuxFixtureAdmissionCleanupReport {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl std::fmt::Debug for LinuxFixtureAdmissionCleanupReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxFixtureAdmissionCleanupReport")
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

pub struct LinuxOuterCleanupReport {
    bytes: Vec<u8>,
    kind: String,
    native_attempts: u64,
    constructor_ledger_len: usize,
}
impl LinuxOuterCleanupReport {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn kind(&self) -> &str {
        &self.kind
    }
    pub fn native_attempts(&self) -> u64 {
        self.native_attempts
    }
    pub fn constructor_ledger_len(&self) -> usize {
        self.constructor_ledger_len
    }
}
impl std::fmt::Debug for LinuxOuterCleanupReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxOuterCleanupReport")
            .field("kind", &self.kind)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxOuterCleanupAdmissionErrorKind {
    ExpiredDeadline,
    DurationExceedsRetirement,
    AllowanceOutOfRange,
    InsufficientTerminalCapacity,
    ArithmeticOverflow,
    InvalidSessionState,
}

#[derive(Debug)]
pub struct LinuxOuterCleanupAdmissionError {
    kind: LinuxOuterCleanupAdmissionErrorKind,
    diagnostic: Vec<u8>,
}
impl LinuxOuterCleanupAdmissionError {
    fn new(kind: LinuxOuterCleanupAdmissionErrorKind, diagnostic: &str) -> Self {
        Self {
            kind,
            diagnostic: diagnostic.as_bytes().to_vec(),
        }
    }
    pub fn kind(&self) -> LinuxOuterCleanupAdmissionErrorKind {
        self.kind
    }
    pub fn diagnostic_bytes(&self) -> &[u8] {
        &self.diagnostic
    }
}
impl std::fmt::Display for LinuxOuterCleanupAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cleanup admission {:?}: {}", self.kind, String::from_utf8_lossy(&self.diagnostic))
    }
}
impl std::error::Error for LinuxOuterCleanupAdmissionError {}
