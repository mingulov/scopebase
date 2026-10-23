// SPDX-License-Identifier: Apache-2.0
//! TT03 Linux fixture session: exact public admission/custody/finalizer API.
//!
//! The constructor validates and adopts the caller files plus the externally
//! bound manifest, acquires the retained creator context, reserves the full
//! admitted roster and one 1MiB terminal slot, and creates no child, thread,
//! directory, mount, filter or handler. TT02 prepare/collect run the native
//! developer driver (real pair launch, prefix advance, drained-raw evidence);
//! effect-transition retirement stays a documented follow-up.
use super::creator::CreatorContext;
use super::driver::{
    launch_pair, DriverError, DriverErrorKind, LaunchConfig, LivePair, Scenario,
};
use super::manifest::{admit_manifest, AdmittedManifest};
use super::phase::LinuxProcessFixture;
use super::wire::sha256_of;
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
    image_a_path: std::path::PathBuf,
    image_b: std::fs::File,
    image_b_path: std::path::PathBuf,
    root: std::fs::File,
    creator: CreatorContext,
    constructor_ledger: Vec<u8>,
    terminal_reserve: Vec<u8>,
}

struct PreparedEntry {
    pair: LivePair,
    process: LinuxProcessFixture,
    excluded: LinuxProcessFixture,
    files: Vec<std::fs::File>,
    scenario: Scenario,
}

pub struct LinuxFixtureSession {
    contract: RunContract,
    manifest: AdmittedManifest,
    manifest_sha256: [u8; 32],
    assets: Option<Assets>,
    execution_deadline: Instant,
    cancellation: Arc<AtomicBool>,
    slots: Mutex<BTreeMap<u64, SlotSet>>,
    prepared: BTreeMap<u64, PreparedEntry>,
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
    let cap = limits.diagnostic_bytes() as usize;
    let mut bytes = diagnostic.as_bytes().to_vec();
    bytes.truncate(cap);
    FixtureError::new(
        FixtureErrorValues {
            key,
            stage,
            category,
            errno: None,
            diagnostic_bytes: bytes,
            effects: EffectBatch::empty(limits),
            read_progress: None,
        },
        limits,
    )
    .expect("bounded typed fixture error")
}

fn driver_to_fixture(
    limits: &RunLimits,
    key: &InvocationKey,
    stage: FixtureStage,
    error: &DriverError,
) -> FixtureError {
    let category = match error.kind() {
        DriverErrorKind::Protocol => FixtureErrorCategory::InvalidProtocol,
        DriverErrorKind::Io => FixtureErrorCategory::Io,
        DriverErrorKind::Timeout => FixtureErrorCategory::TimedOut,
        DriverErrorKind::Refused => FixtureErrorCategory::Denied,
        DriverErrorKind::Cancelled => FixtureErrorCategory::Cancelled,
        DriverErrorKind::Deferred => FixtureErrorCategory::Other,
    };
    typed_error(
        limits,
        Some(key.clone()),
        stage,
        category,
        &format!(
            "native driver: {}",
            String::from_utf8_lossy(error.diagnostic_bytes())
        ),
    )
}

fn phase_to_fixture(
    limits: &RunLimits,
    key: &InvocationKey,
    stage: FixtureStage,
    error: &super::phase::LinuxPhaseError,
) -> FixtureError {
    let cap = limits.diagnostic_bytes() as usize;
    let mut bytes = error.diagnostic_bytes().to_vec();
    bytes.truncate(cap);
    FixtureError::new(
        FixtureErrorValues {
            key: Some(key.clone()),
            stage,
            category: error.category(),
            errno: error.errno(),
            diagnostic_bytes: bytes,
            effects: EffectBatch::empty(limits),
            read_progress: None,
        },
        limits,
    )
    .expect("bounded phase fixture error")
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
        let manifest_sha256 = sha256_of(manifest);
        Ok(Self {
            contract,
            manifest: admitted,
            manifest_sha256,
            assets: Some(Assets {
                image_a: files.image_a,
                image_a_path: files.image_a_path,
                image_b: files.image_b,
                image_b_path: files.image_b_path,
                root: files.root,
                creator,
                constructor_ledger: ledger,
                terminal_reserve: Vec::with_capacity(TERMINAL_SLOT_BYTES),
            }),
            execution_deadline,
            cancellation,
            slots: Mutex::new(slots),
            prepared: BTreeMap::new(),
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
            let mut pending = vec![
                "image_a".to_string(),
                "image_b".to_string(),
                "root".to_string(),
                "creator_context".to_string(),
            ];
            pending.extend(self.prepared.keys().map(|op| format!("prepared-pair-{op}")));
            let report = self.seal_unresolved(
                budget.max_retained_bytes,
                "outer guard allowance exhausted before cleanup",
                guard_attempts,
                effects,
                Vec::new(),
                pending,
            );
            self.sealed = Some(report);
            return Ok(());
        }
        remaining_attempts -= guard_attempts;
        let guard_ok = guard_outcome.is_ok();
        if !guard_ok {
            let mut pending = vec![
                "image_a".to_string(),
                "image_b".to_string(),
                "root".to_string(),
                "creator_context".to_string(),
            ];
            pending.extend(self.prepared.keys().map(|op| format!("prepared-pair-{op}")));
            let report = self.seal_unresolved(
                budget.max_retained_bytes,
                "outer read-only guard refused; no cleanup effects",
                guard_attempts,
                0,
                Vec::new(),
                pending,
            );
            self.sealed = Some(report);
            return Ok(());
        }
        // Prepared native pairs shut down here, precharged 5 native attempts
        // each (two close issues, two exact reaps, one case-dir removal). A
        // pair without precharged allowance stays live in the session and is
        // named unresolved; Drop retires leftovers best-effort.
        let mut prepared_ops: Vec<u64> = self.prepared.keys().copied().collect();
        prepared_ops.sort_unstable();
        for op in prepared_ops {
            if remaining_attempts < 5 {
                unresolved.push(format!("prepared-pair-{op}"));
                continue;
            }
            remaining_attempts -= 5;
            let entry = self.prepared.remove(&op).expect("prepared op");
            let PreparedEntry {
                pair,
                process: _process,
                excluded: _excluded,
                files: _files,
                scenario: _scenario,
            } = entry;
            let report = pair.shutdown();
            effects += 5;
            if report.a_exit.is_none() || report.b_exit.is_none() || !report.case_root_removed {
                unresolved.push(format!("prepared-pair-{op}"));
            }
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
        for (_, entry) in std::mem::take(&mut self.prepared) {
            let _ = entry.pair.shutdown();
        }
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

fn file_scenario(scenario: Scenario) -> bool {
    matches!(scenario, Scenario::FileReplacement | Scenario::DescriptorInventory)
}

impl LinuxFixtureSession {
    fn prepare_effects(
        &self,
        key: &InvocationKey,
        operation_id: u64,
        pair: &LivePair,
        files: &[std::fs::File],
    ) -> Result<EffectBatch, FixtureError> {
        let limits = self.contract.limits();
        let mut registrations = Vec::new();
        let mut push = |id: &str, kind: &str, identity: &[u8]| -> Result<(), FixtureError> {
            let registration = EffectRegistration::new(
                EffectRegistrationValues {
                    resource_id: Label::parse(id).expect("static effect label"),
                    owner: Owner::Fixture,
                    origin: key.clone(),
                    kind: Label::parse(kind).expect("static effect kind"),
                    identity_sha256: Digest256::of_bytes(identity),
                    recovery_evidence_id: None,
                },
                limits,
            )
            .map_err(|e| FixtureError::harness(e, Some(key.clone()), FixtureStage::Prepare))?;
            registrations.push(registration);
            Ok(())
        };
        push("linux.case-root", "linux-case-root", &operation_id.to_le_bytes())?;
        push("linux.child-a", "linux-child", &pair.a_pid().to_le_bytes())?;
        push("linux.child-b", "linux-child", &pair.b_pid().to_le_bytes())?;
        for (index, file) in files.iter().enumerate() {
            use std::os::unix::fs::MetadataExt;
            let metadata = file.metadata().map_err(|e| {
                typed_error(
                    limits,
                    Some(key.clone()),
                    FixtureStage::Prepare,
                    FixtureErrorCategory::Io,
                    &format!("retained file identity refused: {e}"),
                )
            })?;
            let mut identity = Vec::new();
            identity.extend_from_slice(&metadata.dev().to_le_bytes());
            identity.extend_from_slice(&metadata.ino().to_le_bytes());
            push(
                if index == 0 { "linux.file-a" } else { "linux.file-b" },
                "linux-file",
                &identity,
            )?;
        }
        EffectBatch::new(
            EffectBatchValues {
                registrations,
                complete: true,
            },
            limits,
        )
        .map_err(|e| FixtureError::harness(e, Some(key.clone()), FixtureStage::Prepare))
    }

    fn prepare_native(
        &mut self,
        invocation: &CaseInvocation,
    ) -> Result<(u64, EffectBatch), FixtureError> {
        let limits = self.contract.limits().clone();
        let key = invocation.key().clone();
        let operation_id = *key.operation_id();
        let admitted = self
            .manifest
            .invocations
            .iter()
            .find(|i| i.operation_id == operation_id)
            .ok_or_else(|| {
                typed_error(
                    &limits,
                    Some(key.clone()),
                    FixtureStage::Prepare,
                    FixtureErrorCategory::InvalidProtocol,
                    "operation is not admitted by the fixture manifest",
                )
            })?;
        if self.sealed.is_some() || self.assets.is_none() {
            return Err(typed_error(
                &limits,
                Some(key.clone()),
                FixtureStage::Prepare,
                FixtureErrorCategory::InvalidProtocol,
                "session is finalized",
            ));
        }
        if self.prepared.contains_key(&operation_id) {
            return Err(typed_error(
                &limits,
                Some(key.clone()),
                FixtureStage::Prepare,
                FixtureErrorCategory::InvalidProtocol,
                "operation is already prepared",
            ));
        }
        let scenario = admitted.scenario;
        let blobs = (
            admitted.expected_file_a_hex.clone(),
            admitted.expected_file_b_hex.clone(),
            admitted.mutation_hex.clone(),
        );
        let assets = self.assets.as_ref().expect("assets checked");
        let root = assets.root.try_clone().map_err(|e| {
            typed_error(
                &limits,
                Some(key.clone()),
                FixtureStage::Prepare,
                FixtureErrorCategory::Io,
                &format!("admission root clone refused: {e}"),
            )
        })?;
        let deadline_ns = {
            let remaining = self.execution_deadline.saturating_duration_since(Instant::now());
            std::time::SystemTime::now()
                .checked_add(remaining)
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos().min(u128::from(u64::MAX)) as u64)
                .unwrap_or(u64::MAX)
        };
        let config = LaunchConfig {
            worker: assets.image_a_path.clone(),
            image_a: assets.image_a_path.clone(),
            image_b: assets.image_b_path.clone(),
            root,
            run_hex: self.contract.run_id().as_str().to_string(),
            operation_id,
            manifest_sha256: self.manifest_sha256,
            scenario,
            deadline_ns,
            cancel: Arc::clone(&self.cancellation),
        };
        let pair = launch_pair(&config)
            .map_err(|e| driver_to_fixture(&limits, &key, FixtureStage::Prepare, &e))?;
        if file_scenario(scenario) {
            let (a, b, mutation) = match blobs {
                (Some(a), Some(b), Some(mutation)) => (a, b, mutation),
                _ => {
                    pair.shutdown();
                    return Err(typed_error(
                        &limits,
                        Some(key.clone()),
                        FixtureStage::Prepare,
                        FixtureErrorCategory::InvalidProtocol,
                        "file-scenario prepare needs manifest blob bytes",
                    ));
                }
            };
            if let Err(e) = pair.upload_blobs(&a, &b, &mutation) {
                pair.shutdown();
                return Err(driver_to_fixture(&limits, &key, FixtureStage::Prepare, &e));
            }
        }
        let process = pair.a_process();
        let prefix = scenario.prepare_prefix_len();
        for step in scenario.steps().iter().take(prefix) {
            let label = Label::parse(step.id).expect("static scenario step");
            if let Err(e) = process.advance(&label) {
                pair.shutdown();
                return Err(phase_to_fixture(&limits, &key, FixtureStage::Prepare, &e));
            }
        }
        let mut files = Vec::new();
        if file_scenario(scenario) {
            for pull_b in [false, true] {
                let pulled = if pull_b {
                    pair.pulled_file_b()
                } else {
                    pair.pulled_file_a()
                };
                match pulled {
                    Ok(file) => files.push(file),
                    Err(e) => {
                        pair.shutdown();
                        return Err(typed_error(
                            &limits,
                            Some(key.clone()),
                            FixtureStage::Prepare,
                            FixtureErrorCategory::Io,
                            &format!("retained file pull refused: {e}"),
                        ));
                    }
                }
            }
        }
        let effects = self.prepare_effects(&key, operation_id, &pair, &files)?;
        let excluded = pair.b_process();
        self.prepared.insert(
            operation_id,
            PreparedEntry {
                pair,
                process,
                excluded,
                files,
                scenario,
            },
        );
        Ok((operation_id, effects))
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
        let (operation_id, effects) = self.prepare_native(invocation)?;
        let limits = self.contract.limits().clone();
        let stored = self.prepared.get(&operation_id).expect("just prepared");
        let inputs: Vec<FixtureInput<'_>> = Vec::new();
        let mut resources = Vec::new();
        resources.push(FixtureResource::new(
            Label::parse("linux.process").expect("static resource label"),
            &stored.process,
        ));
        resources.push(FixtureResource::new(
            Label::parse("linux.excluded-process").expect("static resource label"),
            &stored.excluded,
        ));
        if file_scenario(stored.scenario) {
            resources.push(FixtureResource::new(
                Label::parse("linux.file-a").expect("static resource label"),
                &stored.files[0],
            ));
            resources.push(FixtureResource::new(
                Label::parse("linux.file-b").expect("static resource label"),
                &stored.files[1],
            ));
        }
        FixtureAccess::new(&inputs, &resources, effects, &limits)
    }
    fn collect(&mut self, invocation: &CaseInvocation) -> Result<ExpectedEvidence, FixtureError> {
        let limits = self.contract.limits().clone();
        let key = invocation.key().clone();
        let operation_id = *key.operation_id();
        let entry = self.prepared.get(&operation_id).ok_or_else(|| {
            typed_error(
                &limits,
                Some(key.clone()),
                FixtureStage::Collect,
                FixtureErrorCategory::InvalidProtocol,
                "operation was not prepared",
            )
        })?;
        let drained = entry.pair.drained_raw();
        let scenario = entry.scenario;
        let digests: Vec<String> = drained
            .iter()
            .map(|r| {
                const H: &[u8; 16] = b"0123456789abcdef";
                let sum = sha256_of(&r.bytes);
                let mut s = String::with_capacity(64);
                for b in sum {
                    s.push(H[(b >> 4) as usize] as char);
                    s.push(H[(b & 15) as usize] as char);
                }
                s
            })
            .collect();
        let completed: Vec<&str> = scenario
            .steps()
            .iter()
            .take(scenario.prepare_prefix_len())
            .map(|s| s.id)
            .collect();
        let expected = serde_json::json!({
            "schema": "tt03.linux.snapshot",
            "revision": 1,
            "slot": "shared_collect",
            "run_id": key.run_id().as_str(),
            "operation_id": operation_id.to_string(),
            "scenario": scenario.as_str(),
            "completed_steps": completed,
            "prefix_records": drained.len(),
            "record_digests": digests,
            "conformance": "subset-second-increment",
        });
        let expected_bytes = serde_json::to_vec(&expected).map_err(|e| {
            FixtureError::harness(
                he(HarnessErrorKind::InvalidInput, &format!("snapshot encode: {e}")),
                Some(key.clone()),
                FixtureStage::Collect,
            )
        })?;
        let mut ledger_bytes = Vec::new();
        for record in &drained {
            ledger_bytes.extend_from_slice(&(record.bytes.len() as u32).to_le_bytes());
            ledger_bytes.extend_from_slice(&record.bytes);
        }
        if let Some(set) = self.slots.lock().expect("slot lock").get_mut(&operation_id) {
            let _ = set.shared.set(expected_bytes.clone());
        }
        ExpectedEvidence::new(
            ExpectedEvidenceValues {
                key: key.clone(),
                oracle: self.contract.expected_oracle().clone(),
                fixture_schema: invocation.fixture_schema().clone(),
                truth_kind: TruthKind::IndependentLedger,
                expected_bytes,
                ledger_bytes,
                coverage: Vec::new(),
                effects: EffectBatch::empty(&limits),
            },
            &limits,
        )
        .map_err(|e| FixtureError::harness(e, Some(key), FixtureStage::Collect))
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
                diagnostic: Some(
                    "prepared linux pairs shut down at finalize; transitions unmodeled".to_string(),
                ),
            },
            self.contract.limits(),
        )
        .expect("bounded linux retirement")
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
