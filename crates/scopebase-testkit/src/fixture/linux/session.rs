// SPDX-License-Identifier: Apache-2.0
//! TT03 Linux fixture session: exact public admission/custody/finalizer API.
//!
//! The constructor validates and adopts the caller files plus the externally
//! bound manifest, acquires the retained creator context, reserves the full
//! admitted roster and one 1MiB terminal slot, and creates no child, thread,
//! directory, mount, filter or handler. TT02 prepare/collect run the native
//! developer driver (real pair launch, prefix advance, drained-raw evidence);
//! retire models full Pending → Retired transitions with exactly-once
//! discoveries and sticky unknown inventory over prepared and failed attempts.
use super::creator::CreatorContext;
use super::driver::{
    launch_pair, CleanupProof, DriverError, DriverErrorKind, LaunchConfig, LivePair, Scenario,
    ShutdownReport,
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
    origin: InvocationKey,
    file_identities: Vec<(String, Vec<u8>)>,
}

/// A failed prepare attempt that still owns retire-relevant evidence.
/// No native owners remain: the pair was shut down (or never launched)
/// on the error path. The shutdown report, registered PIDs, settled
/// flags and sampled-file labels drive retire discoveries, transitions
/// and the sticky unknown inventory.
struct FailedEntry {
    origin: InvocationKey,
    scenario: Scenario,
    control: Option<String>,
    a_pid: Option<u32>,
    b_pid: Option<u32>,
    a_settled: bool,
    b_settled: bool,
    case_root_removed: bool,
    file_sampled: Vec<String>,
    file_identities: Vec<(String, Vec<u8>)>,
}

/// The sealed per-operation retirement outcome. Repeats emit nothing new
/// and re-report the stored unknown inventory, never clearing it.
struct RetiredOp {
    transitioned: Vec<Label>,
    unknown: Vec<Label>,
    complete: bool,
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
    failed: BTreeMap<u64, FailedEntry>,
    retired: BTreeMap<u64, RetiredOp>,
    run_retired: bool,
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
        DriverErrorKind::WorkerDeath => FixtureErrorCategory::InvalidProtocol,
        DriverErrorKind::SetupFailure => FixtureErrorCategory::Other,
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
            failed: BTreeMap::new(),
            retired: BTreeMap::new(),
            run_retired: false,
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
                origin: _origin,
                file_identities: _file_identities,
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

fn file_identity_bytes(file: &std::fs::File) -> Option<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata().ok()?;
    let mut identity = Vec::new();
    identity.extend_from_slice(&metadata.dev().to_le_bytes());
    identity.extend_from_slice(&metadata.ino().to_le_bytes());
    Some(identity)
}

impl FailedEntry {
    /// Capture retire-relevant evidence from a live pair before it is shut
    /// down on a prepare error path. Settled flags stay false until
    /// [`FailedEntry::apply_shutdown`] observes the actual shutdown report.
    fn capture_pair(
        key: &InvocationKey,
        scenario: Scenario,
        control: Option<String>,
        pair: &LivePair,
        files: &[std::fs::File],
    ) -> Self {
        let mut file_sampled = Vec::new();
        for record in pair.drained_raw() {
            if record.kind == "mutation" && !file_sampled.contains(&"linux.file-a".to_string()) {
                file_sampled.push("linux.file-a".to_string());
            }
        }
        let mut file_identities = Vec::new();
        for (index, file) in files.iter().enumerate() {
            if let Some(identity) = file_identity_bytes(file) {
                file_identities.push((
                    if index == 0 {
                        "linux.file-a"
                    } else {
                        "linux.file-b"
                    }
                    .to_string(),
                    identity,
                ));
            }
        }
        Self {
            origin: key.clone(),
            scenario,
            control,
            a_pid: Some(pair.a_pid()),
            b_pid: Some(pair.b_pid()),
            a_settled: false,
            b_settled: false,
            case_root_removed: false,
            file_sampled,
            file_identities,
        }
    }

    fn apply_shutdown(&mut self, shutdown: &ShutdownReport) {
        self.a_settled = shutdown.a_exit.is_some();
        self.b_settled = shutdown.b_exit.is_some();
        self.case_root_removed = shutdown.case_root_removed;
    }

    fn from_launch_proof(
        key: &InvocationKey,
        scenario: Scenario,
        control: Option<String>,
        proof: &CleanupProof,
    ) -> Self {
        Self {
            origin: key.clone(),
            scenario,
            control,
            a_pid: proof.a_pid,
            b_pid: proof.b_pid,
            a_settled: proof.a_exit.is_some(),
            b_settled: proof.b_exit.is_some(),
            case_root_removed: proof.case_root_removed,
            file_sampled: Vec::new(),
            file_identities: Vec::new(),
        }
    }
}

impl LinuxFixtureSession {
    fn prepare_effects(
        &self,
        key: &InvocationKey,
        operation_id: u64,
        pair: &LivePair,
        files: &[std::fs::File],
    ) -> Result<(EffectBatch, Vec<(String, Vec<u8>)>), FixtureError> {
        let limits = self.contract.limits();
        let mut registrations = Vec::new();
        let mut file_identities = Vec::new();
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
            let id = if index == 0 {
                "linux.file-a"
            } else {
                "linux.file-b"
            };
            push(id, "linux-file", &identity)?;
            file_identities.push((id.to_string(), identity));
        }
        let batch = EffectBatch::new(
            EffectBatchValues {
                registrations,
                complete: true,
            },
            limits,
        )
        .map_err(|e| FixtureError::harness(e, Some(key.clone()), FixtureStage::Prepare))?;
        Ok((batch, file_identities))
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
        if self.run_retired {
            return Err(typed_error(
                &limits,
                Some(key.clone()),
                FixtureStage::Prepare,
                FixtureErrorCategory::InvalidProtocol,
                "session run is retired; admission stopped",
            ));
        }
        if self.failed.contains_key(&operation_id) || self.retired.contains_key(&operation_id) {
            return Err(typed_error(
                &limits,
                Some(key.clone()),
                FixtureStage::Prepare,
                FixtureErrorCategory::InvalidProtocol,
                "operation was already attempted",
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
        // Manifest outage controls reach the driver; other admitted kinds
        // keep their existing status-quo handling on their own routes.
        let control = match &admitted.control {
            Some(armed)
                if matches!(
                    armed.kind.as_str(),
                    "worker_exit" | "partial_file_write" | "parent_failure_after_register"
                ) =>
            {
                Some(armed.clone())
            }
            _ => None,
        };
        let control_context = control
            .as_ref()
            .map(|armed| format!("{}/{}", armed.kind, armed.point));
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
            control,
        };
        let pair = match launch_pair(&config) {
            Ok(pair) => pair,
            Err(error) => {
                let proof = error.cleanup_proof();
                let outage = matches!(
                    error.kind(),
                    DriverErrorKind::WorkerDeath | DriverErrorKind::SetupFailure
                );
                if outage
                    || proof.spawned
                    || proof.case_root_removed
                    || proof.a_pid.is_some()
                    || proof.b_pid.is_some()
                {
                    self.failed.insert(
                        operation_id,
                        FailedEntry::from_launch_proof(
                            &key,
                            scenario,
                            control_context.clone(),
                            proof,
                        ),
                    );
                }
                return Err(driver_to_fixture(
                    &limits,
                    &key,
                    FixtureStage::Prepare,
                    &error,
                ));
            }
        };
        if file_scenario(scenario) {
            let (a, b, mutation) = match blobs {
                (Some(a), Some(b), Some(mutation)) => (a, b, mutation),
                _ => {
                    let failed = FailedEntry::capture_pair(
                        &key,
                        scenario,
                        control_context.clone(),
                        &pair,
                        &[],
                    );
                    let shutdown = pair.shutdown();
                    self.fail_pair(operation_id, failed, shutdown);
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
                let failed =
                    FailedEntry::capture_pair(&key, scenario, control_context.clone(), &pair, &[]);
                let shutdown = pair.shutdown();
                self.fail_pair(operation_id, failed, shutdown);
                return Err(driver_to_fixture(&limits, &key, FixtureStage::Prepare, &e));
            }
        }
        let process = pair.a_process();
        let prefix = scenario.prepare_prefix_len();
        for step in scenario.steps().iter().take(prefix) {
            let label = Label::parse(step.id).expect("static scenario step");
            if let Err(e) = process.advance(&label) {
                let failed =
                    FailedEntry::capture_pair(&key, scenario, control_context.clone(), &pair, &[]);
                let shutdown = pair.shutdown();
                self.fail_pair(operation_id, failed, shutdown);
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
                        let failed = FailedEntry::capture_pair(
                            &key,
                            scenario,
                            control_context.clone(),
                            &pair,
                            &files,
                        );
                        let shutdown = pair.shutdown();
                        self.fail_pair(operation_id, failed, shutdown);
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
        let (effects, file_identities) =
            match self.prepare_effects(&key, operation_id, &pair, &files) {
                Ok(ok) => ok,
                Err(error) => {
                    let failed = FailedEntry::capture_pair(
                        &key,
                        scenario,
                        control_context.clone(),
                        &pair,
                        &files,
                    );
                    let shutdown = pair.shutdown();
                    self.fail_pair(operation_id, failed, shutdown);
                    return Err(error);
                }
            };
        let excluded = pair.b_process();
        self.prepared.insert(
            operation_id,
            PreparedEntry {
                pair,
                process,
                excluded,
                files,
                scenario,
                origin: key.clone(),
                file_identities,
            },
        );
        Ok((operation_id, effects))
    }
}

/// Fixed per-operation seal reserve charged against the request's
/// retained-byte allowance before any native work. Actual seals are ~1KiB.
const SEAL_RESERVE_PER_OP: u64 = 2048;

/// First-emission outcome for one operation: discoveries, exact
/// Pending → Retired transitions, registrations that stay pending, the
/// sticky unknown inventory and the slot-seal bytes.
struct OpOutcome {
    scenario: Scenario,
    discovered: Vec<EffectRegistration>,
    transitions: Vec<EffectTransition>,
    pending_keep: Vec<Label>,
    unknown: Vec<Label>,
    complete: bool,
    note: String,
}

struct OutcomeBuilder<'a> {
    limits: &'a RunLimits,
    op: u64,
    origin: &'a InvocationKey,
    discovered: Vec<EffectRegistration>,
    transitions: Vec<EffectTransition>,
    pending_keep: Vec<Label>,
    unknown: Vec<Label>,
}

impl<'a> OutcomeBuilder<'a> {
    fn new(limits: &'a RunLimits, op: u64, origin: &'a InvocationKey) -> Self {
        Self {
            limits,
            op,
            origin,
            discovered: Vec::new(),
            transitions: Vec::new(),
            pending_keep: Vec::new(),
            unknown: Vec::new(),
        }
    }

    fn transition_for(&self, resource_id: &str, identity: &[u8]) -> EffectTransition {
        let short = resource_id.strip_prefix("linux.").unwrap_or(resource_id);
        EffectTransition::new(
            EffectTransitionValues {
                transition_id: Label::parse(&format!("linux.retire.{}.{short}", self.op))
                    .expect("bounded transition id"),
                effect: PendingEffectRef::new(
                    PendingEffectRefValues {
                        resource_id: Label::parse(resource_id).expect("static resource label"),
                        owner: Owner::Fixture,
                        origin: self.origin.clone(),
                        identity_sha256: Digest256::of_bytes(identity),
                    },
                    self.limits,
                )
                .expect("bounded pending ref"),
                to: TransitionTo::Retired,
                evidence_ids: vec![Label::parse(&format!("linux.proof.{}.{short}", self.op))
                    .expect("bounded evidence id")],
            },
            self.limits,
        )
        .expect("bounded linux transition")
    }

    /// A prepare-registered resource: transition it when actually settled,
    /// else keep it pending and mark it sticky-unknown.
    fn known(&mut self, resource_id: &str, identity: &[u8], settled: bool) {
        if settled {
            self.transitions
                .push(self.transition_for(resource_id, identity));
        } else {
            let label = Label::parse(resource_id).expect("static resource label");
            self.pending_keep.push(label.clone());
            self.unknown.push(label);
        }
    }

    /// A retire-discovered resource: register it exactly once here, then
    /// transition it when actually settled.
    fn found(&mut self, resource_id: &str, kind: &str, identity: &[u8], settled: bool) {
        self.discovered.push(
            EffectRegistration::new(
                EffectRegistrationValues {
                    resource_id: Label::parse(resource_id).expect("static resource label"),
                    owner: Owner::Fixture,
                    origin: self.origin.clone(),
                    kind: Label::parse(kind).expect("static effect kind"),
                    identity_sha256: Digest256::of_bytes(identity),
                    recovery_evidence_id: None,
                },
                self.limits,
            )
            .expect("bounded linux discovery"),
        );
        if settled {
            self.transitions
                .push(self.transition_for(resource_id, identity));
        } else {
            let label = Label::parse(resource_id).expect("static resource label");
            self.pending_keep.push(label.clone());
            self.unknown.push(label);
        }
    }

    /// Existed but identity unrecoverable: sticky unknown without any
    /// fabricated registration.
    fn unprovable(&mut self, resource_id: &str) {
        self.unknown
            .push(Label::parse(resource_id).expect("static resource label"));
    }

    fn finish(mut self, scenario: Scenario) -> OpOutcome {
        self.unknown.sort();
        self.unknown.dedup();
        self.pending_keep.sort();
        self.pending_keep.dedup();
        let complete = self.unknown.is_empty() && self.pending_keep.is_empty();
        let note = format!(
            "op {}: +{} discovered ~{} transitioned ?{} unknown !{} pending",
            self.op,
            self.discovered.len(),
            self.transitions.len(),
            self.unknown.len(),
            self.pending_keep.len()
        );
        OpOutcome {
            scenario,
            discovered: self.discovered,
            transitions: self.transitions,
            pending_keep: self.pending_keep,
            unknown: self.unknown,
            complete,
            note,
        }
    }
}

fn echo_retirement(
    limits: &RunLimits,
    request: &RetireRequest,
    complete: bool,
    diagnostic: Option<String>,
) -> RetirementReport {
    let mut snapshot = request.known_pending().to_vec();
    snapshot.sort_by(|a, b| a.resource_id().cmp(b.resource_id()));
    let mut complete = complete;
    if snapshot.len() as u64 > limits.effects_total() {
        snapshot.truncate(limits.effects_total() as usize);
        complete = false;
    }
    let mut diagnostic = diagnostic;
    if let Some(text) = diagnostic.as_mut() {
        text.truncate(limits.diagnostic_bytes() as usize);
    }
    RetirementReport::new(
        RetirementReportValues {
            call_id: request.call_id(),
            owner: request.owner(),
            scope: request.scope().clone(),
            discovered: vec![],
            transitions: vec![],
            pending_snapshot: snapshot,
            complete,
            diagnostic,
        },
        limits,
    )
    .expect("bounded linux retirement echo")
}

fn seal_bytes(
    op: u64,
    run_id: &str,
    scenario: Scenario,
    slot: &str,
    outcome: &OpOutcome,
) -> Vec<u8> {
    let ids = |labels: &[Label]| {
        labels
            .iter()
            .map(|l| format!("{:?}", l.as_str()))
            .collect::<Vec<_>>()
            .join(",")
    };
    let discovered = ids(&outcome
        .discovered
        .iter()
        .map(|r| r.resource_id().clone())
        .collect::<Vec<_>>());
    let transitions = ids(&outcome
        .transitions
        .iter()
        .map(|t| t.effect().resource_id().clone())
        .collect::<Vec<_>>());
    format!(
        "{{\"schema\":\"tt03.linux.snapshot\",\"revision\":1,\"slot\":{slot:?},\
         \"run_id\":{run_id:?},\"operation_id\":\"{op}\",\"scenario\":{:?},\
         \"discovered\":[{discovered}],\"transitions\":[{transitions}],\
         \"pending\":[{}],\"unknown\":[{}],\"complete\":{},\
         \"conformance\":\"subset-retire\"}}",
        scenario.as_str(),
        ids(&outcome.pending_keep),
        ids(&outcome.unknown),
        outcome.complete,
    )
    .into_bytes()
}

impl LinuxFixtureSession {
    fn fail_pair(&mut self, operation_id: u64, failed: FailedEntry, shutdown: ShutdownReport) {
        let mut failed = failed;
        failed.apply_shutdown(&shutdown);
        self.failed.insert(operation_id, failed);
    }

    /// Retire a prepared pair: cooperative close, exact reaps, explicit
    /// retained-File closes and FD-relative case-dir removal through the
    /// single shutdown, then transitions only for actually settled
    /// composites. Inventory children recorded during advance are
    /// discovered here, exactly once.
    fn retire_prepared(&self, op: u64, entry: PreparedEntry, limits: &RunLimits) -> OpOutcome {
        let PreparedEntry {
            pair,
            process: _process,
            excluded: _excluded,
            files,
            scenario,
            origin,
            file_identities,
        } = entry;
        let a_pid = pair.a_pid();
        let b_pid = pair.b_pid();
        let mut inventory: Vec<(String, Vec<u8>, bool)> = pair
            .inventory_children()
            .iter()
            .map(|record| {
                (
                    if record.positive {
                        "linux.inventory-positive"
                    } else {
                        "linux.inventory-negative"
                    }
                    .to_string(),
                    record.pid.to_le_bytes().to_vec(),
                    record.reaped,
                )
            })
            .collect();
        inventory.sort_by(|a, b| a.0.cmp(&b.0));
        inventory.dedup_by(|a, b| a.0 == b.0);
        let shutdown = pair.shutdown();
        for file in files {
            let owned: rustix::fd::OwnedFd = file.into();
            super::creator::explicit_close_fd(owned);
        }
        let mut out = OutcomeBuilder::new(limits, op, &origin);
        out.known(
            "linux.case-root",
            &op.to_le_bytes(),
            shutdown.case_root_removed,
        );
        out.known(
            "linux.child-a",
            &a_pid.to_le_bytes(),
            shutdown.a_exit.is_some(),
        );
        out.known(
            "linux.child-b",
            &b_pid.to_le_bytes(),
            shutdown.b_exit.is_some(),
        );
        for (label, identity) in &file_identities {
            out.known(label, identity, true);
        }
        for (label, identity, reaped) in &inventory {
            out.found(label, "linux-inventory-child", identity, *reaped);
        }
        out.finish(scenario)
    }

    /// Retire a failed attempt: no native owners remain, so this only
    /// models the recorded evidence. Registrations cover exactly the
    /// proven prefix; sampled-but-unrecoverable files stay sticky-unknown.
    fn retire_failed(&self, op: u64, entry: FailedEntry, limits: &RunLimits) -> OpOutcome {
        let mut out = OutcomeBuilder::new(limits, op, &entry.origin);
        out.found(
            "linux.case-root",
            "linux-case-root",
            &op.to_le_bytes(),
            entry.case_root_removed,
        );
        if let Some(pid) = entry.a_pid {
            out.found(
                "linux.child-a",
                "linux-child",
                &pid.to_le_bytes(),
                entry.a_settled,
            );
        }
        if let Some(pid) = entry.b_pid {
            out.found(
                "linux.child-b",
                "linux-child",
                &pid.to_le_bytes(),
                entry.b_settled,
            );
        }
        for (label, identity) in &entry.file_identities {
            out.found(label, "linux-file", identity, true);
        }
        for label in &entry.file_sampled {
            if !entry.file_identities.iter().any(|(l, _)| l == label) {
                out.unprovable(label);
            }
        }
        let control = entry.control.clone();
        let scenario = entry.scenario;
        let mut outcome = out.finish(scenario);
        if let Some(control) = control {
            outcome.note.push_str(&format!("; control {control}"));
        }
        outcome
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
        // Owner, deadline, record/byte allowances and ledger bounds gate
        // the whole call before any native work: a withheld call emits
        // nothing and leaves every entry untouched for the run-scope retry.
        // Callers must have ended all FixtureAccess borrows first; the
        // engine drops access before retiring.
        let limits = self.contract.limits().clone();
        if request.owner() != Owner::Fixture {
            return echo_retirement(
                &limits,
                request,
                false,
                Some(format!(
                    "fixture retire serves only Owner::Fixture, got {:?}",
                    request.owner()
                )),
            );
        }
        if Instant::now() >= request.deadline() {
            return echo_retirement(
                &limits,
                request,
                false,
                Some("retirement deadline expired; no work performed".to_string()),
            );
        }
        let run_scope = matches!(request.scope(), CleanupScope::Run(_));
        if run_scope {
            self.run_retired = true;
        }
        let ops: Vec<u64> = match request.scope() {
            CleanupScope::Case(key) => vec![*key.operation_id()],
            CleanupScope::Run(_) => {
                let mut ops: Vec<u64> = self
                    .prepared
                    .keys()
                    .chain(self.failed.keys())
                    .chain(self.retired.keys())
                    .copied()
                    .collect();
                ops.sort_unstable();
                ops.dedup();
                ops
            }
        };
        // Outstanding ops still need native work plus first emission.
        let outstanding: Vec<u64> = ops
            .iter()
            .copied()
            .filter(|op| !self.retired.contains_key(op))
            .filter(|op| self.prepared.contains_key(op) || self.failed.contains_key(op))
            .collect();
        // Upper bound: at most seven registrations/transitions per op.
        let bound = outstanding.len() as u64 * 7;
        if bound > request.remaining_records() {
            return echo_retirement(
                &limits,
                request,
                false,
                Some(format!(
                    "retirement record allowance exhausted: need up to {bound} for {} op(s)",
                    outstanding.len()
                )),
            );
        }
        if outstanding.len() as u64 * SEAL_RESERVE_PER_OP > request.remaining_retained_bytes() {
            return echo_retirement(
                &limits,
                request,
                false,
                Some("retirement byte allowance exhausted; no work performed".to_string()),
            );
        }
        let ledger_cap = limits.effects_total();
        if bound * 2 + request.known_pending().len() as u64 > ledger_cap {
            return echo_retirement(
                &limits,
                request,
                false,
                Some("retirement exceeds ledger bounds; no work performed".to_string()),
            );
        }
        // Native work plus first emission for outstanding ops.
        let mut outcomes: Vec<(u64, OpOutcome)> = Vec::new();
        for op in &outstanding {
            let op = *op;
            if let Some(entry) = self.prepared.remove(&op) {
                outcomes.push((op, self.retire_prepared(op, entry, &limits)));
            } else if let Some(entry) = self.failed.remove(&op) {
                outcomes.push((op, self.retire_failed(op, entry, &limits)));
            }
        }
        // Aggregate: repeats contribute stored unknown/completeness only.
        let mut discovered: Vec<EffectRegistration> = Vec::new();
        let mut transitions: Vec<EffectTransition> = Vec::new();
        let mut transitioned_ids: Vec<Label> = Vec::new();
        let mut pending_ids: Vec<Label> = Vec::new();
        let mut unknown_all: Vec<Label> = Vec::new();
        let mut notes: Vec<String> = Vec::new();
        let mut complete = true;
        for op in &ops {
            let op = *op;
            if let Some(outcome) = outcomes.iter().find(|(o, _)| *o == op).map(|(_, o)| o) {
                for registration in &outcome.discovered {
                    if !discovered
                        .iter()
                        .any(|r: &EffectRegistration| r.resource_id() == registration.resource_id())
                    {
                        discovered.push(registration.clone());
                    }
                }
                for transition in &outcome.transitions {
                    transitioned_ids.push(transition.effect().resource_id().clone());
                    transitions.push(transition.clone());
                }
                pending_ids.extend(outcome.pending_keep.iter().cloned());
                unknown_all.extend(outcome.unknown.iter().cloned());
                if !outcome.complete {
                    complete = false;
                }
                notes.push(outcome.note.clone());
                // Seal the scope slot; the first seal wins, repeats keep it.
                let seal = seal_bytes(
                    op,
                    self.contract.run_id().as_str(),
                    outcome.scenario,
                    if run_scope {
                        "run_retire"
                    } else {
                        "case_retire"
                    },
                    outcome,
                );
                if let Some(set) = self.slots.lock().expect("slot lock").get_mut(&op) {
                    if seal.len() as u64 <= SEAL_RESERVE_PER_OP {
                        if run_scope {
                            let _ = set.run_retire.set(seal);
                        } else {
                            let _ = set.case_retire.set(seal);
                        }
                    } else {
                        notes.push(format!("op {op}: seal exceeds reserve; transitions kept"));
                    }
                }
                self.retired.insert(
                    op,
                    RetiredOp {
                        transitioned: outcome
                            .transitions
                            .iter()
                            .map(|t| t.effect().resource_id().clone())
                            .collect(),
                        unknown: outcome.unknown.clone(),
                        complete: outcome.complete,
                    },
                );
            } else if let Some(prior) = self.retired.get(&op) {
                unknown_all.extend(prior.unknown.iter().cloned());
                if !prior.complete {
                    complete = false;
                }
                notes.push(format!(
                    "op {op}: already retired ({} transitioned, {} unknown)",
                    prior.transitioned.len(),
                    prior.unknown.len()
                ));
            }
        }
        discovered.sort_by(|a, b| a.resource_id().cmp(b.resource_id()));
        let mut snapshot: Vec<PendingEffectRef> = request
            .known_pending()
            .iter()
            .filter(|p| !transitioned_ids.contains(p.resource_id()))
            .cloned()
            .collect();
        for registration in &discovered {
            let id = registration.resource_id();
            if pending_ids.contains(id) && !transitioned_ids.contains(id) {
                snapshot.push(PendingEffectRef::registration(registration));
            }
        }
        snapshot.sort_by(|a, b| a.resource_id().cmp(b.resource_id()));
        let mut diagnostic = if notes.is_empty() {
            format!(
                "{} retire: nothing outstanding",
                if run_scope { "run" } else { "case" }
            )
        } else {
            notes.join("; ")
        };
        if !unknown_all.is_empty() {
            unknown_all.sort();
            unknown_all.dedup();
            let names: Vec<&str> = unknown_all.iter().map(Label::as_str).collect();
            diagnostic.push_str(&format!("; sticky unknown: {}", names.join(",")));
        }
        let cap = limits.diagnostic_bytes() as usize;
        diagnostic.truncate(cap);
        RetirementReport::new(
            RetirementReportValues {
                call_id: request.call_id(),
                owner: request.owner(),
                scope: request.scope().clone(),
                discovered,
                transitions,
                pending_snapshot: snapshot,
                complete,
                diagnostic: Some(diagnostic),
            },
            &limits,
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

// Native retire tests live in-crate because RetireRequest has no public
// constructor by design (only the runner builds one). These craft requests
// directly; the worker binary is never needed here because the
// after_case_root_register setup failure fires before any spawn.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CaseCatalog, CaseInvocation, CatalogLimits, CleanupScope, Owner, ProfileId, ProfilePlan,
        RetireRequest, RunContract,
    };
    use std::fs::File;
    use std::time::Duration;

    fn unit_contract() -> (ProfilePlan, RunContract) {
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/harness");
        let catalog = CaseCatalog::load(
            &std::fs::read(dir.join("catalog.json")).unwrap(),
            CatalogLimits::default(),
        )
        .unwrap();
        let plan =
            ProfilePlan::select(&catalog, &ProfileId::parse("tt02-harness-v1").unwrap()).unwrap();
        let contract = RunContract::load(
            &catalog,
            &plan,
            &std::fs::read(dir.join("contract.json")).unwrap(),
            crate::RunLimits::default(),
        )
        .unwrap();
        (plan, contract)
    }

    fn unit_manifest(
        run_hex: &str,
        operation_id: u64,
        control: Option<(&str, &str, &str)>,
    ) -> Vec<u8> {
        let steps: Vec<serde_json::Value> = Scenario::LeaderLifecycle
            .steps()
            .iter()
            .map(|s| {
                serde_json::json!({"id": s.id, "action": s.action.as_str(), "actor": s.actor.as_str()})
            })
            .collect();
        let control_value = match control {
            Some((kind, step_id, point)) => {
                serde_json::json!({"kind": kind, "step_id": step_id, "point": point})
            }
            None => serde_json::Value::Null,
        };
        serde_json::json!({
            "schema_version": 1,
            "kind": "tt03-linux-fixture",
            "run_id": run_hex,
            "image_a_artifact": "tt03-worker-a",
            "image_b_artifact": "tt03-worker-b",
            "limits": {"datagrams": 568, "payload_bytes": 65536},
            "invocations": [{
                "key": {
                    "run_id": run_hex,
                    "case_key": {"case_id": "TT03.first", "case_version": 1, "cell_id": "host"},
                    "attempt": 1,
                    "operation_id": operation_id.to_string(),
                },
                "scenario": "leader-lifecycle",
                "steps": steps,
                "control": control_value,
                "expected_file_a_hex": null,
                "expected_file_b_hex": null,
                "mutation_hex": null,
                "driver_schedule": null,
            }],
        })
        .to_string()
        .into_bytes()
    }

    fn unit_dir(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "tt03-unit-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("image-a"), b"fake-image-a").unwrap();
        std::fs::write(base.join("image-b"), b"fake-image-b").unwrap();
        base
    }

    fn unit_session(
        dir: &std::path::Path,
        contract: &RunContract,
        control: Option<(&str, &str, &str)>,
    ) -> (LinuxFixtureSession, CaseInvocation) {
        let key = contract.schedule()[0].clone();
        let rule = contract
            .case_rules()
            .iter()
            .find(|r| r.case_key() == key.case_key())
            .unwrap();
        let invocation = CaseInvocation::new(
            crate::CaseInvocationValues {
                key: key.clone(),
                observation_schema: rule.observation_schema().clone(),
                fixture_schema: rule.fixture_schema().clone(),
                script: rule.script().clone(),
                limits: contract.limits().clone(),
            },
            contract.limits(),
        )
        .unwrap();
        let op = *key.operation_id();
        let files = LinuxFixtureFiles {
            image_a: File::open(dir.join("image-a")).unwrap(),
            image_a_path: dir.join("image-a"),
            image_b: File::open(dir.join("image-b")).unwrap(),
            image_b_path: dir.join("image-b"),
            root: File::open(dir).unwrap(),
        };
        let manifest = unit_manifest(contract.run_id().as_str(), op, control);
        let session = LinuxFixtureSession::new(
            contract.clone(),
            files,
            &manifest,
            Instant::now() + Duration::from_secs(60),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        (session, invocation)
    }

    fn retire_request(
        call_id: u64,
        owner: Owner,
        scope: CleanupScope,
        remaining_records: u64,
        remaining_retained_bytes: u64,
        deadline: Instant,
    ) -> RetireRequest {
        RetireRequest {
            call_id,
            owner,
            scope,
            deadline,
            remaining: deadline.saturating_duration_since(Instant::now()),
            known_pending: vec![],
            uncertainty_ids: vec![],
            remaining_records,
            remaining_retained_bytes,
        }
    }

    fn prepare_err(
        session: &mut LinuxFixtureSession,
        invocation: &CaseInvocation,
    ) -> crate::FixtureError {
        match session.prepare(invocation) {
            Ok(_) => panic!("prepare must fail"),
            Err(e) => e,
        }
    }

    fn generous_request(call_id: u64, scope: CleanupScope) -> RetireRequest {
        retire_request(
            call_id,
            Owner::Fixture,
            scope,
            4096,
            1 << 20,
            Instant::now() + Duration::from_secs(5),
        )
    }

    #[test]
    fn retire_rejects_foreign_owner_without_work() {
        let dir = unit_dir("owner");
        let (_, contract) = unit_contract();
        let (mut session, invocation) = unit_session(&dir, &contract, None);
        let request = retire_request(
            2,
            Owner::Adapter,
            CleanupScope::Case(invocation.key().clone()),
            4096,
            1 << 20,
            Instant::now() + Duration::from_secs(5),
        );
        let report = session.retire(&request);
        assert_eq!(*report.call_id(), 2);
        assert!(report.discovered().is_empty());
        assert!(report.transitions().is_empty());
        assert!(!*report.complete());
        let diagnostic = report.diagnostic().as_ref().expect("retire diagnostic");
        assert!(diagnostic.contains("Owner::Fixture"), "{diagnostic}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn retire_unknown_operation_echoes_complete() {
        let dir = unit_dir("unknown-op");
        let (_, contract) = unit_contract();
        let (mut session, invocation) = unit_session(&dir, &contract, None);
        let request = generous_request(2, CleanupScope::Case(invocation.key().clone()));
        let report = session.retire(&request);
        assert!(*report.complete());
        assert!(report.discovered().is_empty());
        assert!(report.transitions().is_empty());
        assert!(report.pending_snapshot().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn retire_refuses_expired_deadline_without_work() {
        let dir = unit_dir("deadline");
        let (_, contract) = unit_contract();
        let (mut session, invocation) = unit_session(&dir, &contract, None);
        let request = retire_request(
            2,
            Owner::Fixture,
            CleanupScope::Case(invocation.key().clone()),
            4096,
            1 << 20,
            Instant::now() - Duration::from_secs(1),
        );
        let report = session.retire(&request);
        assert!(!*report.complete());
        assert!(report.transitions().is_empty());
        let diagnostic = report.diagnostic().as_ref().expect("retire diagnostic");
        assert!(diagnostic.contains("deadline"), "{diagnostic}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn retire_discovers_setup_failure_case_root() {
        let dir = unit_dir("setup-fail");
        let (_, contract) = unit_contract();
        let (mut session, invocation) = unit_session(
            &dir,
            &contract,
            Some((
                "parent_failure_after_register",
                "s01-ready",
                "after_case_root_register",
            )),
        );
        let err = prepare_err(&mut session, &invocation);
        assert_eq!(*err.category(), FixtureErrorCategory::Other);
        let request = generous_request(2, CleanupScope::Case(invocation.key().clone()));
        let report = session.retire(&request);
        let discovered: Vec<&str> = report
            .discovered()
            .iter()
            .map(|r| r.resource_id().as_str())
            .collect();
        assert_eq!(discovered, vec!["linux.case-root"]);
        let transitioned: Vec<&str> = report
            .transitions()
            .iter()
            .map(|t| t.effect().resource_id().as_str())
            .collect();
        assert_eq!(transitioned, vec!["linux.case-root"]);
        assert!(*report.complete());
        assert!(report.pending_snapshot().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn retire_withholds_work_when_records_exhausted_then_retries() {
        let dir = unit_dir("records");
        let (_, contract) = unit_contract();
        let (mut session, invocation) = unit_session(
            &dir,
            &contract,
            Some((
                "parent_failure_after_register",
                "s01-ready",
                "after_case_root_register",
            )),
        );
        prepare_err(&mut session, &invocation);
        let starved = retire_request(
            2,
            Owner::Fixture,
            CleanupScope::Case(invocation.key().clone()),
            0,
            1 << 20,
            Instant::now() + Duration::from_secs(5),
        );
        let report = session.retire(&starved);
        assert!(!*report.complete());
        assert!(
            report.discovered().is_empty(),
            "all-or-nothing: no partial emission"
        );
        assert!(report.transitions().is_empty());
        let diagnostic = report.diagnostic().as_ref().expect("retire diagnostic");
        assert!(diagnostic.contains("allowance"), "{diagnostic}");
        // The run-scope retry is the second opportunity; it emits everything.
        let retry = generous_request(4, CleanupScope::Run(contract.run_id().clone()));
        let report = session.retire(&retry);
        assert_eq!(report.discovered().len(), 1);
        assert_eq!(report.transitions().len(), 1);
        assert!(*report.complete());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn retire_is_idempotent_for_failed_operation() {
        let dir = unit_dir("idempotent");
        let (_, contract) = unit_contract();
        let (mut session, invocation) = unit_session(
            &dir,
            &contract,
            Some((
                "parent_failure_after_register",
                "s01-ready",
                "after_case_root_register",
            )),
        );
        prepare_err(&mut session, &invocation);
        let first = session.retire(&generous_request(
            2,
            CleanupScope::Case(invocation.key().clone()),
        ));
        assert!(*first.complete());
        let second = session.retire(&generous_request(
            4,
            CleanupScope::Run(contract.run_id().clone()),
        ));
        assert!(second.discovered().is_empty(), "no rediscovery on retry");
        assert!(
            second.transitions().is_empty(),
            "no double transition on retry"
        );
        assert!(*second.complete());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn prepare_refuses_already_attempted_operation() {
        let dir = unit_dir("reattempt");
        let (_, contract) = unit_contract();
        let (mut session, invocation) = unit_session(
            &dir,
            &contract,
            Some((
                "parent_failure_after_register",
                "s01-ready",
                "after_case_root_register",
            )),
        );
        prepare_err(&mut session, &invocation);
        let err = prepare_err(&mut session, &invocation);
        assert!(
            String::from_utf8_lossy(err.diagnostic_bytes()).contains("already attempted"),
            "admission stops after the attempt: {:?}",
            String::from_utf8_lossy(err.diagnostic_bytes())
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn run_retire_stops_admission() {
        let dir = unit_dir("run-stop");
        let (_, contract) = unit_contract();
        let (mut session, invocation) = unit_session(&dir, &contract, None);
        let report = session.retire(&generous_request(
            4,
            CleanupScope::Run(contract.run_id().clone()),
        ));
        assert!(*report.complete());
        let err = prepare_err(&mut session, &invocation);
        assert!(
            String::from_utf8_lossy(err.diagnostic_bytes()).contains("run is retired"),
            "run retire stops admission: {:?}",
            String::from_utf8_lossy(err.diagnostic_bytes())
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
