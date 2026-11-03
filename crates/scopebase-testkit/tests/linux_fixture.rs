// SPDX-License-Identifier: Apache-2.0
//! TT03 first-increment integration: public session API plus the packaged
//! worker driven through the developer driver. Wire/manifest/creator internals
//! are covered by unit tests inside their private modules.
use scopebase_testkit::fixture::linux::{
    clean_shutdown_gate, launch_pair, verify_retirement_exactly_once, verify_unknown_sticky,
    Control, CustodyClaim, DriverErrorKind, LaunchConfig, LinuxFixtureFiles, LinuxFixtureSession,
    LinuxOuterCleanupAdmissionErrorKind, LinuxOuterCleanupBudget, LinuxProcessFixture, Scenario,
    TRICKY_COMM,
};
use scopebase_testkit::{
    CaseErrorCategory, CaseInvocationValues, CleanupCallStatus, CleanupScope, CleanupState,
    ConformanceAdapter, Digest256, EffectBatch, EffectRegistration, EffectTransition,
    EffectTransitionValues, FixtureAccess, FixtureErrorCategory, FixtureSession, Label,
    Observation, Owner, PendingEffectRef, PendingEffectRefValues, RetireRequest, RetirementReport,
    RetirementReportValues, RunLimits, TransitionTo,
};
use std::fs::File;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[path = "fixtures/harness/support.rs"]
mod support;

fn worker_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_scopebase-tt03-worker"))
}

static TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// S229/R32: process-start nonce so a rerun under a recycled PID never
/// collides with crash residue (which would otherwise refuse below).
static START_NONCE: std::sync::OnceLock<u128> = std::sync::OnceLock::new();

fn start_nonce() -> u128 {
    *START_NONCE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    })
}

/// S229/R32: exclusively create a private temp dir. A pre-existing
/// candidate (preplanted symlink, stale residue) is refused loudly:
/// silently reusing it would let a planted link redirect staged
/// worker images outside the temp tree.
fn claim_temp_dir(dir: &std::path::Path) {
    match std::fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) => panic!(
            "refused: temp candidate {} already exists ({e})",
            dir.display()
        ),
    }
}

fn temp_root(tag: &str) -> (PathBuf, File) {
    let id = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let base = std::env::temp_dir().join(format!(
        "tt03-{}-{}-{}-{:x}",
        tag,
        std::process::id(),
        id,
        start_nonce()
    ));
    claim_temp_dir(&base);
    let dir = File::open(&base).unwrap();
    (base, dir)
}

fn stage_images(dir: &std::path::Path) -> (File, PathBuf, File, PathBuf) {
    let wb = worker_bin();
    assert!(wb.is_absolute(), "worker path must be absolute");
    let pa = dir.join("image-a");
    let pb = dir.join("image-b");
    std::fs::copy(&wb, &pa).unwrap();
    std::fs::copy(&wb, &pb).unwrap();
    for p in [&pa, &pb] {
        let stripped = std::process::Command::new("strip")
            .arg(p)
            .status()
            .expect("binutils strip stages packaged-size images");
        assert!(stripped.success(), "strip must succeed");
    }
    use std::os::unix::fs::PermissionsExt;
    for p in [&pa, &pb] {
        let mut perm = std::fs::metadata(p).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(p, perm).unwrap();
    }
    (File::open(&pa).unwrap(), pa, File::open(&pb).unwrap(), pb)
}

fn manifest_bytes(run_hex: &str, scenario: &str, operation_id: u64) -> Vec<u8> {
    manifest_bytes_control(run_hex, scenario, operation_id, None)
}

fn manifest_bytes_control(
    run_hex: &str,
    scenario: &str,
    operation_id: u64,
    control: Option<(&str, &str, &str)>,
) -> Vec<u8> {
    let steps: Vec<serde_json::Value> = Scenario::parse(scenario)
        .unwrap()
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
            "scenario": scenario,
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

fn make_files(dir: &std::path::Path, root: File) -> LinuxFixtureFiles {
    let (fa, pa, fb, pb) = stage_images(dir);
    LinuxFixtureFiles {
        image_a: fa,
        image_a_path: pa,
        image_b: fb,
        image_b_path: pb,
        root,
    }
}

#[test]
fn constructor_rejects_malformed_manifest_and_returns_assets() {
    let (_, _, contract) = support::load();
    let (dir, root) = temp_root("bad-manifest");
    let files = make_files(&dir, root);
    let cancel = Arc::new(AtomicBool::new(false));
    let err = LinuxFixtureSession::new(
        contract.clone(),
        files,
        b"{not json",
        Instant::now() + Duration::from_secs(60),
        cancel,
    )
    .unwrap_err();
    assert_eq!(*err.error.category(), FixtureErrorCategory::InvalidProtocol);
    assert_eq!(err.contract.sha256(), contract.sha256());
    assert!(err.files.image_a_path.ends_with("image-a"));
    assert!(!err.custody.constructor_ledger().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn constructor_accepts_valid_manifest_without_spawning() {
    let (_, _, contract) = support::load();
    let (dir, root) = temp_root("good-manifest");
    let files = make_files(&dir, root);
    let manifest = manifest_bytes(contract.run_id().as_str(), "leader-lifecycle", 7);
    let cancel = Arc::new(AtomicBool::new(false));
    let session = LinuxFixtureSession::new(
        contract.clone(),
        files,
        &manifest,
        Instant::now() + Duration::from_secs(60),
        cancel,
    )
    .unwrap();
    assert_eq!(session.contract().sha256(), contract.sha256());
    assert!(session.outer_cleanup_report().is_none());
    let key = &contract.schedule()[0];
    assert!(session.raw_ledger(key).is_none());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn constructor_rejects_relative_image_path() {
    let (_, _, contract) = support::load();
    let (dir, root) = temp_root("rel-path");
    let (fa, _, fb, pb) = stage_images(&dir);
    let files = LinuxFixtureFiles {
        image_a: fa,
        image_a_path: PathBuf::from("relative/image-a"),
        image_b: fb,
        image_b_path: pb,
        root,
    };
    let manifest = manifest_bytes(contract.run_id().as_str(), "leader-lifecycle", 7);
    let cancel = Arc::new(AtomicBool::new(false));
    let err = LinuxFixtureSession::new(
        contract,
        files,
        &manifest,
        Instant::now() + Duration::from_secs(60),
        cancel,
    )
    .unwrap_err();
    assert_eq!(*err.error.category(), FixtureErrorCategory::InvalidProtocol);
    std::fs::remove_dir_all(&dir).unwrap();
}

fn valid_session(
    dir: &std::path::Path,
    scenario: &str,
) -> (
    LinuxFixtureSession,
    scopebase_testkit::RunContract,
    scopebase_testkit::RunLimits,
) {
    let (_, _, contract) = support::load();
    let root = File::open(dir).unwrap();
    let files = make_files(dir, root);
    let manifest = manifest_bytes(contract.run_id().as_str(), scenario, 9);
    let cancel = Arc::new(AtomicBool::new(false));
    let session = LinuxFixtureSession::new(
        contract.clone(),
        files,
        &manifest,
        Instant::now() + Duration::from_secs(60),
        cancel,
    )
    .unwrap();
    let limits = contract.limits().clone();
    (session, contract, limits)
}

#[test]
fn finalize_static_checks_and_one_shot() {
    let (dir, _root) = temp_root("finalize");
    let (mut session, _, _) = valid_session(&dir, "leader-lifecycle");
    let mk = |deadline: Instant, attempts: u64, records: u64, bytes: u64| LinuxOuterCleanupBudget {
        deadline,
        max_native_attempts: attempts,
        max_records: records,
        max_retained_bytes: bytes,
    };
    let soon = Instant::now() + Duration::from_secs(2);
    assert!(matches!(
        session
            .finalize(mk(Instant::now() - Duration::from_secs(1), 64, 8, 65536))
            .unwrap_err()
            .kind(),
        LinuxOuterCleanupAdmissionErrorKind::ExpiredDeadline
    ));
    assert!(matches!(
        session
            .finalize(mk(soon, 20000, 8, 65536))
            .unwrap_err()
            .kind(),
        LinuxOuterCleanupAdmissionErrorKind::AllowanceOutOfRange
    ));
    assert!(matches!(
        session.finalize(mk(soon, 64, 0, 65536)).unwrap_err().kind(),
        LinuxOuterCleanupAdmissionErrorKind::AllowanceOutOfRange
    ));
    assert!(matches!(
        session
            .finalize(mk(soon, 64, 8, 2 * 1024 * 1024))
            .unwrap_err()
            .kind(),
        LinuxOuterCleanupAdmissionErrorKind::InsufficientTerminalCapacity
    ));
    let first = session
        .finalize(mk(soon, 64, 8, 65536))
        .unwrap()
        .as_bytes()
        .to_vec();
    assert!(!first.is_empty());
    let again = session
        .finalize(mk(
            Instant::now() + Duration::from_secs(3),
            100,
            100,
            100000,
        ))
        .unwrap()
        .as_bytes()
        .to_vec();
    assert_eq!(first, again, "repeat finalize performs no new work");
    assert_eq!(session.outer_cleanup_report().unwrap().as_bytes(), first);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn finalize_no_prepare_reports_clean() {
    let (dir, _root) = temp_root("finalize-clean");
    let (mut session, _, _) = valid_session(&dir, "leader-lifecycle");
    let report = session
        .finalize(LinuxOuterCleanupBudget {
            deadline: Instant::now() + Duration::from_secs(4),
            max_native_attempts: 512,
            max_records: 64,
            max_retained_bytes: 262144,
        })
        .unwrap()
        .as_bytes()
        .to_vec();
    let v: serde_json::Value = serde_json::from_slice(&report).unwrap();
    assert_eq!(v["kind"], "clean");
    assert!(v["native_cleanup_effects"].as_u64().unwrap() >= 3);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn custody_finalize_close_only_and_one_shot() {
    let (_, _, contract) = support::load();
    let (dir, root) = temp_root("custody");
    let files = make_files(&dir, root);
    let mut failure = LinuxFixtureSession::new(
        contract,
        files,
        b"{\"schema_version\":2}",
        Instant::now() + Duration::from_secs(60),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap_err();
    assert!(!failure.custody.constructor_ledger().is_empty());
    assert!(failure.custody.admission_cleanup_report().is_none());
    let mk = || LinuxOuterCleanupBudget {
        deadline: Instant::now() + Duration::from_secs(2),
        max_native_attempts: 64,
        max_records: 8,
        max_retained_bytes: 65536,
    };
    let first = failure.custody.finalize(mk()).unwrap().as_bytes().to_vec();
    let again = failure.custody.finalize(mk()).unwrap().as_bytes().to_vec();
    assert_eq!(first, again);
    std::fs::remove_dir_all(&dir).unwrap();
}

fn invocation_for(contract: &scopebase_testkit::RunContract) -> scopebase_testkit::CaseInvocation {
    let key = contract.schedule()[0].clone();
    let rule = contract
        .case_rules()
        .iter()
        .find(|r| r.case_key() == key.case_key())
        .unwrap();
    scopebase_testkit::CaseInvocation::new(
        CaseInvocationValues {
            key,
            observation_schema: rule.observation_schema().clone(),
            fixture_schema: rule.fixture_schema().clone(),
            script: rule.script().clone(),
            limits: contract.limits().clone(),
        },
        contract.limits(),
    )
    .unwrap()
}

fn native_session(
    dir: &std::path::Path,
    scenario: &str,
) -> (
    LinuxFixtureSession,
    scopebase_testkit::RunContract,
    scopebase_testkit::CaseInvocation,
) {
    native_session_control(dir, scenario, None)
}

fn native_session_control(
    dir: &std::path::Path,
    scenario: &str,
    control: Option<(&str, &str, &str)>,
) -> (
    LinuxFixtureSession,
    scopebase_testkit::RunContract,
    scopebase_testkit::CaseInvocation,
) {
    let (_, _, contract) = support::load();
    let invocation = invocation_for(&contract);
    let op = *invocation.key().operation_id();
    let root = File::open(dir).unwrap();
    let files = make_files(dir, root);
    let manifest = manifest_bytes_control(contract.run_id().as_str(), scenario, op, control);
    let cancel = Arc::new(AtomicBool::new(false));
    let session = LinuxFixtureSession::new(
        contract.clone(),
        files,
        &manifest,
        Instant::now() + Duration::from_secs(60),
        cancel,
    )
    .unwrap();
    (session, contract, invocation)
}

#[test]
fn prepare_collect_run_native_prefix() {
    let (dir, _root) = temp_root("prepare-native");
    let (mut session, _, invocation) = native_session(&dir, "leader-lifecycle");
    let access = session
        .prepare(&invocation)
        .expect("native prepare runs the ready prefix");
    let proc = access
        .resource::<LinuxProcessFixture>(&Label::parse("linux.process").unwrap())
        .expect("linux.process resource");
    assert!(proc.pid() > 0);
    let excluded = access
        .resource::<LinuxProcessFixture>(&Label::parse("linux.excluded-process").unwrap())
        .expect("linux.excluded-process resource");
    assert!(excluded.pid() > 0 && excluded.pid() != proc.pid());
    assert_eq!(
        excluded.nonleader_tid(),
        None,
        "excluded fixture exposes no TID"
    );
    let refused = excluded
        .advance(&label("s01-ready"))
        .expect_err("excluded fixture must refuse advance");
    assert_eq!(refused.category(), FixtureErrorCategory::Denied);
    assert_eq!(refused.step_id(), &label("s01-ready"));
    assert_eq!(
        refused.diagnostic_bytes(),
        b"excluded fixture does not advance".as_slice()
    );
    assert!(
        access.effects().registrations().len() >= 3,
        "prepare registers case-root and both children"
    );
    let evidence = session
        .collect(&invocation)
        .expect("native collect seals drained raw");
    assert_eq!(evidence.key(), invocation.key());
    assert!(!evidence.expected_bytes().is_empty());
    assert!(!evidence.ledger_bytes().is_empty());
    session
        .finalize(LinuxOuterCleanupBudget {
            deadline: Instant::now() + Duration::from_secs(2),
            max_native_attempts: 512,
            max_records: 64,
            max_retained_bytes: 262144,
        })
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn prepare_unknown_operation_refused() {
    let (dir, _root) = temp_root("prepare-unknown-op");
    let (_, _, contract) = support::load();
    let invocation = invocation_for(&contract);
    let wrong_op = *invocation.key().operation_id() + 1000;
    let root = File::open(&dir).unwrap();
    let files = make_files(&dir, root);
    let manifest = manifest_bytes(contract.run_id().as_str(), "leader-lifecycle", wrong_op);
    let cancel = Arc::new(AtomicBool::new(false));
    let mut session = LinuxFixtureSession::new(
        contract.clone(),
        files,
        &manifest,
        Instant::now() + Duration::from_secs(60),
        cancel,
    )
    .unwrap();
    let err = match session.prepare(&invocation) {
        Ok(_) => panic!("unadmitted operation must not prepare"),
        Err(e) => e,
    };
    assert_eq!(
        *err.category(),
        FixtureErrorCategory::InvalidProtocol,
        "unadmitted operation must be a typed refusal, not a spawn"
    );
    session
        .finalize(LinuxOuterCleanupBudget {
            deadline: Instant::now() + Duration::from_secs(2),
            max_native_attempts: 512,
            max_records: 64,
            max_retained_bytes: 262144,
        })
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

fn live_pair_with_images(
    scenario: Scenario,
    op: u64,
    distinct: bool,
) -> (scopebase_testkit::fixture::linux::LivePair, PathBuf) {
    let (dir, root) = temp_root("live");
    let (fa, pa, fb, pb) = if distinct {
        stage_distinct_images(&dir)
    } else {
        stage_images(&dir)
    };
    drop((fa, fb));
    let cfg = LaunchConfig {
        worker: pa.clone(),
        image_a: pa,
        image_b: pb,
        root,
        run_hex: "00".repeat(16),
        operation_id: op,
        manifest_sha256: [0u8; 32],
        scenario,
        deadline_ns: u64::MAX,
        cancel: Arc::new(AtomicBool::new(false)),
        control: None,
    };
    let pair = launch_pair(&cfg).unwrap();
    (pair, dir)
}

fn live_pair(
    scenario: Scenario,
    op: u64,
) -> (scopebase_testkit::fixture::linux::LivePair, PathBuf) {
    live_pair_with_images(scenario, op, false)
}

fn outage_control(kind: &str, step_id: &str, point: &str) -> Control {
    Control {
        kind: kind.to_string(),
        step_id: step_id.to_string(),
        point: point.to_string(),
    }
}

fn launch_config_with_control(
    dir: &std::path::Path,
    root: File,
    scenario: Scenario,
    op: u64,
    control: Option<Control>,
) -> (LaunchConfig, PathBuf) {
    let (fa, pa, fb, pb) = stage_images(dir);
    drop((fa, fb));
    let cfg = LaunchConfig {
        worker: pa.clone(),
        image_a: pa,
        image_b: pb,
        root,
        run_hex: "00".repeat(16),
        operation_id: op,
        manifest_sha256: [0u8; 32],
        scenario,
        deadline_ns: u64::MAX,
        cancel: Arc::new(AtomicBool::new(false)),
        control,
    };
    (cfg, dir.to_path_buf())
}

fn live_pair_with_control(
    scenario: Scenario,
    op: u64,
    control: Control,
) -> (scopebase_testkit::fixture::linux::LivePair, PathBuf) {
    let (dir, root) = temp_root("live-outage");
    let (cfg, dir) = launch_config_with_control(&dir, root, scenario, op, Some(control));
    let pair = launch_pair(&cfg).unwrap();
    (pair, dir)
}

fn case_path(dir: &std::path::Path, op: u64) -> PathBuf {
    dir.join(format!("tt03-{}-{op}", "00".repeat(16)))
}

fn hex_of(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

fn stage_distinct_images(dir: &std::path::Path) -> (File, PathBuf, File, PathBuf) {
    use std::io::Write;
    let (fa, pa, fb, pb) = stage_images(dir);
    drop((fa, fb));
    for (path, marker) in [(&pa, b'A'), (&pb, b'B')] {
        let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        let trailer = [marker; 64];
        file.write_all(&trailer).unwrap();
        file.sync_all().unwrap();
    }
    assert_ne!(
        std::fs::read(&pa).unwrap(),
        std::fs::read(&pb).unwrap(),
        "distinct staged images must differ"
    );
    (File::open(&pa).unwrap(), pa, File::open(&pb).unwrap(), pb)
}

fn exe_sha256(pid: u32) -> [u8; 32] {
    exe_sha256_as(pid, None)
}

fn exe_sha256_as(pid: u32, live_tid: Option<u32>) -> [u8; 32] {
    let path = match live_tid {
        Some(tid) => format!("/proc/{pid}/task/{tid}/exe"),
        None => format!("/proc/{pid}/exe"),
    };
    let bytes = std::fs::read(path).unwrap();
    scopebase_testkit::fixture::linux::wire::sha256_of(&bytes)
}

fn task_tids(pid: u32) -> Vec<u32> {
    let mut tids: Vec<u32> = std::fs::read_dir(format!("/proc/{pid}/task"))
        .unwrap()
        .map(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .parse::<u32>()
                .unwrap()
        })
        .collect();
    tids.sort_unstable();
    tids
}

fn task_state(pid: u32, tid: u32) -> u8 {
    let stat = std::fs::read(format!("/proc/{pid}/task/{tid}/stat")).unwrap();
    let (_, state, _) =
        scopebase_testkit::fixture::linux::parse_stat_comm_state_starttime(&stat).unwrap();
    state
}

fn label(id: &str) -> Label {
    Label::parse(id).unwrap()
}

#[test]
fn worker_hello_ready_capture_close_roundtrip() {
    let (pair, dir) = live_pair(Scenario::LeaderLifecycle, 11);
    assert!(pair.a_pid() > 0 && pair.b_pid() > 0 && pair.a_pid() != pair.b_pid());
    let a: LinuxProcessFixture = pair.a_process();
    assert_eq!(a.pid(), pair.a_pid());
    assert_eq!(a.nonleader_tid(), None);
    a.advance(&label("s01-ready")).unwrap();
    pair.b_heartbeat(&label("s01-ready")).unwrap();
    a.advance(&label("s02-live")).unwrap();
    let raw = pair.drained_raw();
    assert!(!raw.is_empty());
    let task = raw.iter().find(|r| r.kind == "task").expect("task record");
    assert_eq!(task.actor, "a");
    let body: serde_json::Value = serde_json::from_slice(&task.bytes).unwrap();
    assert_eq!(body["values"]["pid"], pair.a_pid());
    assert!(a.advance(&label("s07-close")).is_err());
    a.advance(&label("s03-exit")).unwrap();
    a.advance(&label("s04-zombie")).unwrap();
    a.advance(&label("s05-reap")).unwrap();
    a.advance(&label("s06-reaped")).unwrap();
    a.advance(&label("s07-close")).unwrap();
    let report = pair.shutdown();
    assert!(report.case_root_removed);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn tricky_comm_birth_invariant() {
    let (pair, dir) = live_pair(Scenario::TrickyComm, 12);
    let a = pair.a_process();
    a.advance(&label("s01-ready")).unwrap();
    a.advance(&label("s02-comm")).unwrap();
    let stat = std::fs::read(format!("/proc/{}/stat", pair.a_pid())).unwrap();
    let (comm, state, start) =
        scopebase_testkit::fixture::linux::parse_stat_comm_state_starttime(&stat).unwrap();
    assert_eq!(comm, TRICKY_COMM.as_bytes());
    assert_ne!(state, b'Z', "live worker is not a zombie");
    assert!(!scopebase_testkit::fixture::linux::stat_is_zombie(&stat).unwrap());
    a.advance(&label("s03-live")).unwrap();
    a.advance(&label("s04-exit")).unwrap();
    let zstat = std::fs::read(format!("/proc/{}/stat", pair.a_pid())).unwrap();
    let (_, _, zstart) =
        scopebase_testkit::fixture::linux::parse_stat_comm_state_starttime(&zstat).unwrap();
    assert_eq!(zstart, start, "same birth across live and zombie");
    assert!(scopebase_testkit::fixture::linux::stat_is_zombie(&zstat).unwrap());
    a.advance(&label("s05-zombie")).unwrap();
    a.advance(&label("s06-reap")).unwrap();
    a.advance(&label("s07-reaped")).unwrap();
    a.advance(&label("s08-close")).unwrap();
    pair.shutdown();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn wnowait_lifecycle_order() {
    use scopebase_testkit::fixture::linux::exited_unreaped_owned;
    let (pair, dir) = live_pair(Scenario::LeaderLifecycle, 13);
    let a = pair.a_process();
    a.advance(&label("s01-ready")).unwrap();
    assert_eq!(pair.a_exited_unreaped().unwrap(), None);
    assert_eq!(exited_unreaped_owned(pair.a_pid(), 4).unwrap(), None);
    pair.terminate_a().unwrap();
    assert!(pair.a_exit_ready(5000).unwrap());
    assert_eq!(pair.a_exited_unreaped().unwrap(), Some(libc::CLD_KILLED));
    let reaped = pair.reap_a().unwrap();
    assert_eq!(reaped.signal, Some(libc::SIGKILL));
    assert_eq!(
        exited_unreaped_owned(pair.a_pid(), 4)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ECHILD)
    );
    pair.b_heartbeat(&label("s02-live")).unwrap();
    pair.shutdown();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn replacement_keeps_original_fd() {
    use scopebase_linux::control::OperationControl;
    use scopebase_linux::file::{HeldFile, ReadLimits};
    let (pair, dir) = live_pair(Scenario::FileReplacement, 14);
    let a = pair.a_process();
    let blob_a = b"alpha-content-001".to_vec();
    let blob_b = b"beta--content-002".to_vec();
    assert_eq!(blob_a.len(), blob_b.len());
    let mutation = b"ALPHA-CONTENT-001".to_vec();
    pair.upload_blobs(&blob_a, &blob_b, &mutation).unwrap();
    for step in ["s01-ready", "s02-create-files", "s03-offer-files"] {
        a.advance(&label(step)).unwrap();
    }
    let fa_clone = pair.pulled_file_a().unwrap();
    let held = HeldFile::from_file(fa_clone).unwrap();
    let before = held.stat().unwrap().key();
    let limits = ReadLimits {
        max_bytes: 1024,
        max_read_calls: 4,
        max_buffer_capacity: 2048,
    };
    let control = OperationControl::unlimited();
    let read = held.read_all(limits, &control).unwrap();
    assert_eq!(read.bytes(), blob_a.as_slice());
    a.advance(&label("s04-original")).unwrap();
    a.advance(&label("s05-replace")).unwrap();
    a.advance(&label("s06-replaced")).unwrap();
    let after_replace = held.stat().unwrap().key();
    assert_eq!(
        (after_replace.device_raw(), after_replace.inode()),
        (before.device_raw(), before.inode())
    );
    a.advance(&label("s07-unlink")).unwrap();
    let still = held.read_all(limits, &control).unwrap();
    assert_eq!(still.bytes(), blob_a.as_slice());
    a.advance(&label("s08-mutate")).unwrap();
    let mutated = held.read_all(limits, &control).unwrap();
    assert_eq!(mutated.bytes(), mutation.as_slice());
    a.advance(&label("s09-mutated")).unwrap();
    a.advance(&label("s10-close")).unwrap();
    pair.shutdown();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn wrong_image_refused_before_grant() {
    let (dir, root) = temp_root("wrong-image");
    let (fa, pa, _fb, _pb) = stage_images(&dir);
    drop(fa);
    let other = dir.join("unrelated");
    std::fs::copy("/bin/true", &other).unwrap();
    let cfg = LaunchConfig {
        worker: pa.clone(),
        image_a: other,
        image_b: pa.clone(),
        root,
        run_hex: "11".repeat(16),
        operation_id: 15,
        manifest_sha256: [0u8; 32],
        scenario: Scenario::LeaderLifecycle,
        deadline_ns: u64::MAX,
        cancel: Arc::new(AtomicBool::new(false)),
        control: None,
    };
    let err = launch_pair(&cfg).unwrap_err();
    assert!(matches!(err.kind(), DriverErrorKind::Refused));
    assert!(err.cleanup_proof().a_reaped);
    let case_dir = dir.join(format!("tt03-{}-15", "11".repeat(16)));
    if case_dir.exists() {
        assert_eq!(std::fs::read_dir(&case_dir).unwrap().count(), 0);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn cancel_before_create_spawns_nothing() {
    let (dir, root) = temp_root("cancel-create");
    let (fa, pa, fb, pb) = stage_images(&dir);
    drop((fa, fb));
    let cancel = Arc::new(AtomicBool::new(true));
    let cfg = LaunchConfig {
        worker: pa.clone(),
        image_a: pa,
        image_b: pb,
        root,
        run_hex: "22".repeat(16),
        operation_id: 16,
        manifest_sha256: [0u8; 32],
        scenario: Scenario::LeaderLifecycle,
        deadline_ns: u64::MAX,
        cancel,
        control: None,
    };
    let err = launch_pair(&cfg).unwrap_err();
    assert!(matches!(err.kind(), DriverErrorKind::Cancelled));
    assert!(!err.cleanup_proof().spawned);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn observation_does_not_control_target() {
    let (pair, dir) = live_pair(Scenario::LeaderLifecycle, 17);
    let a = pair.a_process();
    a.advance(&label("s01-ready")).unwrap();
    let _ = pair.drained_raw();
    let stat_a = std::fs::read(format!("/proc/{}/stat", pair.a_pid())).unwrap();
    let stat_b = std::fs::read(format!("/proc/{}/stat", pair.b_pid())).unwrap();
    assert!(!stat_a.is_empty() && !stat_b.is_empty());
    assert_eq!(pair.a_exited_unreaped().unwrap(), None);
    pair.b_heartbeat(&label("s02-live")).unwrap();
    a.advance(&label("s02-live")).unwrap();
    assert_eq!(pair.a_exited_unreaped().unwrap(), None);
    a.advance(&label("s03-exit")).unwrap();
    a.advance(&label("s04-zombie")).unwrap();
    a.advance(&label("s05-reap")).unwrap();
    a.advance(&label("s06-reaped")).unwrap();
    a.advance(&label("s07-close")).unwrap();
    pair.shutdown();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn accepted_components_consumed() {
    use scopebase_linux::control::OperationControl;
    use scopebase_linux::file::{HeldFile, ProcFdResolver, ReadLimits, SymlinkPolicy};
    use scopebase_linux::procfs::{parse_maps, parse_mountinfo, ParseLimits};
    let (dir, _root) = temp_root("accepted");
    let path = dir.join("probe.txt");
    std::fs::write(&path, b"0123456789abcdef").unwrap();
    let resolver = ProcFdResolver::open_self().unwrap();
    let held = HeldFile::open(&path, &resolver, SymlinkPolicy::RejectFinal).unwrap();
    let limits = ReadLimits {
        max_bytes: 64,
        max_read_calls: 4,
        max_buffer_capacity: 128,
    };
    let read = held
        .read_all(limits, &OperationControl::unlimited())
        .unwrap();
    assert_eq!(read.bytes(), b"0123456789abcdef");
    assert!(read.charges().read_calls() >= 1);
    let maps = std::fs::read("/proc/self/maps").unwrap();
    let snapshot = parse_maps(
        &maps,
        ParseLimits {
            max_bytes: maps.len(),
            max_entries: 4096,
            max_line_bytes: 8192,
        },
    )
    .unwrap();
    assert!(snapshot.entries().len() > 0);
    let sample = b"22 28 0:20 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw\n";
    let mounts = parse_mountinfo(
        sample,
        ParseLimits {
            max_bytes: sample.len(),
            max_entries: 4,
            max_line_bytes: 8192,
        },
    )
    .unwrap();
    assert_eq!(mounts.entries().len(), 1);
    // RATIFY-2026-10-23-LX05-NSFS (LX06 repair): real kernels
    // render namespace pseudo-names as nsfs mount roots; the
    // accepted parser admits exactly that documented shape
    // (unknown non-`/` roots still refuse, pinned by the
    // parser's own unit tests).
    let nsfs = b"1572 34 0:5 net:[4026532307] /run/docker/netns/5014e9543e94 rw shared:1132 - nsfs nsfs rw\n";
    let table = parse_mountinfo(
        nsfs,
        ParseLimits {
            max_bytes: nsfs.len(),
            max_entries: 4,
            max_line_bytes: 8192,
        },
    )
    .expect("accepted parser admits ratified nsfs pseudo-root");
    assert_eq!(table.entries().len(), 1);
    let entry = table.entries().next().unwrap();
    assert_eq!(entry.root().decoded(), b"net:[4026532307]");
    assert_eq!(entry.filesystem_type().decoded(), b"nsfs");
    assert_eq!(entry.source().decoded(), b"nsfs");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn python_oracle_agrees_on_tricky_stat() {
    let oracle = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("oracle/tt03_stat_oracle.py");
    let vectors = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("oracle/tt03_stat_vectors.json");
    let (pair, dir) = live_pair(Scenario::TrickyComm, 18);
    let a = pair.a_process();
    a.advance(&label("s01-ready")).unwrap();
    a.advance(&label("s02-comm")).unwrap();
    let stat = std::fs::read(format!("/proc/{}/stat", pair.a_pid())).unwrap();
    let out = std::process::Command::new("python3")
        .arg(&oracle)
        .arg("--vectors")
        .arg(&vectors)
        .arg("--live-stat")
        .arg(String::from_utf8_lossy(&stat).into_owned())
        .arg("--expect-comm")
        .arg(TRICKY_COMM)
        .output()
        .expect("python3 runs the delivered oracle");
    assert!(
        out.status.success(),
        "oracle failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let verdict: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(verdict["verdict"], "pass");
    assert_eq!(verdict["live"]["comm"], TRICKY_COMM);
    a.advance(&label("s03-live")).unwrap();
    a.advance(&label("s04-exit")).unwrap();
    a.advance(&label("s05-zombie")).unwrap();
    a.advance(&label("s06-reap")).unwrap();
    a.advance(&label("s07-reaped")).unwrap();
    a.advance(&label("s08-close")).unwrap();
    pair.shutdown();
    std::fs::remove_dir_all(&dir).unwrap();
}

fn proc_starttime(pid: u32) -> u64 {
    let stat = std::fs::read(format!("/proc/{pid}/stat")).unwrap();
    let (_, _, start) =
        scopebase_testkit::fixture::linux::parse_stat_comm_state_starttime(&stat).unwrap();
    start
}

#[test]
fn exec_failure_keeps_current_image() {
    let (pair, dir) = live_pair(Scenario::ExecFailure, 22);
    let a = pair.a_process();
    let sha_before = exe_sha256(pair.a_pid());
    let start_before = proc_starttime(pair.a_pid());
    a.advance(&label("s01-ready")).unwrap();
    a.advance(&label("s02-before")).unwrap();
    a.advance(&label("s03-missing"))
        .expect("real failed exec attempt with ENOENT evidence");
    assert_eq!(exe_sha256(pair.a_pid()), sha_before, "image unchanged");
    assert_eq!(proc_starttime(pair.a_pid()), start_before, "same birth");
    let raw = pair.drained_raw();
    let exec = raw.iter().find(|r| r.kind == "exec").expect("exec record");
    let body: serde_json::Value = serde_json::from_slice(&exec.bytes).unwrap();
    assert_eq!(body["errno"], libc::ENOENT);
    assert_eq!(body["call_result"], "failed");
    a.advance(&label("s04-after")).unwrap();
    a.advance(&label("s05-close")).unwrap();
    pair.shutdown();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn exec_aba_preserves_birth_not_image() {
    let (pair, dir) = live_pair_with_images(Scenario::ExecAba, 23, true);
    let a = pair.a_process();
    let sha_a = exe_sha256(pair.a_pid());
    let start = proc_starttime(pair.a_pid());
    a.advance(&label("s01-ready")).unwrap();
    a.advance(&label("s02-a")).unwrap();
    a.advance(&label("s03-exec-b"))
        .expect("real exec to image B");
    let sha_b = exe_sha256(pair.a_pid());
    assert_ne!(sha_a, sha_b, "executable image changed at A->B");
    assert_eq!(
        proc_starttime(pair.a_pid()),
        start,
        "birth preserved at A->B"
    );
    assert_eq!(a.pid(), pair.a_pid(), "same PID across exec");
    a.advance(&label("s04-b")).unwrap();
    a.advance(&label("s05-exec-a"))
        .expect("real exec back to image A");
    assert_eq!(exe_sha256(pair.a_pid()), sha_a, "executable image restored");
    assert_eq!(
        proc_starttime(pair.a_pid()),
        start,
        "birth preserved at B->A"
    );
    a.advance(&label("s06-a2")).unwrap();
    a.advance(&label("s07-close")).unwrap();
    pair.shutdown();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn thread_lifecycle_sibling_phases() {
    let (pair, dir) = live_pair_with_images(Scenario::ThreadLifecycle, 24, true);
    let a = pair.a_process();
    assert_eq!(a.nonleader_tid(), None, "no sibling before start");
    a.advance(&label("s01-ready")).unwrap();
    a.advance(&label("s02-start-sibling"))
        .expect("real sibling thread spawn");
    let sibling = a.nonleader_tid().expect("sibling TID while barrier held");
    assert_ne!(sibling, pair.a_pid());
    assert_eq!(task_tids(pair.a_pid()), {
        let mut v = vec![pair.a_pid(), sibling];
        v.sort_unstable();
        v
    });
    a.advance(&label("s03-sibling")).unwrap();
    a.advance(&label("s04-exit-leader"))
        .expect("leader-only native exit");
    assert_eq!(
        task_state(pair.a_pid(), pair.a_pid()),
        b'Z',
        "leader is a zombie"
    );
    assert_ne!(
        task_state(pair.a_pid(), sibling),
        b'Z',
        "sibling stays live"
    );
    assert_eq!(a.nonleader_tid(), Some(sibling));
    a.advance(&label("s05-leader-exited")).unwrap();
    a.advance(&label("s06-missing"))
        .expect("failed exec from sibling");
    assert_eq!(task_state(pair.a_pid(), pair.a_pid()), b'Z');
    assert_ne!(task_state(pair.a_pid(), sibling), b'Z');
    a.advance(&label("s07-still-sibling")).unwrap();
    let sha_before = exe_sha256_as(pair.a_pid(), a.nonleader_tid());
    a.advance(&label("s08-exec-sibling"))
        .expect("real nonleader exec");
    assert_ne!(exe_sha256(pair.a_pid()), sha_before, "new image after exec");
    assert_eq!(
        task_tids(pair.a_pid()),
        vec![pair.a_pid()],
        "single thread again"
    );
    assert_eq!(a.nonleader_tid(), None, "barrier invalidated by exec");
    a.advance(&label("s09-new-image")).unwrap();
    a.advance(&label("s10-close")).unwrap();
    pair.shutdown();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn descriptor_inventory_canary() {
    let (pair, dir) = live_pair(Scenario::DescriptorInventory, 25);
    let a = pair.a_process();
    pair.upload_blobs(
        b"alpha-content-001",
        b"beta--content-002",
        b"ALPHA-CONTENT-001",
    )
    .unwrap();
    a.advance(&label("s01-ready")).unwrap();
    a.advance(&label("s02-create-files")).unwrap();
    a.advance(&label("s03-offer-files")).unwrap();
    a.advance(&label("s04-inventory"))
        .expect("real third-slot inventory children with canary");
    let raw = pair.drained_raw();
    let positive = raw
        .iter()
        .find(|r| r.kind == "fd" && r.step_id == "s04-inventory" && r.actor == "parent-positive")
        .expect("positive inventory record");
    let body: serde_json::Value = serde_json::from_slice(&positive.bytes).unwrap();
    assert_eq!(
        body["values"]["canary_hex"],
        "53424649585455524543414e41525931"
    );
    let negative = raw
        .iter()
        .find(|r| r.kind == "fd" && r.step_id == "s04-inventory" && r.actor == "parent-negative")
        .expect("negative inventory record");
    let negative_body: serde_json::Value = serde_json::from_slice(&negative.bytes).unwrap();
    assert_eq!(
        negative_body["values"]["canary_hex"],
        serde_json::Value::Null
    );
    a.advance(&label("s05-responding-ab")).unwrap();
    pair.b_heartbeat(&label("s05-responding-ab")).unwrap();
    a.advance(&label("s06-close")).unwrap();
    pair.shutdown();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn deadline_hold_parametric() {
    let (pair, dir) = live_pair(Scenario::ExecAba, 26);
    let a = pair.a_process();
    a.advance(&label("s01-ready")).unwrap();
    let report = pair.deadline_hold("s01-ready", 200, 2000).unwrap();
    assert!(
        report.elapsed_ns >= 200_000_000,
        "hold waits the full execution duration"
    );
    assert_eq!(report.completed_prefix, "s01-ready");
    assert_eq!(report.extra_worker_datagrams, 0);
    assert_eq!(pair.a_exited_unreaped().unwrap(), None);
    a.advance(&label("s02-a")).unwrap();
    a.advance(&label("s03-exec-b"))
        .expect("real exec to image B");
    a.advance(&label("s04-b")).unwrap();
    a.advance(&label("s05-exec-a"))
        .expect("real exec back to image A");
    a.advance(&label("s06-a2")).unwrap();
    a.advance(&label("s07-close")).unwrap();
    pair.shutdown();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
#[ignore]
fn reached_deadline_30s_schedule() {
    let (pair, dir) = live_pair_with_images(Scenario::ExecAba, 27, true);
    let a = pair.a_process();
    a.advance(&label("s01-ready")).unwrap();
    a.advance(&label("s02-a")).unwrap();
    a.advance(&label("s03-exec-b"))
        .expect("real exec to image B");
    a.advance(&label("s04-b")).unwrap();
    a.advance(&label("s05-exec-a"))
        .expect("real exec back to image A");
    a.advance(&label("s06-a2")).unwrap();
    let report = pair.deadline_hold("s06-a2", 30_000, 31_000).unwrap();
    assert!(
        report.elapsed_ns >= 30_000_000_000,
        "reached schedule waits the full 30s after the s06-a2 ACK"
    );
    assert_eq!(report.completed_prefix, "s06-a2");
    assert_eq!(report.extra_worker_datagrams, 0);
    a.advance(&label("s07-close")).unwrap();
    pair.shutdown();
    std::fs::remove_dir_all(&dir).unwrap();
}

fn assert_worker_death(
    err: &scopebase_testkit::fixture::linux::LinuxPhaseError,
    step_id: &str,
    elapsed: Duration,
) {
    assert_eq!(
        err.category(),
        FixtureErrorCategory::InvalidProtocol,
        "worker death is a typed protocol failure"
    );
    assert_eq!(err.step_id(), &label(step_id));
    let diagnostic = String::from_utf8_lossy(err.diagnostic_bytes());
    assert!(
        diagnostic.contains("died mid-protocol"),
        "death is reported, never silent: {diagnostic}"
    );
    assert!(
        diagnostic.contains("code 3"),
        "control death carries the distinct wait status: {diagnostic}"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "death is detected at once, never via the 10s reply timeout: {elapsed:?}"
    );
}

#[test]
fn worker_exit_after_root_grant_is_typed_death() {
    let (pair, dir) = live_pair_with_control(
        Scenario::LeaderLifecycle,
        31,
        outage_control("worker_exit", "s01-ready", "after_root_grant"),
    );
    let a = pair.a_process();
    let start = Instant::now();
    let err = a
        .advance(&label("s01-ready"))
        .expect_err("root-granted worker exit must fail the step");
    assert_worker_death(&err, "s01-ready", start.elapsed());
    // B never received the control and stays fully serviceable.
    pair.b_heartbeat(&label("s01-ready"))
        .expect("excluded worker is unaffected by A's death");
    // Orphaned retirement: A reaped with its control status, B closed clean,
    // case directory removed.
    let report = pair.shutdown();
    assert_eq!(report.a_exit.map(|e| e.code), Some(Some(3)));
    assert_eq!(report.b_exit.map(|e| e.code), Some(Some(0)));
    assert!(report.case_root_removed);
    let case = case_path(&dir, 31);
    assert!(!case.exists(), "retired case directory is gone");
    std::fs::remove_dir_all(&dir).unwrap();
    // Valid twin: the same script without the control proceeds past s01.
    let (twin, twin_dir) = live_pair(Scenario::LeaderLifecycle, 32);
    let t = twin.a_process();
    t.advance(&label("s01-ready")).unwrap();
    t.advance(&label("s02-live")).unwrap();
    let shutdown = twin.shutdown();
    assert!(shutdown.case_root_removed);
    std::fs::remove_dir_all(&twin_dir).unwrap();
}

#[test]
fn worker_exit_after_file_register_keeps_file_a_first() {
    let (pair, dir) = live_pair_with_control(
        Scenario::FileReplacement,
        33,
        outage_control("worker_exit", "s02-create-files", "after_file_register"),
    );
    let a = pair.a_process();
    let blob_a = b"alpha-content-001".to_vec();
    let blob_b = b"beta--content-002".to_vec();
    let mutation = b"ALPHA-CONTENT-001".to_vec();
    pair.upload_blobs(&blob_a, &blob_b, &mutation).unwrap();
    a.advance(&label("s01-ready")).unwrap();
    let start = Instant::now();
    let err = a
        .advance(&label("s02-create-files"))
        .expect_err("FileA-created exit must fail the step");
    assert_worker_death(&err, "s02-create-files", start.elapsed());
    // FileA was registered first, before FileB and before the death: its
    // complete bytes survive on the retained case root; FileB never exists.
    let case = case_path(&dir, 33);
    assert_eq!(std::fs::read(case.join("a")).unwrap(), blob_a);
    assert!(
        !case.join("b").exists(),
        "FileB is never created before the death"
    );
    // The parent sampled the file prefix at death into retained evidence.
    let raw = pair.drained_raw();
    let sample = raw
        .iter()
        .find(|r| r.kind == "mutation" && r.step_id == "s02-create-files")
        .expect("parent death-sample record");
    let body: serde_json::Value = serde_json::from_slice(&sample.bytes).unwrap();
    assert_eq!(body["values"]["readback_hex"], hex_of(&blob_a));
    assert_eq!(body["values"]["byte_count"], blob_a.len().to_string());
    // Drained prefix before the death is retained, not dropped.
    assert!(raw.iter().any(|r| r.step_id == "s01-ready"));
    let report = pair.shutdown();
    assert_eq!(report.a_exit.map(|e| e.code), Some(Some(3)));
    assert!(report.case_root_removed);
    assert!(!case.exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn partial_file_write_detected_typed() {
    let (pair, dir) = live_pair_with_control(
        Scenario::FileReplacement,
        34,
        outage_control("partial_file_write", "s08-mutate", "before_ack"),
    );
    let a = pair.a_process();
    let blob_a = b"alpha-content-001".to_vec();
    let blob_b = b"beta--content-002".to_vec();
    // Premise: equal length, bytes 0 and 1 each differ.
    let mutation = b"ZZpha-content-001".to_vec();
    assert_eq!(mutation.len(), blob_a.len());
    assert_ne!(mutation[0], blob_a[0]);
    assert_ne!(mutation[1], blob_a[1]);
    pair.upload_blobs(&blob_a, &blob_b, &mutation).unwrap();
    for step in [
        "s01-ready",
        "s02-create-files",
        "s03-offer-files",
        "s04-original",
        "s05-replace",
        "s06-replaced",
        "s07-unlink",
    ] {
        a.advance(&label(step)).unwrap();
    }
    let start = Instant::now();
    let err = a
        .advance(&label("s08-mutate"))
        .expect_err("one-byte partial write must fail the step");
    assert_worker_death(&err, "s08-mutate", start.elapsed());
    // Partial-file detection through the parent's retained original FileA:
    // exactly the first byte changed, the tail is untouched. Positional
    // read: the shared description's offset sits at EOF after the worker's
    // positional create write.
    use std::os::unix::fs::FileExt;
    let pulled = pair.pulled_file_a().unwrap();
    let mut readback = vec![0u8; blob_a.len()];
    pulled.read_exact_at(&mut readback, 0).unwrap();
    let mut expect = blob_a.clone();
    expect[0] = mutation[0];
    assert_eq!(readback, expect, "exactly one byte was written");
    assert_ne!(readback, mutation, "a full mutation must not be claimed");
    let raw = pair.drained_raw();
    let sample = raw
        .iter()
        .find(|r| r.kind == "mutation" && r.step_id == "s08-mutate")
        .expect("parent partial-write record");
    let body: serde_json::Value = serde_json::from_slice(&sample.bytes).unwrap();
    assert_eq!(body["values"]["readback_hex"], hex_of(&readback));
    assert_eq!(body["values"]["offset"], "0");
    let report = pair.shutdown();
    assert_eq!(report.a_exit.map(|e| e.code), Some(Some(3)));
    assert_eq!(report.b_exit.map(|e| e.code), Some(Some(0)));
    assert!(report.case_root_removed);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn partial_file_write_premise_violation_refused() {
    let (pair, dir) = live_pair_with_control(
        Scenario::FileReplacement,
        35,
        outage_control("partial_file_write", "s08-mutate", "before_ack"),
    );
    let a = pair.a_process();
    let blob_a = b"alpha-content-001".to_vec();
    let blob_b = b"beta--content-002".to_vec();
    // Byte 0 matches: the one-byte premise cannot hold, so the worker must
    // refuse with a typed Error instead of dying.
    let mutation = b"aLPHA-CONTENT-001".to_vec();
    pair.upload_blobs(&blob_a, &blob_b, &mutation).unwrap();
    for step in [
        "s01-ready",
        "s02-create-files",
        "s03-offer-files",
        "s04-original",
        "s05-replace",
        "s06-replaced",
        "s07-unlink",
    ] {
        a.advance(&label(step)).unwrap();
    }
    let err = a
        .advance(&label("s08-mutate"))
        .expect_err("premise violation must refuse the step");
    assert_eq!(err.category(), FixtureErrorCategory::InvalidProtocol);
    let diagnostic = String::from_utf8_lossy(err.diagnostic_bytes());
    // The frozen Error shape carries detail hex-encoded in diagnostic_hex;
    // 7072656d697365 is "premise".
    assert!(
        diagnostic.contains("7072656d697365"),
        "refusal names the premise: {diagnostic}"
    );
    assert!(
        !diagnostic.contains("died mid-protocol"),
        "a refusal is not a death: {diagnostic}"
    );
    // The worker is alive and responsive: the same step refuses again.
    let retry = a.advance(&label("s08-mutate")).unwrap_err();
    assert!(
        String::from_utf8_lossy(retry.diagnostic_bytes()).contains("7072656d697365"),
        "live worker refuses the retried step"
    );
    let report = pair.shutdown();
    assert_eq!(report.a_exit.map(|e| e.code), Some(Some(0)));
    assert!(report.case_root_removed);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn parent_failure_after_case_root_register() {
    let (dir, root) = temp_root("parent-fail-root");
    let (cfg, _) = launch_config_with_control(
        &dir,
        root,
        Scenario::LeaderLifecycle,
        36,
        Some(outage_control(
            "parent_failure_after_register",
            "s01-ready",
            "after_case_root_register",
        )),
    );
    let err = launch_pair(&cfg).unwrap_err();
    assert!(matches!(err.kind(), DriverErrorKind::SetupFailure));
    assert_eq!(err.step_id(), Some("s01-ready"));
    let diagnostic = String::from_utf8_lossy(err.diagnostic_bytes());
    assert!(
        diagnostic.contains("after_case_root_register"),
        "{diagnostic}"
    );
    assert!(diagnostic.contains("case-root"), "{diagnostic}");
    assert!(!err.cleanup_proof().spawned, "no child ever spawns");
    assert!(!case_path(&dir, 36).exists(), "case dir is retired");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn parent_failure_after_child_register() {
    let (dir, root) = temp_root("parent-fail-child");
    let (cfg, _) = launch_config_with_control(
        &dir,
        root,
        Scenario::LeaderLifecycle,
        37,
        Some(outage_control(
            "parent_failure_after_register",
            "s01-ready",
            "after_child_register",
        )),
    );
    let err = launch_pair(&cfg).unwrap_err();
    assert!(matches!(err.kind(), DriverErrorKind::SetupFailure));
    assert_eq!(err.step_id(), Some("s01-ready"));
    let diagnostic = String::from_utf8_lossy(err.diagnostic_bytes());
    assert!(diagnostic.contains("after_child_register"), "{diagnostic}");
    assert!(diagnostic.contains("child-A"), "{diagnostic}");
    assert!(diagnostic.contains("B never spawned"), "{diagnostic}");
    let proof = err.cleanup_proof();
    assert!(proof.spawned && proof.a_reaped && !proof.b_reaped);
    assert!(!case_path(&dir, 37).exists(), "case dir is retired");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn parent_failure_after_pidfd_register() {
    let (dir, root) = temp_root("parent-fail-pidfd");
    let (cfg, _) = launch_config_with_control(
        &dir,
        root,
        Scenario::LeaderLifecycle,
        38,
        Some(outage_control(
            "parent_failure_after_register",
            "s01-ready",
            "after_pidfd_register",
        )),
    );
    let err = launch_pair(&cfg).unwrap_err();
    assert!(matches!(err.kind(), DriverErrorKind::SetupFailure));
    assert_eq!(err.step_id(), Some("s01-ready"));
    let diagnostic = String::from_utf8_lossy(err.diagnostic_bytes());
    assert!(diagnostic.contains("after_pidfd_register"), "{diagnostic}");
    assert!(diagnostic.contains("pidfd-A"), "{diagnostic}");
    let proof = err.cleanup_proof();
    assert!(proof.spawned && proof.a_reaped && !proof.b_reaped);
    assert!(!case_path(&dir, 38).exists(), "case dir is retired");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn outage_control_pairing_refused_before_effects() {
    // Inapplicable pairing: partial writes exist only in file-replacement.
    let (dir, root) = temp_root("outage-refused");
    let (cfg, _) = launch_config_with_control(
        &dir,
        root,
        Scenario::LeaderLifecycle,
        39,
        Some(outage_control(
            "partial_file_write",
            "s01-ready",
            "before_ack",
        )),
    );
    let err = launch_pair(&cfg).unwrap_err();
    assert!(matches!(err.kind(), DriverErrorKind::Refused));
    assert!(!err.cleanup_proof().spawned);
    assert!(!case_path(&dir, 39).exists(), "refused before effects");
    // Admitted pairing with no population on this route stays loud, too.
    let (dir2, root2) = temp_root("outage-unrouted");
    let (cfg2, _) = launch_config_with_control(
        &dir2,
        root2,
        Scenario::LeaderLifecycle,
        40,
        Some(outage_control("wrong_run", "s01-ready", "before_ack")),
    );
    let err2 = launch_pair(&cfg2).unwrap_err();
    assert!(matches!(err2.kind(), DriverErrorKind::Refused));
    assert!(
        String::from_utf8_lossy(err2.diagnostic_bytes()).contains("no driver population"),
        "unrouted kinds refuse loudly"
    );
    assert!(!err2.cleanup_proof().spawned);
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&dir2).unwrap();
}

#[test]
fn prepare_reports_worker_death_typed() {
    let (dir, _root) = temp_root("prepare-death");
    let (mut session, _, invocation) = native_session_control(
        &dir,
        "leader-lifecycle",
        Some(("worker_exit", "s01-ready", "after_root_grant")),
    );
    let err = match session.prepare(&invocation) {
        Ok(_) => panic!("prepare must report the worker death"),
        Err(e) => e,
    };
    assert_eq!(*err.category(), FixtureErrorCategory::InvalidProtocol);
    let diagnostic = String::from_utf8_lossy(err.diagnostic_bytes());
    assert!(diagnostic.contains("died mid-protocol"), "{diagnostic}");
    assert!(diagnostic.contains("code 3"), "{diagnostic}");
    // The orphaned pair was retired inside prepare; finalize stays clean.
    let report = session
        .finalize(LinuxOuterCleanupBudget {
            deadline: Instant::now() + Duration::from_secs(4),
            max_native_attempts: 512,
            max_records: 64,
            max_retained_bytes: 262144,
        })
        .unwrap()
        .as_bytes()
        .to_vec();
    let v: serde_json::Value = serde_json::from_slice(&report).unwrap();
    assert_eq!(v["kind"], "clean");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn prepare_reports_parent_failure_typed() {
    let (dir, _root) = temp_root("prepare-parent-fail");
    let (mut session, _, invocation) = native_session_control(
        &dir,
        "leader-lifecycle",
        Some((
            "parent_failure_after_register",
            "s01-ready",
            "after_child_register",
        )),
    );
    let err = match session.prepare(&invocation) {
        Ok(_) => panic!("prepare must report the parent setup failure"),
        Err(e) => e,
    };
    assert_eq!(*err.category(), FixtureErrorCategory::Other);
    let diagnostic = String::from_utf8_lossy(err.diagnostic_bytes());
    assert!(diagnostic.contains("after_child_register"), "{diagnostic}");
    let report = session
        .finalize(LinuxOuterCleanupBudget {
            deadline: Instant::now() + Duration::from_secs(4),
            max_native_attempts: 512,
            max_records: 64,
            max_retained_bytes: 262144,
        })
        .unwrap()
        .as_bytes()
        .to_vec();
    let v: serde_json::Value = serde_json::from_slice(&report).unwrap();
    assert_eq!(v["kind"], "clean");
    std::fs::remove_dir_all(&dir).unwrap();
}

fn tt03_runner_contract() -> (
    scopebase_testkit::ProfilePlan,
    scopebase_testkit::RunContract,
) {
    let catalog = scopebase_testkit::CaseCatalog::load(
        &std::fs::read(support::root().join("catalog.json")).unwrap(),
        scopebase_testkit::CatalogLimits::default(),
    )
    .unwrap();
    let plan = scopebase_testkit::ProfilePlan::select(
        &catalog,
        &scopebase_testkit::ProfileId::parse("tt02-harness-v1").unwrap(),
    )
    .unwrap();
    let bytes = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tt03/contract.json"),
    )
    .unwrap();
    let contract =
        scopebase_testkit::RunContract::load(&catalog, &plan, &bytes, RunLimits::default())
            .unwrap();
    assert_eq!(contract.schedule().len(), 1, "one scheduled invocation");
    (plan, contract)
}

fn manifest_bytes_full(
    run_hex: &str,
    scenario: &str,
    operation_id: u64,
    control: Option<(&str, &str, &str)>,
    blobs: Option<(&str, &str, &str)>,
) -> Vec<u8> {
    let steps: Vec<serde_json::Value> = Scenario::parse(scenario)
        .unwrap()
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
    let (hex_a, hex_b, hex_m) = match blobs {
        Some((a, b, m)) => (
            serde_json::Value::String(a.to_string()),
            serde_json::Value::String(b.to_string()),
            serde_json::Value::String(m.to_string()),
        ),
        None => (
            serde_json::Value::Null,
            serde_json::Value::Null,
            serde_json::Value::Null,
        ),
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
            "scenario": scenario,
            "steps": steps,
            "control": control_value,
            "expected_file_a_hex": hex_a,
            "expected_file_b_hex": hex_b,
            "mutation_hex": hex_m,
            "driver_schedule": null,
        }],
    })
    .to_string()
    .into_bytes()
}

fn tt03_session(
    dir: &std::path::Path,
    contract: &scopebase_testkit::RunContract,
    scenario: &str,
    control: Option<(&str, &str, &str)>,
    blobs: Option<(&str, &str, &str)>,
) -> (LinuxFixtureSession, scopebase_testkit::CaseInvocation) {
    let invocation = invocation_for(contract);
    let op = *invocation.key().operation_id();
    let root = File::open(dir).unwrap();
    let files = make_files(dir, root);
    let manifest = manifest_bytes_full(contract.run_id().as_str(), scenario, op, control, blobs);
    let cancel = Arc::new(AtomicBool::new(false));
    let session = LinuxFixtureSession::new(
        contract.clone(),
        files,
        &manifest,
        Instant::now() + Duration::from_secs(60),
        cancel,
    )
    .unwrap();
    (session, invocation)
}

fn case_path_run(dir: &std::path::Path, run_hex: &str, op: u64) -> PathBuf {
    dir.join(format!("tt03-{run_hex}-{op}"))
}

/// Runner vehicle for retire: optionally advances the prepared Linux
/// process through scripted steps (reaching retire-relevant advance
/// effects such as descriptor inventory), optionally injects foreign
/// filesystem interference, then cancels so Collect/Judge (other
/// owners' contracts) are skipped. Retirement still runs through the
/// real engine and ledger.
struct Tt03RetireAdapter {
    subject: scopebase_testkit::SubjectBinding,
    advance_steps: Vec<String>,
    interfere_remove: Option<PathBuf>,
    calls: usize,
}

impl ConformanceAdapter for Tt03RetireAdapter {
    fn subject(&self) -> scopebase_testkit::SubjectBinding {
        self.subject.clone()
    }
    fn execute(
        &mut self,
        invocation: &scopebase_testkit::CaseInvocation,
        fixture: &FixtureAccess<'_>,
    ) -> Result<Observation, scopebase_testkit::CaseError> {
        self.calls += 1;
        if !self.advance_steps.is_empty() {
            let proc = fixture
                .resource::<LinuxProcessFixture>(&Label::parse("linux.process").unwrap())
                .expect("linux.process resource for scripted advance");
            for step in &self.advance_steps {
                proc.advance(&Label::parse(step).unwrap())
                    .expect("scripted advance reaches its trigger");
            }
        }
        if let Some(path) = &self.interfere_remove {
            assert!(path.exists(), "interference reaches a live case dir");
            std::fs::remove_dir_all(path).expect("foreign actor removes the case dir");
        }
        Err(support::adapter::operation_error(
            invocation,
            CaseErrorCategory::Cancelled,
            None,
            vec![],
            None,
            b"tt03 retire vehicle: adapter cancels after fixture advance",
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
            &RunLimits::default(),
        )
        .unwrap()
    }
}

fn tt03_oracle(contract: &scopebase_testkit::RunContract) -> support::oracle::ArithmeticOracle {
    support::oracle::ArithmeticOracle {
        binding: contract.expected_oracle().clone(),
    }
}

fn fixture_records(report: &scopebase_testkit::RunReport) -> Vec<usize> {
    report
        .cleanup_records()
        .iter()
        .enumerate()
        .filter(|(_, r)| *r.owner() == Owner::Fixture)
        .map(|(i, _)| i)
        .collect()
}

#[test]
fn dag_grammar_152_rows_not_run() {
    let dag = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/superpowers/specs/tt03-linux/materializer-command-dag.json");
    let bytes = std::fs::read(&dag).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["grammar_row_count"], 152);
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 152);
    assert_eq!(v["packet_ready"], false);
    for row in rows {
        let status = row["status"].as_str().unwrap_or("");
        assert!(
            status.contains("NOT_RUN") || status.contains("NOT-RUN") || status.is_empty(),
            "offline lane executes no delivery command row: {}",
            row["id"].as_str().unwrap_or("?")
        );
    }
}

fn transition_resource_ids(report: &RetirementReport) -> Vec<String> {
    report
        .transitions()
        .iter()
        .map(|t| t.effect().resource_id().as_str().to_string())
        .collect()
}

#[test]
fn retire_case_scope_transitions_prepared_pair() {
    let (dir, _root) = temp_root("retire-case");
    let (plan, contract) = tt03_runner_contract();
    let (mut session, _) = tt03_session(&dir, &contract, "leader-lifecycle", None, None);
    let mut adapter = Tt03RetireAdapter {
        subject: contract.expected_subject().clone(),
        advance_steps: vec![],
        interfere_remove: None,
        calls: 0,
    };
    let oracle = tt03_oracle(&contract);
    let report = scopebase_testkit::run_profile(&plan, &mut adapter, &mut session, &oracle)
        .expect("retire vehicle run completes");
    assert_eq!(adapter.calls, 1);
    assert_eq!(report.cleanup_records().len(), 4);
    let fixture = fixture_records(&report);
    assert_eq!(fixture.len(), 2);
    let case_record = &report.cleanup_records()[fixture[0]];
    assert_eq!(*case_record.call_id(), 2);
    assert!(matches!(case_record.scope(), CleanupScope::Case(_)));
    assert_eq!(*case_record.status(), CleanupCallStatus::Called);
    assert!(case_record.error().is_none());
    let case_response = case_record
        .response()
        .as_ref()
        .expect("case retire response");
    assert_eq!(
        transition_resource_ids(case_response),
        vec![
            "linux.case-root".to_string(),
            "linux.child-a".to_string(),
            "linux.child-b".to_string(),
        ]
    );
    assert!(case_response.discovered().is_empty());
    assert!(case_response.pending_snapshot().is_empty());
    assert!(*case_response.complete());
    assert_eq!(
        *case_record.state_at_case_end().as_ref().unwrap(),
        CleanupState::Complete
    );
    let run_record = &report.cleanup_records()[fixture[1]];
    assert_eq!(*run_record.call_id(), 4);
    assert!(matches!(run_record.scope(), CleanupScope::Run(_)));
    let run_response = run_record.response().as_ref().expect("run retire response");
    assert!(
        run_response.transitions().is_empty(),
        "run retire has nothing left"
    );
    assert!(*run_response.complete());
    assert_eq!(*run_record.state_at_run_end(), CleanupState::Complete);
    // Exactly-once across prepare (recorded), collect (omitted: empty) and retire.
    let batches = report.case_results()[0].effect_batches();
    assert_eq!(batches.len(), 2, "prepare + adapter-execute batches");
    let empty = EffectBatch::empty(contract.limits());
    let discovered: Vec<EffectRegistration> = case_response
        .discovered()
        .iter()
        .chain(run_response.discovered().iter())
        .cloned()
        .collect();
    let transitions = case_response
        .transitions()
        .iter()
        .chain(run_response.transitions().iter())
        .cloned()
        .collect::<Vec<_>>();
    verify_retirement_exactly_once(&batches[0], &empty, &discovered, &transitions).unwrap();
    // The clean-shutdown gate passes on the retired custody.
    let claim = CustodyClaim {
        retired_report: true,
        exit_status_only: false,
        original_root: true,
        original_owners: true,
        registered: batches[0]
            .registrations()
            .iter()
            .map(|r| r.resource_id().clone())
            .collect(),
        transitioned: transition_resource_ids(case_response)
            .iter()
            .map(|s| Label::parse(s).unwrap())
            .collect(),
        unknown: vec![],
        cleanup_errors: vec![],
    };
    clean_shutdown_gate(&claim).unwrap();
    // Retired pairs are gone before the finalizer; it stays clean.
    session
        .finalize(LinuxOuterCleanupBudget {
            deadline: Instant::now() + Duration::from_secs(4),
            max_native_attempts: 512,
            max_records: 64,
            max_retained_bytes: 262144,
        })
        .unwrap();
    let v: serde_json::Value =
        serde_json::from_slice(session.outer_cleanup_report().unwrap().as_bytes()).unwrap();
    assert_eq!(v["kind"], "clean");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn retire_discovers_inventory_children_exactly_once() {
    let (dir, _root) = temp_root("retire-inventory");
    let (plan, contract) = tt03_runner_contract();
    let blob_a = hex_of(b"alpha-content-001");
    let blob_b = hex_of(b"beta--content-002");
    let mutation = hex_of(b"ALPHA-CONTENT-001");
    let (mut session, _) = tt03_session(
        &dir,
        &contract,
        "descriptor-inventory",
        None,
        Some((&blob_a, &blob_b, &mutation)),
    );
    let mut adapter = Tt03RetireAdapter {
        subject: contract.expected_subject().clone(),
        advance_steps: vec!["s04-inventory".to_string(), "s05-responding-ab".to_string()],
        interfere_remove: None,
        calls: 0,
    };
    let oracle = tt03_oracle(&contract);
    let report = scopebase_testkit::run_profile(&plan, &mut adapter, &mut session, &oracle)
        .expect("inventory retire run completes");
    let fixture = fixture_records(&report);
    let case_record = &report.cleanup_records()[fixture[0]];
    let case_response = case_record
        .response()
        .as_ref()
        .expect("case retire response");
    let discovered: Vec<String> = case_response
        .discovered()
        .iter()
        .map(|r| r.resource_id().as_str().to_string())
        .collect();
    assert_eq!(
        discovered,
        vec![
            "linux.inventory-negative".to_string(),
            "linux.inventory-positive".to_string(),
        ],
        "advance-made inventory children are discovered by retire"
    );
    let mut transitioned = transition_resource_ids(case_response);
    transitioned.sort();
    assert_eq!(
        transitioned,
        vec![
            "linux.case-root".to_string(),
            "linux.child-a".to_string(),
            "linux.child-b".to_string(),
            "linux.file-a".to_string(),
            "linux.file-b".to_string(),
            "linux.inventory-negative".to_string(),
            "linux.inventory-positive".to_string(),
        ]
    );
    assert!(*case_response.complete());
    assert_eq!(
        *case_record.state_at_case_end().as_ref().unwrap(),
        CleanupState::Complete
    );
    let batches = report.case_results()[0].effect_batches();
    assert_eq!(
        batches[0].registrations().len(),
        5,
        "prepare registers five"
    );
    let empty = EffectBatch::empty(contract.limits());
    verify_retirement_exactly_once(
        &batches[0],
        &empty,
        case_response.discovered(),
        case_response.transitions(),
    )
    .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn retire_after_worker_death_settles_known_prefix() {
    let (dir, _root) = temp_root("retire-death");
    let (plan, contract) = tt03_runner_contract();
    let (mut session, _) = tt03_session(
        &dir,
        &contract,
        "leader-lifecycle",
        Some(("worker_exit", "s01-ready", "after_root_grant")),
        None,
    );
    let mut adapter = Tt03RetireAdapter {
        subject: contract.expected_subject().clone(),
        advance_steps: vec![],
        interfere_remove: None,
        calls: 0,
    };
    let oracle = tt03_oracle(&contract);
    let report = scopebase_testkit::run_profile(&plan, &mut adapter, &mut session, &oracle)
        .expect("death retire run completes");
    assert_eq!(adapter.calls, 0, "prepare failure skips execute");
    assert!(report.case_results()[0].fixture_failure().is_some());
    let fixture = fixture_records(&report);
    assert_eq!(fixture.len(), 2);
    let case_record = &report.cleanup_records()[fixture[0]];
    assert_eq!(*case_record.status(), CleanupCallStatus::Called);
    let case_response = case_record
        .response()
        .as_ref()
        .expect("case retire response");
    assert_eq!(
        transition_resource_ids(case_response),
        vec![
            "linux.case-root".to_string(),
            "linux.child-a".to_string(),
            "linux.child-b".to_string(),
        ]
    );
    assert_eq!(
        case_response.discovered().len(),
        3,
        "failed prefix is discovered"
    );
    assert!(*case_response.complete());
    assert_eq!(
        *case_record.state_at_case_end().as_ref().unwrap(),
        CleanupState::Complete
    );
    let batches = report.case_results()[0].effect_batches();
    assert_eq!(batches.len(), 1, "only the failed-prepare batch");
    assert!(batches[0].registrations().is_empty());
    let empty = EffectBatch::empty(contract.limits());
    let run_response = report.cleanup_records()[fixture[1]]
        .response()
        .as_ref()
        .expect("run retire response");
    let transitions = case_response
        .transitions()
        .iter()
        .chain(run_response.transitions().iter())
        .cloned()
        .collect::<Vec<_>>();
    verify_retirement_exactly_once(
        &batches[0],
        &empty,
        case_response.discovered(),
        &transitions,
    )
    .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn retire_after_file_death_keeps_file_a_unknown_sticky() {
    let (dir, _root) = temp_root("retire-file-unknown");
    let (plan, contract) = tt03_runner_contract();
    let blob_a = hex_of(b"alpha-content-001");
    let blob_b = hex_of(b"beta--content-002");
    let mutation = hex_of(b"ALPHA-CONTENT-001");
    let (mut session, _) = tt03_session(
        &dir,
        &contract,
        "file-replacement",
        Some(("worker_exit", "s02-create-files", "after_file_register")),
        Some((&blob_a, &blob_b, &mutation)),
    );
    let mut adapter = Tt03RetireAdapter {
        subject: contract.expected_subject().clone(),
        advance_steps: vec![],
        interfere_remove: None,
        calls: 0,
    };
    let oracle = tt03_oracle(&contract);
    let report = scopebase_testkit::run_profile(&plan, &mut adapter, &mut session, &oracle)
        .expect("file-death retire run completes");
    let fixture = fixture_records(&report);
    let case_record = &report.cleanup_records()[fixture[0]];
    let case_response = case_record
        .response()
        .as_ref()
        .expect("case retire response");
    assert_eq!(
        transition_resource_ids(case_response),
        vec![
            "linux.case-root".to_string(),
            "linux.child-a".to_string(),
            "linux.child-b".to_string(),
        ]
    );
    assert!(
        !*case_response.complete(),
        "sampled-but-unrecoverable file-a blocks clean"
    );
    let diagnostic = case_response
        .diagnostic()
        .as_ref()
        .expect("retire diagnostic");
    assert!(
        diagnostic.contains("linux.file-a"),
        "unknown names file-a: {diagnostic}"
    );
    assert_eq!(
        *case_record.state_at_case_end().as_ref().unwrap(),
        CleanupState::Unresolved
    );
    assert!(
        !case_record.uncertainty_ids().is_empty(),
        "incomplete retire records uncertainty"
    );
    // Stickiness: the run-scope call repeats the unknown, never clears it.
    let run_response = report.cleanup_records()[fixture[1]]
        .response()
        .as_ref()
        .expect("run retire response");
    assert!(!*run_response.complete());
    let run_diagnostic = run_response.diagnostic().as_ref().expect("run diagnostic");
    assert!(
        run_diagnostic.contains("linux.file-a"),
        "unknown survives: {run_diagnostic}"
    );
    assert!(
        run_response.transitions().is_empty(),
        "no double transition on retry"
    );
    verify_unknown_sticky(
        &[Label::parse("linux.file-a").unwrap()],
        &[Label::parse("linux.file-a").unwrap()],
    )
    .unwrap();
    // The gate fails on the sticky unknown, not on setup or transitions.
    let claim = CustodyClaim {
        retired_report: true,
        exit_status_only: false,
        original_root: true,
        original_owners: true,
        registered: transition_resource_ids(case_response)
            .iter()
            .map(|s| Label::parse(s).unwrap())
            .collect(),
        transitioned: transition_resource_ids(case_response)
            .iter()
            .map(|s| Label::parse(s).unwrap())
            .collect(),
        unknown: vec![Label::parse("linux.file-a").unwrap()],
        cleanup_errors: vec![],
    };
    let err = clean_shutdown_gate(&claim).unwrap_err();
    assert!(
        err.detail().contains("unknown inventory"),
        "{}",
        err.detail()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn retire_after_parent_failure_discovers_prefix() {
    let (dir, _root) = temp_root("retire-parent-fail");
    let (plan, contract) = tt03_runner_contract();
    let (mut session, _) = tt03_session(
        &dir,
        &contract,
        "leader-lifecycle",
        Some((
            "parent_failure_after_register",
            "s01-ready",
            "after_child_register",
        )),
        None,
    );
    let mut adapter = Tt03RetireAdapter {
        subject: contract.expected_subject().clone(),
        advance_steps: vec![],
        interfere_remove: None,
        calls: 0,
    };
    let oracle = tt03_oracle(&contract);
    let report = scopebase_testkit::run_profile(&plan, &mut adapter, &mut session, &oracle)
        .expect("parent-failure retire run completes");
    let fixture = fixture_records(&report);
    let case_record = &report.cleanup_records()[fixture[0]];
    let case_response = case_record
        .response()
        .as_ref()
        .expect("case retire response");
    assert_eq!(
        transition_resource_ids(case_response),
        vec!["linux.case-root".to_string(), "linux.child-a".to_string(),]
    );
    assert!(
        !transition_resource_ids(case_response).contains(&"linux.child-b".to_string()),
        "B never spawned"
    );
    assert!(*case_response.complete());
    assert_eq!(
        *case_record.state_at_case_end().as_ref().unwrap(),
        CleanupState::Complete
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn ambient_removal_is_not_custody() {
    let (dir, _root) = temp_root("retire-interfere");
    let (plan, contract) = tt03_runner_contract();
    let op = *invocation_for(&contract).key().operation_id();
    let target = case_path_run(&dir, contract.run_id().as_str(), op);
    let (mut session, _) = tt03_session(&dir, &contract, "leader-lifecycle", None, None);
    let mut adapter = Tt03RetireAdapter {
        subject: contract.expected_subject().clone(),
        advance_steps: vec![],
        interfere_remove: Some(target),
        calls: 0,
    };
    let oracle = tt03_oracle(&contract);
    let report = scopebase_testkit::run_profile(&plan, &mut adapter, &mut session, &oracle)
        .expect("interference retire run completes");
    let fixture = fixture_records(&report);
    let case_record = &report.cleanup_records()[fixture[0]];
    let case_response = case_record
        .response()
        .as_ref()
        .expect("case retire response");
    assert_eq!(
        transition_resource_ids(case_response),
        vec!["linux.child-a".to_string(), "linux.child-b".to_string(),]
    );
    assert!(
        !*case_response.complete(),
        "foreign-removed root is unknown, never retired"
    );
    let diagnostic = case_response
        .diagnostic()
        .as_ref()
        .expect("retire diagnostic");
    assert!(
        diagnostic.contains("linux.case-root"),
        "unknown names case-root: {diagnostic}"
    );
    assert_eq!(
        case_response.pending_snapshot().len(),
        1,
        "case-root stays pending"
    );
    assert_eq!(
        case_response.pending_snapshot()[0].resource_id().as_str(),
        "linux.case-root"
    );
    assert_eq!(
        *case_record.state_at_case_end().as_ref().unwrap(),
        CleanupState::Unresolved
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn drop_without_retire_is_failed_shutdown() {
    let (dir, _root) = temp_root("drop-only");
    let (mut session, _, invocation) = native_session(&dir, "leader-lifecycle");
    let access = session
        .prepare(&invocation)
        .expect("native prepare succeeds");
    let pid = access
        .resource::<LinuxProcessFixture>(&Label::parse("linux.process").unwrap())
        .expect("linux.process")
        .pid();
    let registrations = access.effects().registrations().to_vec();
    assert_eq!(registrations.len(), 3);
    drop(access);
    assert!(
        PathBuf::from(format!("/proc/{pid}")).exists(),
        "child is live before drop"
    );
    drop(session);
    // Best-effort Drop ran, but it proves nothing: no retirement report exists.
    let claim = CustodyClaim {
        retired_report: false,
        exit_status_only: false,
        original_root: true,
        original_owners: true,
        registered: registrations
            .iter()
            .map(|r| r.resource_id().clone())
            .collect(),
        transitioned: vec![],
        unknown: vec![],
        cleanup_errors: vec![],
    };
    let err = clean_shutdown_gate(&claim).unwrap_err();
    assert!(
        err.detail().contains("no retirement report"),
        "drop-only fails custody: {}",
        err.detail()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn skip_cleanup_leaves_live_owners_unresolved() {
    let (dir, _root) = temp_root("skip-cleanup");
    let (mut session, _, invocation) = native_session(&dir, "leader-lifecycle");
    let access = session
        .prepare(&invocation)
        .expect("native prepare succeeds");
    let pid_a = access
        .resource::<LinuxProcessFixture>(&Label::parse("linux.process").unwrap())
        .expect("linux.process")
        .pid();
    let pid_b = access
        .resource::<LinuxProcessFixture>(&Label::parse("linux.excluded-process").unwrap())
        .expect("linux.excluded-process")
        .pid();
    drop(access);
    // Zero native attempts: the guard cannot be charged, pairs stay live.
    session
        .finalize(LinuxOuterCleanupBudget {
            deadline: Instant::now() + Duration::from_secs(2),
            max_native_attempts: 0,
            max_records: 8,
            max_retained_bytes: 65536,
        })
        .expect("exhausted budget seals unresolved");
    let report = session
        .outer_cleanup_report()
        .expect("sealed report")
        .as_bytes()
        .to_vec();
    let v: serde_json::Value = serde_json::from_slice(&report).unwrap();
    assert_eq!(v["kind"], "unresolved");
    let unresolved = v["unresolved_owners"].as_array().unwrap();
    assert!(unresolved
        .iter()
        .any(|o| o.as_str().unwrap_or("").starts_with("prepared-pair-")));
    assert!(
        PathBuf::from(format!("/proc/{pid_a}")).exists(),
        "A stays live without cleanup"
    );
    assert!(
        PathBuf::from(format!("/proc/{pid_b}")).exists(),
        "B stays live without cleanup"
    );
    drop(session);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn substituted_owner_identity_fails_retirement_oracle() {
    let (dir, _root) = temp_root("substituted-owner");
    let (mut session, _, invocation) = native_session(&dir, "leader-lifecycle");
    let access = session
        .prepare(&invocation)
        .expect("native prepare succeeds");
    let prepare = access.effects().clone();
    drop(access);
    let limits = RunLimits::default();
    let original = prepare
        .registrations()
        .iter()
        .find(|r| r.resource_id().as_str() == "linux.child-a")
        .expect("child-a registration");
    // Mutant: same resource id and origin, reopened-substitute identity.
    let substituted = PendingEffectRef::new(
        PendingEffectRefValues {
            resource_id: original.resource_id().clone(),
            owner: *original.owner(),
            origin: original.origin().clone(),
            identity_sha256: Digest256::of_bytes(b"reopened-substitute"),
        },
        &limits,
    )
    .unwrap();
    let mutant = EffectTransition::new(
        EffectTransitionValues {
            transition_id: Label::parse("linux.retire.1.child-a").unwrap(),
            effect: substituted,
            to: TransitionTo::Retired,
            evidence_ids: vec![Label::parse("linux.proof.1.child-a").unwrap()],
        },
        &limits,
    )
    .unwrap();
    let empty = EffectBatch::empty(&limits);
    let err = verify_retirement_exactly_once(&prepare, &empty, &[], &[mutant]).unwrap_err();
    assert!(
        err.detail().contains("identity mismatch"),
        "substituted identity fails its assertion: {}",
        err.detail()
    );
    // Valid twin: the exact registered ref transitions cleanly.
    let exact = PendingEffectRef::new(
        PendingEffectRefValues {
            resource_id: original.resource_id().clone(),
            owner: *original.owner(),
            origin: original.origin().clone(),
            identity_sha256: *original.identity_sha256(),
        },
        &limits,
    )
    .unwrap();
    let valid = EffectTransition::new(
        EffectTransitionValues {
            transition_id: Label::parse("linux.retire.1.child-a").unwrap(),
            effect: exact,
            to: TransitionTo::Retired,
            evidence_ids: vec![Label::parse("linux.proof.1.child-a").unwrap()],
        },
        &limits,
    )
    .unwrap();
    verify_retirement_exactly_once(&prepare, &empty, &[], &[valid]).unwrap();
    // And the gate refuses substituted owners as a custody claim.
    let claim = CustodyClaim {
        retired_report: true,
        exit_status_only: false,
        original_root: true,
        original_owners: false,
        registered: vec![Label::parse("linux.child-a").unwrap()],
        transitioned: vec![Label::parse("linux.child-a").unwrap()],
        unknown: vec![],
        cleanup_errors: vec![],
    };
    let err = clean_shutdown_gate(&claim).unwrap_err();
    assert!(
        err.detail().contains("substituted owner"),
        "{}",
        err.detail()
    );
    drop(session);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn foreign_root_proof_fails_custody_gate() {
    let (dir, _root) = temp_root("foreign-root");
    let (mut session, contract, invocation) = native_session(&dir, "leader-lifecycle");
    let op = *invocation.key().operation_id();
    let access = session
        .prepare(&invocation)
        .expect("native prepare succeeds");
    let registrations = access.effects().registrations().to_vec();
    drop(access);
    // The ambient path resolves to the same live directory, yet proof by
    // ambient path is foreign: only the original retained root counts.
    let ambient = case_path_run(&dir, contract.run_id().as_str(), op);
    assert!(ambient.is_dir(), "ambient path reaches the live case dir");
    let ids: Vec<Label> = registrations
        .iter()
        .map(|r| r.resource_id().clone())
        .collect();
    let mutant = CustodyClaim {
        retired_report: true,
        exit_status_only: false,
        original_root: false,
        original_owners: true,
        registered: ids.clone(),
        transitioned: ids.clone(),
        unknown: vec![],
        cleanup_errors: vec![],
    };
    let err = clean_shutdown_gate(&mutant).unwrap_err();
    assert!(
        err.detail().contains("foreign root"),
        "foreign root fails its assertion: {}",
        err.detail()
    );
    let valid = CustodyClaim {
        retired_report: true,
        exit_status_only: false,
        original_root: true,
        original_owners: true,
        registered: ids.clone(),
        transitioned: ids,
        unknown: vec![],
        cleanup_errors: vec![],
    };
    clean_shutdown_gate(&valid).unwrap();
    drop(session);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn exit_status_only_is_not_custody() {
    let (pair, dir) = live_pair(Scenario::LeaderLifecycle, 41);
    let a = pair.a_process();
    a.advance(&label("s01-ready")).unwrap();
    let shutdown = pair.shutdown();
    assert_eq!(
        shutdown.b_exit.map(|e| e.code),
        Some(Some(0)),
        "real exit 0 observed"
    );
    // Mutant: the claim rests only on that exit status, without per-owner proof.
    let mutant = CustodyClaim {
        retired_report: true,
        exit_status_only: true,
        original_root: true,
        original_owners: true,
        registered: vec![Label::parse("linux.child-b").unwrap()],
        transitioned: vec![Label::parse("linux.child-b").unwrap()],
        unknown: vec![],
        cleanup_errors: vec![],
    };
    let err = clean_shutdown_gate(&mutant).unwrap_err();
    assert!(
        err.detail().contains("exit status is not custody proof"),
        "exit0-only fails its assertion: {}",
        err.detail()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// S229/R32 canary: a preplanted symlink at the claimed path is
/// refused, never followed: the outside canary survives and nothing
/// is written through the link.
#[test]
fn s229_temp_claim_refuses_preplanted_symlink() {
    let nonce = start_nonce();
    let plant = std::env::temp_dir().join(format!(
        "tt03-canary-plant-{}-{:x}",
        std::process::id(),
        nonce
    ));
    let _ = std::fs::remove_file(&plant);
    let _ = std::fs::remove_dir_all(&plant);
    let outside = std::env::temp_dir().join(format!(
        "tt03-canary-outside-{}-{:x}",
        std::process::id(),
        nonce
    ));
    let _ = std::fs::remove_dir_all(&outside);
    claim_temp_dir(&outside);
    let canary = outside.join("canary.txt");
    std::fs::write(&canary, b"canary").unwrap();
    std::os::unix::fs::symlink(&outside, &plant).unwrap();
    let outcome = std::panic::catch_unwind(|| claim_temp_dir(&plant));
    assert!(
        outcome.is_err(),
        "preplanted symlink was claimed instead of refused"
    );
    assert_eq!(
        std::fs::read(&canary).unwrap(),
        b"canary",
        "claim wrote through the planted link"
    );
    std::fs::remove_file(&plant).unwrap();
    std::fs::remove_dir_all(&outside).unwrap();
}
