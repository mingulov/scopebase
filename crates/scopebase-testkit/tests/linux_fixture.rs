// SPDX-License-Identifier: Apache-2.0
//! TT03 first-increment integration: public session API plus the packaged
//! worker driven through the developer driver. Wire/manifest/creator internals
//! are covered by unit tests inside their private modules.
use scopebase_testkit::fixture::linux::{
    launch_pair, DriverErrorKind, LaunchConfig, LinuxFixtureFiles, LinuxFixtureSession,
    LinuxOuterCleanupAdmissionErrorKind, LinuxOuterCleanupBudget, LinuxProcessFixture,
    Scenario, TRICKY_COMM,
};
use scopebase_testkit::{CaseInvocationValues, FixtureErrorCategory, FixtureSession, Label};
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

fn temp_root(tag: &str) -> (PathBuf, File) {
    let base = std::env::temp_dir().join(format!(
        "tt03-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base).unwrap();
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
    let steps: Vec<serde_json::Value> = Scenario::parse(scenario)
        .unwrap()
        .steps()
        .iter()
        .map(|s| {
            serde_json::json!({"id": s.id, "action": s.action.as_str(), "actor": s.actor.as_str()})
        })
        .collect();
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
            "control": null,
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
    let mk = |deadline: Instant, attempts: u64, records: u64, bytes: u64| {
        LinuxOuterCleanupBudget {
            deadline,
            max_native_attempts: attempts,
            max_records: records,
            max_retained_bytes: bytes,
        }
    };
    let soon = Instant::now() + Duration::from_secs(2);
    assert!(matches!(
        session
            .finalize(mk(
                Instant::now() - Duration::from_secs(1),
                64,
                8,
                65536
            ))
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
        session
            .finalize(mk(soon, 64, 0, 65536))
            .unwrap_err()
            .kind(),
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
    let first = failure
        .custody
        .finalize(mk())
        .unwrap()
        .as_bytes()
        .to_vec();
    let again = failure
        .custody
        .finalize(mk())
        .unwrap()
        .as_bytes()
        .to_vec();
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
    let (_, _, contract) = support::load();
    let invocation = invocation_for(&contract);
    let op = *invocation.key().operation_id();
    let root = File::open(dir).unwrap();
    let files = make_files(dir, root);
    let manifest = manifest_bytes(contract.run_id().as_str(), scenario, op);
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
) -> (
    scopebase_testkit::fixture::linux::LivePair,
    PathBuf,
) {
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
    };
    let pair = launch_pair(&cfg).unwrap();
    (pair, dir)
}

fn live_pair(
    scenario: Scenario,
    op: u64,
) -> (
    scopebase_testkit::fixture::linux::LivePair,
    PathBuf,
) {
    live_pair_with_images(scenario, op, false)
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
        .map(|e| e.unwrap().file_name().to_string_lossy().parse::<u32>().unwrap())
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
    assert_eq!(
        pair.a_exited_unreaped().unwrap(),
        Some(libc::CLD_KILLED)
    );
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
    let read = held.read_all(limits, &OperationControl::unlimited()).unwrap();
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
    let nsfs = b"1572 34 0:5 net:[4026532307] /run/docker/netns/5014e9543e94 rw shared:1132 - nsfs nsfs rw\n";
    assert!(
        parse_mountinfo(
            nsfs,
            ParseLimits {
                max_bytes: nsfs.len(),
                max_entries: 4,
                max_line_bytes: 8192,
            },
        )
        .is_err(),
        "accepted parser pins current nsfs-source refusal (LX05 follow-up)"
    );
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
    a.advance(&label("s03-exec-b")).expect("real exec to image B");
    let sha_b = exe_sha256(pair.a_pid());
    assert_ne!(sha_a, sha_b, "executable image changed at A->B");
    assert_eq!(proc_starttime(pair.a_pid()), start, "birth preserved at A->B");
    assert_eq!(a.pid(), pair.a_pid(), "same PID across exec");
    a.advance(&label("s04-b")).unwrap();
    a.advance(&label("s05-exec-a")).expect("real exec back to image A");
    assert_eq!(exe_sha256(pair.a_pid()), sha_a, "executable image restored");
    assert_eq!(proc_starttime(pair.a_pid()), start, "birth preserved at B->A");
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
    a.advance(&label("s04-exit-leader")).expect("leader-only native exit");
    assert_eq!(task_state(pair.a_pid(), pair.a_pid()), b'Z', "leader is a zombie");
    assert_ne!(task_state(pair.a_pid(), sibling), b'Z', "sibling stays live");
    assert_eq!(a.nonleader_tid(), Some(sibling));
    a.advance(&label("s05-leader-exited")).unwrap();
    a.advance(&label("s06-missing")).expect("failed exec from sibling");
    assert_eq!(task_state(pair.a_pid(), pair.a_pid()), b'Z');
    assert_ne!(task_state(pair.a_pid(), sibling), b'Z');
    a.advance(&label("s07-still-sibling")).unwrap();
    let sha_before = exe_sha256_as(pair.a_pid(), a.nonleader_tid());
    a.advance(&label("s08-exec-sibling")).expect("real nonleader exec");
    assert_ne!(exe_sha256(pair.a_pid()), sha_before, "new image after exec");
    assert_eq!(task_tids(pair.a_pid()), vec![pair.a_pid()], "single thread again");
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
    pair.upload_blobs(b"alpha-content-001", b"beta--content-002", b"ALPHA-CONTENT-001")
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
    assert_eq!(body["values"]["canary_hex"], "53424649585455524543414e41525931");
    let negative = raw
        .iter()
        .find(|r| r.kind == "fd" && r.step_id == "s04-inventory" && r.actor == "parent-negative")
        .expect("negative inventory record");
    let negative_body: serde_json::Value = serde_json::from_slice(&negative.bytes).unwrap();
    assert_eq!(negative_body["values"]["canary_hex"], serde_json::Value::Null);
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
    a.advance(&label("s03-exec-b")).expect("real exec to image B");
    a.advance(&label("s04-b")).unwrap();
    a.advance(&label("s05-exec-a")).expect("real exec back to image A");
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
    a.advance(&label("s03-exec-b")).expect("real exec to image B");
    a.advance(&label("s04-b")).unwrap();
    a.advance(&label("s05-exec-a")).expect("real exec back to image A");
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
