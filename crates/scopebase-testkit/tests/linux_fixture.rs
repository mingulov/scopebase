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

#[test]
fn prepare_collect_return_typed_deferred() {
    let (dir, _root) = temp_root("trait-honest");
    let (mut session, contract, _) = valid_session(&dir, "leader-lifecycle");
    let key = contract.schedule()[0].clone();
    let rule = contract
        .case_rules()
        .iter()
        .find(|r| r.case_key() == key.case_key())
        .unwrap();
    let invocation = scopebase_testkit::CaseInvocation::new(
        CaseInvocationValues {
            key,
            observation_schema: rule.observation_schema().clone(),
            fixture_schema: rule.fixture_schema().clone(),
            script: rule.script().clone(),
            limits: contract.limits().clone(),
        },
        contract.limits(),
    )
    .unwrap();
    let err = match session.prepare(&invocation) {
        Ok(_) => panic!("first-increment prepare must stay deferred"),
        Err(e) => e,
    };
    assert_eq!(*err.category(), FixtureErrorCategory::Other);
    assert!(!err.diagnostic_bytes().is_empty());
    let err = match session.collect(&invocation) {
        Ok(_) => panic!("first-increment collect must stay deferred"),
        Err(e) => e,
    };
    assert_eq!(*err.category(), FixtureErrorCategory::Other);
    std::fs::remove_dir_all(&dir).unwrap();
}

fn live_pair(
    scenario: Scenario,
    op: u64,
) -> (
    scopebase_testkit::fixture::linux::LivePair,
    PathBuf,
) {
    let (dir, root) = temp_root("live");
    let (fa, pa, fb, pb) = stage_images(&dir);
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
