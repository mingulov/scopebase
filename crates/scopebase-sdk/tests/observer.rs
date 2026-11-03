// SPDX-License-Identifier: Apache-2.0
//! SDK04 owned-workload observer tests: the observer spawns its OWN workload
//! and refuses every foreign PID with a typed error before any effect. Owned
//! observations are bounded (count and retained bytes, N/N+1), cooperative
//! cancellation surfaces as typed Linux refusal, held reads survive path
//! replacement, and shutdown/drop reap the owned child with no zombie.
//!
//! Fixture patterns are independently authored literals below; expected bytes
//! are asserted from those same literals.

#![cfg(feature = "linux")]

use scopebase_linux::control::{CancelToken, OperationControl};
use scopebase_linux::error::Reason;
use scopebase_linux::file::ReadLimits;
use scopebase_sdk::context::AppContext;
use scopebase_sdk::limits::Limits;
use scopebase_sdk::observer::{
    ObserverError, ObserverLimits, WaitOutcome, WorkloadObserver, DEFAULT_INPUT_BYTES,
    DEFAULT_LIVE_OWNERS, DEFAULT_OPERATIONS, DEFAULT_PATTERN_BYTES, DEFAULT_RETAINED_BYTES,
};
use scopebase_sdk::profile::Profile;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "sdk04-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// External R1-1: run `op` on a DETACHED worker, returning the
/// receiver for a bounded `recv_timeout` wait. A wedged worker is
/// abandoned, never joined — the timeout panics instead of hanging
/// the suite. (`thread::scope` would join the stuck worker during
/// teardown: proved hung, killed by timeout exit 124.) The abandoned
/// worker dies with the test process; it exists only when the
/// operation under test already wedged, i.e. the suite is red.
fn run_detached<T, F>(op: F) -> std::sync::mpsc::Receiver<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(op());
    });
    rx
}

/// External R1-1 collateral: the timeout path abandons a wedged
/// worker instead of joining it. A parked worker plus a 100ms
/// timeout yields `Timeout` and the test ENDS.
#[test]
fn detached_timeout_abandons_wedged_worker() {
    let rx = run_detached(|| {
        std::thread::park();
    });
    let err = rx
        .recv_timeout(Duration::from_millis(100))
        .unwrap_err();
    assert_eq!(err, std::sync::mpsc::RecvTimeoutError::Timeout);
}

/// Deterministic 4,096-byte ASCII pattern with no shell metacharacters.
fn pattern_a() -> Vec<u8> {
    assert_eq!(DEFAULT_PATTERN_BYTES, 4_096);
    let unit = b"sdk04-observation;";
    let mut out = Vec::with_capacity(DEFAULT_PATTERN_BYTES);
    while out.len() + unit.len() <= DEFAULT_PATTERN_BYTES {
        out.extend_from_slice(unit);
    }
    while out.len() < DEFAULT_PATTERN_BYTES {
        out.push(b'.');
    }
    out
}

fn pattern_b() -> Vec<u8> {
    assert_eq!(DEFAULT_PATTERN_BYTES, 4_096);
    vec![b'Q'; DEFAULT_PATTERN_BYTES]
}

fn test_profile() -> Profile {
    Profile::new("sdk04-observer", Vec::new(), Vec::new()).unwrap()
}

fn test_limits() -> Limits {
    Limits {
        input_bytes: DEFAULT_INPUT_BYTES,
        retained_bytes: 65_536,
        work_items: 64,
        live_owners: DEFAULT_LIVE_OWNERS,
        diagnostic_count: 32,
        diagnostic_bytes: 65_536,
        wait: Duration::from_secs(2),
    }
}

fn test_observer_limits() -> ObserverLimits {
    ObserverLimits {
        max_observations: DEFAULT_OPERATIONS,
        max_retained_bytes: DEFAULT_RETAINED_BYTES,
        read: ReadLimits {
            max_bytes: DEFAULT_INPUT_BYTES,
            max_read_calls: 64,
            max_buffer_capacity: 65_537,
        },
    }
}

/// A writer workload: the OWNED child writes `bytes` to `path` and exits.
fn writer_command(path: &PathBuf, bytes: &[u8]) -> Command {
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let mut command = Command::new("sh");
    command.arg("-c").arg(format!(
        "printf '%s' '{}' > '{}'",
        text,
        path.to_string_lossy()
    ));
    command
}

fn is_foreign_pid(pids: &[u32]) -> u32 {
    // PID 1 (init) is never a child this test process spawned.
    assert!(!pids.contains(&1));
    1
}

#[test]
fn owned_workload_produces_bounded_observations() {
    let fixture = Fixture::new();
    let target = fixture.path("owned.bin");
    let expected = pattern_a();
    let mut command = writer_command(&target, &expected);
    let mut observer =
        WorkloadObserver::spawn(test_profile(), test_limits(), test_observer_limits(), &mut command)
            .unwrap();
    let pid = observer.pid();
    assert!(pid > 1);

    let outcome = observer.wait_for_exit(Duration::from_secs(10)).unwrap();
    assert!(outcome.exited(), "owned writer must exit, got {outcome:?}");

    let control = OperationControl::unlimited();
    let observation = observer.observe_file(pid, &target, &control).unwrap();
    assert_eq!(observation.sequence, 0);
    assert_eq!(observation.pid, pid);
    assert_eq!(observation.bytes, expected);
    assert_eq!(observation.before.len() as usize, expected.len());
    assert_eq!(observation.after.len() as usize, expected.len());
    assert_eq!(observation.before.key(), observation.after.key());
    assert!(observation.read_calls >= 1);
    assert_eq!(observer.observation_count(), 1);
    assert_eq!(observer.retained_bytes(), expected.len() as u64);

    // Bounded report: one diagnostic retained per observation, admission
    // untouched by observation facts.
    let report = observer.context().report();
    assert_eq!(report.diagnostics.len(), 1);
    assert_eq!(report.diagnostics[0].code, "sdk04_observe");
    assert_eq!(report.omitted.count, 0);

    let shutdown = observer.shutdown().unwrap();
    assert_eq!(shutdown.pid, pid);
    assert!(shutdown.exited_cleanly());
    assert_eq!(shutdown.observations, 1);
    assert_eq!(shutdown.retained_bytes, expected.len() as u64);
}

#[test]
fn foreign_pid_is_refused_before_effects() {
    let fixture = Fixture::new();
    let target = fixture.path("owned.bin");
    let expected = pattern_a();
    let mut command = writer_command(&target, &expected);
    let mut observer =
        WorkloadObserver::spawn(test_profile(), test_limits(), test_observer_limits(), &mut command)
            .unwrap();
    let pid = observer.pid();
    let outcome = observer.wait_for_exit(Duration::from_secs(10)).unwrap();
    assert!(outcome.exited());

    let control = OperationControl::unlimited();
    let foreign = is_foreign_pid(&[pid, std::process::id()]);
    let refused = observer.observe_file(foreign, &target, &control);
    assert!(
        matches!(refused, Err(ObserverError::ForeignPid)),
        "foreign PID must be refused typed, got {refused:?}"
    );
    // Refusal precedes effects: no observation, no retained bytes, no file
    // acquisition recorded, and the owned PID still observes afterwards.
    assert_eq!(observer.observation_count(), 0);
    assert_eq!(observer.retained_bytes(), 0);
    assert_eq!(observer.context().report().diagnostics.len(), 0);

    let observation = observer.observe_file(pid, &target, &control).unwrap();
    assert_eq!(observation.bytes, expected);
    assert_eq!(observer.observation_count(), 1);

    let shutdown = observer.shutdown().unwrap();
    assert!(shutdown.exited_cleanly());
}

#[test]
fn observation_count_bound_is_enforced() {
    let fixture = Fixture::new();
    let target = fixture.path("owned.bin");
    let expected = pattern_a();
    let mut command = writer_command(&target, &expected);
    let limits = ObserverLimits {
        max_observations: 1,
        ..test_observer_limits()
    };
    let mut observer =
        WorkloadObserver::spawn(test_profile(), test_limits(), limits, &mut command).unwrap();
    let pid = observer.pid();
    assert!(observer.wait_for_exit(Duration::from_secs(10)).unwrap().exited());

    let control = OperationControl::unlimited();
    observer.observe_file(pid, &target, &control).unwrap();
    let refused = observer.observe_file(pid, &target, &control);
    assert!(
        matches!(refused, Err(ObserverError::Capacity)),
        "second observation over max_observations=1 must refuse, got {refused:?}"
    );
    // Failed observation retains nothing new.
    assert_eq!(observer.observation_count(), 1);
    assert_eq!(observer.retained_bytes(), expected.len() as u64);

    observer.shutdown().unwrap();
}

#[test]
fn retained_bytes_bound_is_enforced_n_over_n_plus_one() {
    let fixture = Fixture::new();
    let expected = pattern_a();
    let over = (expected.len() as u64) - 1;
    let exact = expected.len() as u64;

    // N = exact fit passes.
    let target = fixture.path("exact.bin");
    let mut command = writer_command(&target, &expected);
    let limits = ObserverLimits {
        max_retained_bytes: exact,
        ..test_observer_limits()
    };
    let mut observer =
        WorkloadObserver::spawn(test_profile(), test_limits(), limits, &mut command).unwrap();
    let pid = observer.pid();
    assert!(observer.wait_for_exit(Duration::from_secs(10)).unwrap().exited());
    observer
        .observe_file(pid, &target, &OperationControl::unlimited())
        .unwrap();
    assert_eq!(observer.retained_bytes(), exact);
    observer.shutdown().unwrap();

    // N+1 = one byte short refuses before retention.
    let target = fixture.path("over.bin");
    let mut command = writer_command(&target, &expected);
    let limits = ObserverLimits {
        max_retained_bytes: over,
        ..test_observer_limits()
    };
    let mut observer =
        WorkloadObserver::spawn(test_profile(), test_limits(), limits, &mut command).unwrap();
    let pid = observer.pid();
    assert!(observer.wait_for_exit(Duration::from_secs(10)).unwrap().exited());
    let refused = observer.observe_file(pid, &target, &OperationControl::unlimited());
    assert!(
        matches!(refused, Err(ObserverError::Capacity)),
        "retained N+1 must refuse, got {refused:?}"
    );
    assert_eq!(observer.observation_count(), 0);
    assert_eq!(observer.retained_bytes(), 0);
    observer.shutdown().unwrap();
}

#[test]
fn cancelled_control_refuses_read_as_cancelled() {
    let fixture = Fixture::new();
    let target = fixture.path("owned.bin");
    let expected = pattern_a();
    let mut command = writer_command(&target, &expected);
    let mut observer =
        WorkloadObserver::spawn(test_profile(), test_limits(), test_observer_limits(), &mut command)
            .unwrap();
    let pid = observer.pid();
    assert!(observer.wait_for_exit(Duration::from_secs(10)).unwrap().exited());

    // LX04: cancellation shared through the observer's control reaches the
    // bounded read, which reports typed Cancelled with no retention.
    let token = CancelToken::new();
    token.cancel();
    let control = OperationControl::new(None, token);
    let refused = observer.observe_file(pid, &target, &control);
    match refused {
        Err(ObserverError::Linux(error)) => assert_eq!(error.reason(), Reason::Cancelled),
        other => panic!("cancelled read must surface Linux Cancelled, got {other:?}"),
    }
    assert_eq!(observer.observation_count(), 0);
    assert_eq!(observer.retained_bytes(), 0);

    // The observer itself is unharmed: an uncancelled control still observes.
    let observation = observer
        .observe_file(pid, &target, &OperationControl::unlimited())
        .unwrap();
    assert_eq!(observation.bytes, expected);
    observer.shutdown().unwrap();
}

#[test]
fn held_observation_survives_path_replacement() {
    let fixture = Fixture::new();
    let target = fixture.path("swap.bin");
    let before_bytes = pattern_a();
    let mut command = writer_command(&target, &before_bytes);
    let mut observer =
        WorkloadObserver::spawn(test_profile(), test_limits(), test_observer_limits(), &mut command)
            .unwrap();
    let pid = observer.pid();
    assert!(observer.wait_for_exit(Duration::from_secs(10)).unwrap().exited());

    let control = OperationControl::unlimited();
    let first = observer.observe_file(pid, &target, &control).unwrap();
    assert_eq!(first.bytes, before_bytes);
    let first_key = first.before.key();

    // Replace the path out from under the observation: write a sibling
    // and rename it over the target so the path resolves to a new inode
    // (plain truncate-write would keep the same file identity). The
    // `fs::read` check is the independent raw verification path, not
    // production read output.
    let after_bytes = pattern_b();
    let sibling = fixture.path("swap.bin.new");
    fs::write(&sibling, &after_bytes).unwrap();
    fs::rename(&sibling, &target).unwrap();
    assert_eq!(fs::read(&target).unwrap(), after_bytes);

    // Retained observation still carries the original bytes and identity.
    assert_eq!(observer.observations()[0].bytes, before_bytes);
    assert_eq!(observer.observations()[0].before.key(), first_key);

    // A fresh observation sees the replacement under a distinct identity.
    let second = observer.observe_file(pid, &target, &control).unwrap();
    assert_eq!(second.sequence, 1);
    assert_eq!(second.bytes, after_bytes);
    assert_ne!(second.before.key(), first_key);

    observer.shutdown().unwrap();
}

#[test]
fn invalid_observer_limits_refuse_before_spawn() {
    let zero_count = ObserverLimits {
        max_observations: 0,
        ..test_observer_limits()
    };
    let mut probe = Command::new("sh");
    probe.arg("-c").arg("exit 0");
    let refused = WorkloadObserver::spawn(test_profile(), test_limits(), zero_count, &mut probe);
    assert!(matches!(refused, Err(ObserverError::InvalidLimits)));

    let zero_retained = ObserverLimits {
        max_retained_bytes: 0,
        ..test_observer_limits()
    };
    let refused = WorkloadObserver::spawn(test_profile(), test_limits(), zero_retained, &mut probe);
    assert!(matches!(refused, Err(ObserverError::InvalidLimits)));

    let zero_read = ObserverLimits {
        read: ReadLimits {
            max_bytes: 0,
            max_read_calls: 64,
            max_buffer_capacity: 65_537,
        },
        ..test_observer_limits()
    };
    let refused = WorkloadObserver::spawn(test_profile(), test_limits(), zero_read, &mut probe);
    assert!(matches!(refused, Err(ObserverError::InvalidLimits)));

    // S218 self-review: the remaining two refusal shapes. Zero
    // read-call and buffer-capacity ceilings refuse InvalidLimits
    // WITHOUT spawning — the nonexistent binary proves refusal
    // precedes spawn (a spawn-first order would yield Spawn).
    for (field, read) in [
        (
            "max_read_calls",
            ReadLimits {
                max_bytes: 1024,
                max_read_calls: 0,
                max_buffer_capacity: 65_537,
            },
        ),
        (
            "max_buffer_capacity",
            ReadLimits {
                max_bytes: 1024,
                max_read_calls: 64,
                max_buffer_capacity: 0,
            },
        ),
    ] {
        let limits = ObserverLimits {
            read,
            ..test_observer_limits()
        };
        let mut ghost = Command::new("/nonexistent-sdk04-probe");
        let refused = WorkloadObserver::spawn(test_profile(), test_limits(), limits, &mut ghost);
        assert!(
            matches!(refused, Err(ObserverError::InvalidLimits)),
            "{field} must refuse before spawn"
        );
    }
}

#[test]
fn shutdown_reaps_running_child_with_explicit_outcome() {
    // Long-lived owned workload: shutdown must kill and reap it, reporting
    // the forced outcome explicitly rather than as a clean exit.
    let mut command = Command::new("sleep");
    command.arg("60");
    let mut observer =
        WorkloadObserver::spawn(test_profile(), test_limits(), test_observer_limits(), &mut command)
            .unwrap();
    let pid = observer.pid();

    let shutdown = observer.shutdown().unwrap();
    assert_eq!(shutdown.pid, pid);
    assert!(!shutdown.exited_cleanly());
    assert!(shutdown.was_killed());
    assert_eq!(shutdown.observations, 0);

    // No zombie: the owned PID is reaped and gone from the process table.
    assert!(!proc_pid_exists(pid), "owned PID {pid} must be reaped");

    // Second shutdown is a typed refusal, not a second kill.
    let again = observer.shutdown();
    assert!(
        matches!(again, Err(ObserverError::ShutDown)),
        "repeat shutdown must refuse typed, got {again:?}"
    );
    // Post-shutdown observation is refused too.
    let refused = observer.observe_file(pid, PathBuf::from("/nonexistent").as_path(), &OperationControl::unlimited());
    assert!(matches!(refused, Err(ObserverError::ShutDown)));
}

#[test]
fn drop_without_shutdown_reaps_running_child() {
    let mut command = Command::new("sleep");
    command.arg("60");
    let observer =
        WorkloadObserver::spawn(test_profile(), test_limits(), test_observer_limits(), &mut command)
            .unwrap();
    let pid = observer.pid();
    drop(observer);

    // Drop is last-resort cleanup of the OWNED child only: kill plus reap,
    // never a detached zombie. Poll briefly for reaping to land.
    let deadline = Instant::now() + Duration::from_secs(5);
    while proc_pid_exists(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!proc_pid_exists(pid), "dropped observer must reap owned PID {pid}");
}

#[test]
fn wait_timeout_leaves_child_running_and_unreaped() {
    let mut command = Command::new("sleep");
    command.arg("60");
    let mut observer =
        WorkloadObserver::spawn(test_profile(), test_limits(), test_observer_limits(), &mut command)
            .unwrap();
    let pid = observer.pid();

    let outcome = observer.wait_for_exit(Duration::from_millis(50)).unwrap();
    assert!(!outcome.exited(), "short wait must time out, got {outcome:?}");
    // A timeout is an observation deadline, not retirement: the child is
    // still alive and still owned (shutdown below must report a kill).
    assert!(proc_pid_exists(pid));

    let shutdown = observer.shutdown().unwrap();
    assert!(shutdown.was_killed());
    assert!(!proc_pid_exists(pid));
}

fn proc_pid_exists(pid: u32) -> bool {
    PathBuf::from(format!("/proc/{pid}")).exists()
}

#[test]
fn context_is_inert_and_borrow_only() {
    // The observer's AppContext behaves as SDK02 specifies: dropping the
    // observer touches no context-external resource beyond its owned child,
    // and the context borrow exposes no authority.
    let fixture = Fixture::new();
    let target = fixture.path("owned.bin");
    let expected = pattern_a();
    let mut command = writer_command(&target, &expected);
    let mut observer =
        WorkloadObserver::spawn(test_profile(), test_limits(), test_observer_limits(), &mut command)
            .unwrap();
    let pid = observer.pid();
    assert!(observer.wait_for_exit(Duration::from_secs(10)).unwrap().exited());
    observer
        .observe_file(pid, &target, &OperationControl::unlimited())
        .unwrap();
    let context: &AppContext = observer.context();
    assert_eq!(context.report().observations.len(), 0);
    assert_eq!(context.report().diagnostics.len(), 1);
    observer.shutdown().unwrap();
}

// S212: an overflowing deadline (`Duration::MAX`) saturates to
// "never expires" instead of timing out immediately. A waiter
// thread must still be blocked after 100ms; an external kill then
// lets it reap Exited (proving it waited past the overflow point
// rather than returning instant Timeout).
#[test]
fn wait_for_exit_overflow_timeout_waits() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let mut command = Command::new("sleep");
    command.arg("60");
    let mut observer =
        WorkloadObserver::spawn(test_profile(), test_limits(), test_observer_limits(), &mut command)
            .unwrap();
    let pid = observer.pid();
    let done = Arc::new(AtomicBool::new(false));
    std::thread::scope(|s| {
        let waiter_done = done.clone();
        let obs = &mut observer;
        let waiter = s.spawn(move || {
            let outcome = obs.wait_for_exit(Duration::MAX).unwrap();
            waiter_done.store(true, Ordering::SeqCst);
            outcome
        });
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !done.load(Ordering::SeqCst),
            "overflow wait returned immediately"
        );
        assert!(proc_pid_exists(pid), "child must still run at 100ms");
        let killed = Command::new("sh")
            .arg("-c")
            .arg(format!("kill {pid}"))
            .status()
            .unwrap();
        assert!(killed.success());
        let outcome = waiter.join().unwrap();
        assert!(
            matches!(outcome, WaitOutcome::Exited(_)),
            "waiter must reap the killed child, got {outcome:?}"
        );
    });
    assert!(!proc_pid_exists(pid), "killed child must be reaped");
    // The waiter already reaped: shutdown reports the earlier exit,
    // never a kill.
    let shutdown = observer.shutdown().unwrap();
    assert!(!shutdown.was_killed());
    assert!(!shutdown.exited_cleanly(), "signal kill is not clean");
}

// S215: the `FileObservation` Debug impl is a redaction boundary
// — retained bytes and stat metadata never render. Pinned with
// marker bytes: a derived `Debug` (or a new field wired into the
// manual impl) leaks the marker and fails this test.
#[test]
fn file_observation_debug_redacts_content() {
    let fixture = Fixture::new();
    let target = fixture.path("secret.bin");
    let marker = b"S215-SECRET-MARKER-9f8e7d6c5b";
    let mut command = writer_command(&target, marker);
    let mut observer =
        WorkloadObserver::spawn(test_profile(), test_limits(), test_observer_limits(), &mut command)
            .unwrap();
    let pid = observer.pid();
    assert!(observer.wait_for_exit(Duration::from_secs(10)).unwrap().exited());
    let control = OperationControl::unlimited();
    let observation = observer.observe_file(pid, &target, &control).unwrap();
    assert_eq!(&observation.bytes, marker);
    let rendered = format!("{observation:?}");
    assert!(
        !rendered.contains("S215-SECRET-MARKER"),
        "Debug leaks retained bytes: {rendered}"
    );
    assert!(
        !rendered.contains("secret.bin"),
        "Debug leaks the observed path: {rendered}"
    );
    // The safe skeleton still renders (regression trip-wire both
    // directions: redaction must not swallow the whole struct).
    for field in ["sequence", "pid", "bytes_len", "read_calls"] {
        assert!(rendered.contains(field), "missing {field}: {rendered}");
    }
    assert!(rendered.contains(&format!("bytes_len: {}", marker.len())));
    observer.shutdown().unwrap();
}

// S218: spawning a nonexistent workload binary fails with
// `Spawn`, preserving the OS error as source — never a panic,
// never a phantom observer.
#[test]
fn spawn_missing_binary_reports_spawn_error() {
    let mut command = Command::new("/nonexistent-scopebase-workload-binary");
    let err = WorkloadObserver::spawn(
        test_profile(),
        test_limits(),
        test_observer_limits(),
        &mut command,
    )
    .expect_err("missing binary must not spawn");
    assert!(
        matches!(err, ObserverError::Spawn(_)),
        "expected Spawn, got {err:?}"
    );
    assert!(!err.to_string().is_empty());
    assert!(std::error::Error::source(&err).is_some());
}

// S218: observing a 0-byte file returns promptly with empty bytes
// (EOF is not a retry condition). Runs on a DETACHED worker with a
// bounded wait (external R1-1): a read-zero spin trips the timeout
// instead of hanging the suite — the wedged worker is abandoned,
// never joined. The observer moves in and comes back out; outcome
// assertions run on the main thread so a content failure never
// misreports as a hang.
#[test]
fn observe_empty_file_returns_empty_bytes() {
    let fixture = Fixture::new();
    let target = fixture.path("empty.bin");
    std::fs::write(&target, b"").unwrap();
    let mut command = Command::new("true");
    let mut observer =
        WorkloadObserver::spawn(test_profile(), test_limits(), test_observer_limits(), &mut command)
            .unwrap();
    let pid = observer.pid();
    assert!(observer.wait_for_exit(Duration::from_secs(10)).unwrap().exited());
    let rx = run_detached(move || {
        let control = OperationControl::unlimited();
        // Owned bits only: the observation borrows the observer, so
        // both cannot cross the channel together.
        let outcome = observer
            .observe_file(pid, &target, &control)
            .map(|found| (found.sequence, found.bytes.clone(), found.read_calls));
        let counts = (observer.observation_count(), observer.retained_bytes());
        (outcome, counts, observer)
    });
    let (outcome, (count, retained), mut observer) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("observe_file hung on a 0-byte file");
    let (sequence, bytes, read_calls) = outcome.expect("empty file must observe");
    assert_eq!(sequence, 0);
    assert!(bytes.is_empty());
    assert!(read_calls >= 1, "empty read still charges its call");
    assert_eq!(count, 1);
    assert_eq!(retained, 0);
    observer.shutdown().unwrap();
}

// S213: race coverage — a naturally clean exit must never report
// `Killed`, however the shutdown kill races it. A zero status
// proves our kill did not cause the exit (a delivered SIGTERM
// never reads 0), so every clean round must report `Exited`.
#[test]
fn shutdown_clean_exit_never_reports_killed() {
    for _ in 0..30 {
        let mut command = Command::new("true");
        let mut observer = WorkloadObserver::spawn(
            test_profile(),
            test_limits(),
            test_observer_limits(),
            &mut command,
        )
        .unwrap();
        let shutdown = observer.shutdown().unwrap();
        if shutdown.status().success() {
            assert!(
                !shutdown.was_killed(),
                "clean exit misreported as kill"
            );
        }
    }
}
