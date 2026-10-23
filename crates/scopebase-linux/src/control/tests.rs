// SPDX-License-Identifier: Apache-2.0
//! Private seam/protocol tests. These do not implement or qualify HeldFile reads.
use super::*;
use crate::error::{CleanupDisposition, DescriptorFlagEffect};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{fs::MetadataExt, net::UnixStream},
    panic::{catch_unwind, AssertUnwindSafe},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicU64, AtomicUsize},
        mpsc, Mutex,
    },
    thread,
};

fn effect(attempted: u64, completed: u64) -> EffectSummary {
    EffectSummary {
        attempted,
        completed,
        cleanup: CleanupDisposition::NotNeeded,
        flags: DescriptorFlagEffect::NotAttempted,
    }
}
fn charges(syscalls: u64) -> ResourceCharges {
    ResourceCharges {
        parse: None,
        syscalls,
        acquired: 0,
        peak: 0,
        read: None,
        #[cfg(feature = "process")]
        process: None,
    }
}
fn control_at(start: Instant, after: Duration, token: CancelToken) -> OperationControl {
    OperationControl::new(Some(deadline_after_at(start, after).unwrap()), token)
}

#[test]
fn cancel_before_first_effect() {
    let token = CancelToken::new();
    let control = OperationControl::new(None, token.clone());
    let ledger = AtomicUsize::new(0);
    let owner = Arc::new(17);
    token.clone().cancel();
    let result = control
        .checkpoint()
        .map(|()| ledger.fetch_add(1, Ordering::SeqCst));
    assert_eq!(result, Err(ControlStop::Cancelled));
    assert_eq!(
        ledger.load(Ordering::SeqCst),
        0,
        "preflight must prevent effect"
    );
    assert_eq!(*owner, 17);
    OperationControl::unlimited().checkpoint().unwrap();
    ledger.fetch_add(1, Ordering::SeqCst);
    assert_eq!(ledger.load(Ordering::SeqCst), 1);
}
#[test]
fn deadline_equality_is_expired() {
    let start = Instant::now();
    let control = control_at(start, Duration::from_secs(1), CancelToken::new());
    assert_eq!(control.checkpoint_using(|| start), Ok(()));
    assert_eq!(
        control.checkpoint_using(|| start + Duration::from_secs(1)),
        Err(ControlStop::Deadline)
    );
    assert_eq!(
        control.checkpoint_using(|| start + Duration::from_secs(2)),
        Err(ControlStop::Deadline)
    );
    let zero = control_at(start, Duration::ZERO, CancelToken::new());
    assert_eq!(zero.checkpoint_using(|| start), Err(ControlStop::Deadline));
}
#[test]
fn deadline_overflow_is_invalid_input() {
    let error = deadline_after_at(Instant::now(), Duration::MAX).unwrap_err();
    assert_eq!(
        (error.stage(), error.reason()),
        (Stage::ConfigureControl, Reason::InvalidInput)
    );
    assert!(error.source().is_none());
    assert_eq!(
        (
            error.effect().attempted_operations(),
            error.effect().completed_operations(),
            error.charges().syscall_attempts(),
            error.charges().fd_acquisitions(),
            error.charges().peak_new_fds()
        ),
        (0, 0, 0, 0, 0)
    );
    assert_eq!(
        (error.effect().cleanup(), error.effect().descriptor_flags()),
        (
            CleanupDisposition::NotNeeded,
            DescriptorFlagEffect::NotAttempted
        )
    );
    assert!(deadline_after_at(Instant::now(), Duration::from_secs(1)).is_ok());
}
#[test]
fn independent_controls_do_not_share_deadline_state() {
    let start = Instant::now();
    let token = CancelToken::new();
    let a = control_at(start, Duration::ZERO, token.clone());
    let b = control_at(start, Duration::from_secs(2), token.clone());
    let cloned = b.clone();
    assert_eq!(a.checkpoint_using(|| start), Err(ControlStop::Deadline));
    assert_eq!(b.checkpoint_using(|| start), Ok(()));
    assert_eq!(
        cloned.checkpoint_using(|| start + Duration::from_secs(2)),
        Err(ControlStop::Deadline)
    );
    token.cancel();
    assert_eq!(b.checkpoint_using(|| start), Err(ControlStop::Cancelled));
    assert_eq!(
        control_at(start, Duration::from_secs(2), CancelToken::new()).checkpoint_using(|| start),
        Ok(())
    );
}
#[test]
fn reused_control_observes_current_stop_precedence() {
    let start = Instant::now();
    let token = CancelToken::new();
    let control = control_at(start, Duration::ZERO, token.clone());
    assert_eq!(
        control.checkpoint_using(|| start),
        Err(ControlStop::Deadline)
    );
    assert_eq!(
        control.checkpoint_using(|| start),
        Err(ControlStop::Deadline)
    );
    token.cancel();
    assert_eq!(
        control.checkpoint_using(|| start),
        Err(ControlStop::Cancelled)
    );
}
#[test]
fn cancel_race_has_a_checkpoint_boundary() {
    let token = CancelToken::new();
    let control = OperationControl::new(None, token.clone());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        token.cancel();
        tx.send(()).unwrap();
    })
    .join()
    .unwrap();
    rx.recv().unwrap();
    assert_eq!(control.checkpoint(), Err(ControlStop::Cancelled));
    let start = Instant::now();
    let token = CancelToken::new();
    let control = control_at(start, Duration::from_secs(1), token.clone());
    let (loaded_tx, loaded_rx) = mpsc::channel();
    let (cancelled_tx, cancelled_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        loaded_rx.recv().unwrap();
        token.cancel();
        cancelled_tx.send(()).unwrap();
    });
    assert_eq!(
        control.checkpoint_using(|| {
            loaded_tx.send(()).unwrap();
            cancelled_rx.recv().unwrap();
            start
        }),
        Ok(()),
        "cancellation after the final load may coexist with success"
    );
    worker.join().unwrap();
    assert_eq!(control.checkpoint(), Err(ControlStop::Cancelled));
}
#[test]
fn cancel_clone_drop_does_not_reset() {
    let token = CancelToken::new();
    let control = OperationControl::new(None, token.clone());
    let clone = control.clone();
    token.cancel();
    drop(token);
    drop(clone);
    assert_eq!(control.checkpoint(), Err(ControlStop::Cancelled));
    assert_eq!(
        OperationControl::unlimited().checkpoint_using(|| panic!("no deadline queries no clock")),
        Ok(())
    );
}
#[test]
fn cancel_after_success_preserves_metadata() {
    let token = CancelToken::new();
    let control = OperationControl::new(None, token.clone());
    control.checkpoint().unwrap();
    token.cancel();
    let error = control.checkpoint().unwrap_err().into_error(
        Stage::ReopenHeld,
        EffectSummary {
            attempted: 3,
            completed: 2,
            cleanup: CleanupDisposition::Complete,
            flags: DescriptorFlagEffect::Unknown,
        },
        ResourceCharges {
            parse: None,
            syscalls: 3,
            acquired: 2,
            peak: 2,
            read: None,
            #[cfg(feature = "process")]
            process: None,
        },
    );
    assert_eq!(
        (error.stage(), error.reason()),
        (Stage::ReopenHeld, Reason::Cancelled)
    );
    assert!(error.source().is_none());
    assert_eq!(
        (
            error.effect().attempted_operations(),
            error.effect().completed_operations(),
            error.charges().syscall_attempts(),
            error.charges().fd_acquisitions(),
            error.charges().peak_new_fds()
        ),
        (3, 2, 3, 2, 2),
        "metadata must not be refunded"
    );
    assert_eq!(
        (error.effect().cleanup(), error.effect().descriptor_flags()),
        (CleanupDisposition::Complete, DescriptorFlagEffect::Unknown)
    );
    assert_eq!(
        (
            error.effect().target_mappings_created(),
            error.effect().target_mappings_retired()
        ),
        (0, 0)
    );
    let error = ControlStop::Deadline.into_error(Stage::ValidateFile, effect(1, 1), charges(1));
    assert_eq!(error.reason(), Reason::Deadline);
    assert_eq!(error.effect().completed_operations(), 1);
}

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = root.join(format!(
            "scopebase-control-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path).unwrap();
        Self { path }
    }
    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

// Fixture-only operation owner. ValidateFile supplies an existing stage; this
// does not advertise a production write/read API. Failed io::Error stays primary.
fn fixture_write(
    file: &mut File,
    control: &OperationControl,
    after: impl FnOnce(),
) -> Result<usize, LinuxError> {
    control
        .checkpoint()
        .map_err(|s| s.into_error(Stage::ValidateFile, effect(0, 0), charges(0)))?;
    let result = file.write(b"!");
    after();
    let post = control.checkpoint();
    match result {
        Err(source) => Err(LinuxError {
            parse_line: None,
            stage: Stage::ValidateFile,
            reason: Reason::Unreadable,
            source: Some(source),
            effect: effect(1, 0),
            charges: charges(1),
            #[cfg(feature = "process")]
            process: None,
        }),
        Ok(n) => {
            post.map_err(|s| s.into_error(Stage::ValidateFile, effect(1, 1), charges(1)))?;
            Ok(n)
        }
    }
}
#[test]
fn failed_syscall_wins_concurrent_cancel() {
    let _fd_table = crate::FD_TABLE.lock().unwrap();
    let fixture = Fixture::new();
    let path = fixture.file("input");
    fs::write(&path, b"original").unwrap();
    let mut file = File::open(&path).unwrap();
    let token = CancelToken::new();
    let control = OperationControl::new(None, token.clone());
    let error = fixture_write(&mut file, &control, || token.cancel()).unwrap_err();
    assert_eq!(
        (error.stage(), error.reason()),
        (Stage::ValidateFile, Reason::Unreadable),
        "failed syscall stays primary"
    );
    assert_eq!(error.source().unwrap().raw_os_error(), Some(9));
    assert!(std::error::Error::source(&error).unwrap().is::<io::Error>());
    assert_eq!(
        (
            error.effect().attempted_operations(),
            error.effect().completed_operations(),
            error.charges().syscall_attempts()
        ),
        (1, 0, 1)
    );
    assert_eq!(fs::read(&path).unwrap(), b"original");
    let out = fixture.file("out");
    let mut writable = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&out)
        .unwrap();
    let token = CancelToken::new();
    let control = OperationControl::new(None, token.clone());
    let error = fixture_write(&mut writable, &control, || token.cancel()).unwrap_err();
    assert_eq!(error.reason(), Reason::Cancelled);
    assert_eq!(error.effect().completed_operations(), 1);
    assert_eq!(error.charges().syscall_attempts(), 1);
    assert_eq!(fs::read(out).unwrap(), b"!");
}
#[test]
fn expired_and_cancelled_prefers_cancel() {
    let start = Instant::now();
    let token = CancelToken::new();
    let control = control_at(start, Duration::ZERO, token.clone());
    assert_eq!(
        control.checkpoint_using(|| start),
        Err(ControlStop::Deadline)
    );
    token.cancel();
    let calls = AtomicUsize::new(0);
    assert_eq!(
        control.checkpoint_using(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            start
        }),
        Err(ControlStop::Cancelled)
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "cancellation must bypass clock"
    );
}
#[test]
fn clock_domains_do_not_convert() {
    let start = Instant::now();
    for origin in [start, start + Duration::from_secs(1000)] {
        let control = control_at(origin, Duration::from_secs(2), CancelToken::new());
        assert_eq!(
            control.checkpoint_using(|| origin + Duration::from_secs(1)),
            Ok(())
        );
        assert_eq!(
            control.checkpoint_using(|| origin),
            Ok(()),
            "preterminal time regression is a new observation"
        );
        assert_eq!(
            control.checkpoint_using(|| origin + Duration::from_secs(2)),
            Err(ControlStop::Deadline)
        );
    }
}
#[test]
fn clock_callback_panic_unwinds_without_effect() {
    struct Guard<'a>(&'a AtomicUsize);
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let dropped = AtomicUsize::new(0);
    let effects = AtomicUsize::new(0);
    let start = Instant::now();
    let control = control_at(start, Duration::from_secs(1), CancelToken::new());
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _guard = Guard(&dropped);
        control
            .checkpoint_using(|| panic!("clock fixture panic"))
            .unwrap();
        effects.fetch_add(1, Ordering::SeqCst);
    }))
    .is_err());
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    let clock = Mutex::new(start);
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _held = clock.lock().unwrap();
        panic!("poison fixture");
    }));
    assert!(clock.is_poisoned());
    assert!(catch_unwind(AssertUnwindSafe(|| {
        control.checkpoint_using(|| *clock.lock().unwrap()).unwrap();
        effects.fetch_add(1, Ordering::SeqCst);
    }))
    .is_err());
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert_eq!(control.checkpoint_using(|| start), Ok(()));
    assert_eq!(OperationControl::unlimited().checkpoint(), Ok(()));
}

#[derive(Default)]
struct ReadLedger {
    attempts: AtomicU64,
    completed: AtomicU64,
    bytes: AtomicU64,
    first_byte: AtomicU64,
}
// A test owner of one actual Read call, including pre/post-publication checks.
fn one_read(
    mut reader: impl Read,
    control: &OperationControl,
    ledger: &ReadLedger,
) -> Result<Vec<u8>, LinuxError> {
    control
        .checkpoint()
        .map_err(|s| s.into_error(Stage::ValidateFile, effect(0, 0), charges(0)))?;
    ledger.attempts.fetch_add(1, Ordering::SeqCst);
    let mut bytes = [0; 8];
    let result = reader.read(&mut bytes);
    let completed = if let Ok(n) = result {
        ledger.completed.fetch_add(1, Ordering::SeqCst);
        ledger.bytes.fetch_add(n as u64, Ordering::SeqCst);
        if n > 0 {
            ledger.first_byte.store(bytes[0] as u64, Ordering::SeqCst);
        }
        1
    } else {
        0
    };
    let post = control.checkpoint();
    match result {
        Err(source) => Err(LinuxError {
            parse_line: None,
            stage: Stage::ValidateFile,
            reason: Reason::Unreadable,
            source: Some(source),
            effect: effect(1, completed),
            charges: charges(1),
            #[cfg(feature = "process")]
            process: None,
        }),
        Ok(n) => {
            post.map_err(|s| s.into_error(Stage::ValidateFile, effect(1, completed), charges(1)))?;
            Ok(bytes[..n].to_vec())
        }
    }
}
struct EnteredRead {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}
impl Read for EnteredRead {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.entered.send(()).unwrap();
        self.release.recv().unwrap();
        out[..3].copy_from_slice(b"abc");
        Ok(3)
    }
}
fn assert_read_result(result: Result<Vec<u8>, LinuxError>, ledger: &ReadLedger, n: u64) {
    assert!(result.is_err(), "unpublished bytes must be discarded");
    let error = result.unwrap_err();
    assert_eq!(error.reason(), Reason::Cancelled);
    assert_eq!(
        (
            error.effect().attempted_operations(),
            error.effect().completed_operations(),
            error.charges().syscall_attempts()
        ),
        (1, 1, 1),
        "incurred read charges must survive cancellation"
    );
    assert_eq!(
        (
            ledger.attempts.load(Ordering::SeqCst),
            ledger.completed.load(Ordering::SeqCst),
            ledger.bytes.load(Ordering::SeqCst)
        ),
        (1, 1, n)
    );
}

fn watchdog(name: &str) -> bool {
    let key = "SCOPEBASE_CONTROL_CHILD";
    if std::env::var(key).ok().as_deref() == Some(name) {
        return false;
    }
    let fixture = Fixture::new();
    let stdout = fixture.file("stdout");
    let stderr = fixture.file("stderr");
    let out = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stdout)
        .unwrap();
    let err = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stderr)
        .unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env(key, name)
        .env("TMPDIR", &fixture.path)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .spawn()
        .unwrap();
    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > Duration::from_secs(5)
            || fs::metadata(&stdout).unwrap().len() > 1024 * 1024
            || fs::metadata(&stderr).unwrap().len() > 1024 * 1024
        {
            timed_out = true;
            child.kill().unwrap();
            break child.wait().unwrap();
        }
        thread::sleep(Duration::from_millis(5));
    };
    let out = fs::read_to_string(stdout).unwrap();
    let err = fs::read_to_string(stderr).unwrap();
    assert!(
        !timed_out,
        "owned watchdog failed; child killed and reaped: {out} {err}"
    );
    assert!(status.success(), "owned child failed: {out} {err}");
    assert!(
        out.contains("1 passed"),
        "exact child fixture must run: {out}"
    );
    true
}
#[test]
fn blocked_inner_read_is_not_claimed_interrupted() {
    let _fd_table = crate::FD_TABLE.lock().unwrap();
    if watchdog("control::tests::blocked_inner_read_is_not_claimed_interrupted") {
        return;
    }
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let ledger = Arc::new(ReadLedger::default());
    let work_ledger = ledger.clone();
    let token = CancelToken::new();
    let control = OperationControl::new(None, token.clone());
    let worker_control = control.clone();
    let worker = thread::spawn(move || {
        let result = one_read(
            EnteredRead {
                entered: entered_tx,
                release: release_rx,
            },
            &worker_control,
            &work_ledger,
        );
        done_tx.send(result).unwrap();
    });
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    token.cancel();
    let early = done_rx.recv_timeout(Duration::from_millis(30));
    let pending = matches!(early, Err(mpsc::RecvTimeoutError::Timeout));
    release_tx.send(()).unwrap();
    let result = match early {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            done_rx.recv_timeout(Duration::from_secs(1)).unwrap()
        }
        Err(error) => panic!("result channel lost: {error}"),
    };
    worker.join().unwrap();
    assert!(
        pending,
        "synchronous read must retain custody until release"
    );
    assert_read_result(result, &ledger, 3);
    assert_eq!(ledger.first_byte.load(Ordering::SeqCst), b'a' as u64);
    struct ForbiddenRead;
    impl Read for ForbiddenRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("no second read after cancellation");
        }
    }
    let next = one_read(ForbiddenRead, &control, &ledger).unwrap_err();
    assert_eq!(next.reason(), Reason::Cancelled);
    assert_eq!(ledger.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        one_read(
            io::Cursor::new(b"abc"),
            &OperationControl::unlimited(),
            &ReadLedger::default()
        )
        .unwrap(),
        b"abc"
    );
}
#[test]
fn real_stream_read_control_boundary() {
    let _fd_table = crate::FD_TABLE.lock().unwrap();
    if watchdog("control::tests::real_stream_read_control_boundary") {
        return;
    }
    let fixture = Fixture::new();
    let file_path = fixture.file("retained");
    fs::write(&file_path, b"owner").unwrap();
    let retained = File::open(&file_path).unwrap();
    let ino = retained.metadata().unwrap().ino();
    let (stream, mut writer) = UnixStream::pair().unwrap();
    assert_ne!(
        std::os::fd::AsRawFd::as_raw_fd(&stream),
        std::os::fd::AsRawFd::as_raw_fd(&writer)
    );
    let (before_tx, before_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let token = CancelToken::new();
    let control = OperationControl::new(None, token.clone());
    let ledger = Arc::new(ReadLedger::default());
    let work_ledger = ledger.clone();
    struct PreRead {
        stream: UnixStream,
        before: mpsc::Sender<()>,
    }
    impl Read for PreRead {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.before.send(()).unwrap();
            self.stream.read(out)
        }
    }
    let worker = thread::spawn(move || {
        done_tx
            .send(one_read(
                PreRead {
                    stream,
                    before: before_tx,
                },
                &control,
                &work_ledger,
            ))
            .unwrap();
    });
    before_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let (ack_tx, ack_rx) = mpsc::channel();
    thread::spawn(move || {
        token.cancel();
        ack_tx.send(()).unwrap();
    })
    .join()
    .unwrap();
    ack_rx.recv().unwrap();
    let early = done_rx.recv_timeout(Duration::from_millis(30));
    let pending = matches!(early, Err(mpsc::RecvTimeoutError::Timeout));
    writer.write_all(b"z").unwrap();
    let result = match early {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            done_rx.recv_timeout(Duration::from_secs(1)).unwrap()
        }
        Err(error) => panic!("result channel lost: {error}"),
    };
    worker.join().unwrap();
    assert!(
        pending,
        "real stream result remains pending until parent release"
    );
    assert_read_result(result, &ledger, 1);
    assert_eq!(ledger.first_byte.load(Ordering::SeqCst), b'z' as u64);
    assert_eq!(retained.metadata().unwrap().ino(), ino);
    assert_eq!(fs::read(file_path).unwrap(), b"owner");
}
#[test]
fn deadline_after_read_before_publication_keeps_charge() {
    let start = Instant::now();
    let control = control_at(start, Duration::from_secs(1), CancelToken::new());
    let calls = AtomicUsize::new(0);
    control.checkpoint_using(|| start).unwrap();
    let mut reader = io::Cursor::new(b"abc");
    let mut data = [0; 3];
    calls.fetch_add(1, Ordering::SeqCst);
    assert_eq!(reader.read(&mut data).unwrap(), 3);
    let error = control
        .checkpoint_using(|| start + Duration::from_secs(1))
        .unwrap_err()
        .into_error(Stage::ValidateFile, effect(1, 1), charges(1));
    assert_eq!(error.reason(), Reason::Deadline);
    assert_eq!(error.effect().completed_operations(), 1);
    assert_eq!(error.charges().syscall_attempts(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
