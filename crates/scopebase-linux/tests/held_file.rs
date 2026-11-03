// SPDX-License-Identifier: Apache-2.0
// Adapted regression scenarios from the selected P/O sources; see README.
use rustix::fs::{self as sys, Mode, OFlags};
use scopebase_linux::{
    error::{Reason, Stage},
    file::{HeldFile, ProcFdResolver, SymlinkPolicy},
};
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::{AsFd, AsRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileExt, MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
static SEQ: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "lx02-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.0.join(name);
        fs::write(&p, bytes).unwrap();
        p
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // S211: never panic in drop — a removal failure during
        // assertion unwinding must not abort the test process.
        let _ = fs::remove_dir_all(&self.0);
    }
}

// Z4: probe the REAL capability behind the wedge instead of
// branching on uid — uid 0 without DAC override must take the
// stands-wedged branch. Mirrors the test's gated op (removing a
// 0555 dir holding a file) on a scratch twin.
fn probe_can_remove_readonly_wedge() -> bool {
    use std::sync::atomic::Ordering;
    let p = std::env::temp_dir().join(format!(
        "held-file-probe-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&p).unwrap();
    fs::write(p.join("payload.bin"), b"x").unwrap();
    std::fs::set_permissions(
        &p,
        std::os::unix::fs::PermissionsExt::from_mode(0o555),
    )
    .unwrap();
    let removed = fs::remove_dir_all(&p).is_ok() && !p.exists();
    if p.exists() {
        std::fs::set_permissions(
            &p,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        fs::remove_dir_all(&p).unwrap();
    }
    removed
}

// S211: guard drops must not panic — a removal failure during
// assertion unwinding must not turn a reportable failure into a
// process abort (matches the sibling `let _ = ...` guards).
#[test]
fn fixture_drop_tolerates_unremovable_scratch() {
    use std::sync::Mutex;
    let leaked = Mutex::new(None);
    let outcome = std::panic::catch_unwind(|| {
        let fixture = Fixture::new();
        fixture.write("payload.bin", b"0123456789");
        // Deny removal: a read-only dir refuses entry unlinking.
        std::fs::set_permissions(
            &fixture.0,
            std::os::unix::fs::PermissionsExt::from_mode(0o555),
        )
        .unwrap();
        *leaked.lock().unwrap() = Some(fixture.0.clone());
        panic!("forced S211 unwind");
    });
    assert!(outcome.is_err(), "original failure still reports");
    // Z4: the expected branch comes from a capability probe, not
    // the uid. An override run retires the wedge during unwinding
    // (Drop still must not panic); a restricted run leaves it
    // standing for manual restore. A behavior/probe mismatch fails
    // loudly either way.
    let override_present = probe_can_remove_readonly_wedge();
    let saved = leaked.lock().unwrap().clone();
    if let Some(path) = saved {
        match (override_present, path.exists()) {
            (true, false) => {}
            (false, true) => {
                std::fs::set_permissions(
                    &path,
                    std::os::unix::fs::PermissionsExt::from_mode(0o755),
                )
                .unwrap();
                std::fs::remove_dir_all(&path).unwrap();
            }
            (true, true) => panic!("wedge stands despite override capability"),
            (false, false) => panic!("wedge removed without override capability"),
        }
    }
}
fn read_held(held: &HeldFile) -> Vec<u8> {
    let mut bytes = vec![0; held.stat().unwrap().len() as usize];
    let duplicate = File::from(rustix::io::dup(held.as_fd()).unwrap());
    duplicate.read_exact_at(&mut bytes, 0).unwrap();
    bytes
}
fn assert_truth(held: &HeldFile, file: &File) {
    let s = held.stat().unwrap();
    let m = file.metadata().unwrap();
    assert_eq!(
        (
            s.key().device_raw(),
            s.key().inode(),
            s.len(),
            s.mtime(),
            s.ctime()
        ),
        (
            m.dev(),
            m.ino(),
            m.len(),
            (m.mtime(), m.mtime_nsec() as u32),
            (m.ctime(), m.ctime_nsec() as u32)
        )
    );
}
#[test]
fn stat_tracks_held_descriptor() {
    let f = Fixture::new();
    let a = f.write("a", b"AAA");
    let b = f.write("b", b"BBBBB");
    let oracle = File::open(&a).unwrap();
    let resolver = ProcFdResolver::open_self().unwrap();
    let held = HeldFile::open(&a, &resolver, SymlinkPolicy::Follow).unwrap();
    fs::rename(&b, &a).unwrap();
    assert_truth(&held, &oracle);
    assert_eq!(read_held(&held), b"AAA");
    oracle
        .set_permissions(fs::Permissions::from(
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        ))
        .unwrap();
    OpenOptions::new()
        .write(true)
        .open(format!("/proc/self/fd/{}", oracle.as_raw_fd()))
        .unwrap()
        .set_len(1)
        .unwrap();
    assert_truth(&held, &oracle);
    assert_eq!(held.stat().unwrap().len(), 1);
}
#[test]
fn retained_owner_and_same_bytes_different_inode() {
    let f = Fixture::new();
    let a = f.write("a", b"same bytes");
    let b = f.write("b", b"same bytes");
    let resolver = ProcFdResolver::open_self().unwrap();
    let original = File::open(&a).unwrap();
    let held = Arc::new(HeldFile::open(&a, &resolver, SymlinkPolicy::Follow).unwrap());
    let other = HeldFile::open(&b, &resolver, SymlinkPolicy::Follow).unwrap();
    assert_ne!(held.stat().unwrap().key(), other.stat().unwrap().key());
    fs::remove_file(&a).unwrap();
    let twin = Arc::clone(&held);
    drop(held);
    assert_truth(&twin, &original);
    assert_eq!(read_held(&twin), b"same bytes");
}
#[test]
fn rejects_fifo_before_read_open() {
    let f = Fixture::new();
    let fifo = f.0.join("fifo");
    sys::mknodat(
        sys::CWD,
        &fifo,
        sys::FileType::Fifo,
        Mode::RUSR | Mode::WUSR,
        0,
    )
    .unwrap();
    let r = ProcFdResolver::open_self().unwrap();
    let e = HeldFile::open(&fifo, &r, SymlinkPolicy::Follow).unwrap_err();
    assert_eq!(
        (e.stage(), e.reason()),
        (Stage::ValidateFile, Reason::NonRegular)
    );
    assert_eq!(e.charges().syscall_attempts(), 2);
    assert_eq!(e.charges().fd_acquisitions(), 1);
}
#[test]
fn reject_final_differs_from_follow() {
    let f = Fixture::new();
    let a = f.write("a", b"A");
    let link = f.0.join("link");
    std::os::unix::fs::symlink(&a, &link).unwrap();
    let r = ProcFdResolver::open_self().unwrap();
    assert_eq!(
        read_held(&HeldFile::open(&link, &r, SymlinkPolicy::Follow).unwrap()),
        b"A"
    );
    assert_eq!(
        HeldFile::open(&link, &r, SymlinkPolicy::RejectFinal)
            .unwrap_err()
            .reason(),
        Reason::NonRegular
    );
    let dangling = f.0.join("dangling");
    std::os::unix::fs::symlink(f.0.join("absent"), &dangling).unwrap();
    let error = HeldFile::open(&dangling, &r, SymlinkPolicy::Follow).unwrap_err();
    assert_eq!(
        (
            error.stage(),
            error.reason(),
            error.source().unwrap().raw_os_error()
        ),
        (Stage::AcquirePath, Reason::Disappeared, Some(2))
    );
    let error = HeldFile::open(&dangling, &r, SymlinkPolicy::RejectFinal).unwrap_err();
    assert_eq!(
        (error.stage(), error.reason()),
        (Stage::ValidateFile, Reason::NonRegular)
    );
    assert!(error.source().is_none());
    let intermediate = f.0.join("dir-link");
    std::os::unix::fs::symlink(&f.0, &intermediate).unwrap();
    assert!(HeldFile::open(&intermediate.join("a"), &r, SymlinkPolicy::RejectFinal).is_ok());
}
#[test]
fn adopt_error_returns_original_file() {
    let f = Fixture::new();
    let p = f.write("a", b"A");
    for flags in [OFlags::PATH, OFlags::WRONLY] {
        let file = File::from(sys::open(&p, flags | OFlags::CLOEXEC, Mode::empty()).unwrap());
        let fd = file.as_raw_fd();
        let truth = file.metadata().unwrap();
        let e = HeldFile::from_file(file).unwrap_err();
        assert_eq!(e.file.as_raw_fd(), fd);
        assert_eq!(e.file.metadata().unwrap().ino(), truth.ino());
        assert_eq!(e.error.reason(), Reason::Unreadable);
    }
    let directory = File::open(&f.0).unwrap();
    let fd = directory.as_raw_fd();
    let e = HeldFile::from_file(directory).unwrap_err();
    assert_eq!(e.file.as_raw_fd(), fd);
    assert_eq!(e.error.reason(), Reason::NonRegular);
}
#[test]
fn adopt_preserves_fd_cursor_status_and_duplicate_descriptor_flags() {
    use std::io::{Seek, SeekFrom};
    let f = Fixture::new();
    let p = f.write("a", b"abcdef");
    for write in [false, true] {
        let mut file = OpenOptions::new()
            .read(true)
            .write(write)
            .custom_flags(OFlags::NONBLOCK.bits() as i32)
            .open(&p)
            .unwrap();
        file.seek(SeekFrom::Start(3)).unwrap();
        let alias = file.try_clone().unwrap();
        let fd = file.as_raw_fd();
        let status = sys::fcntl_getfl(&file).unwrap();
        rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::empty()).unwrap();
        let h = HeldFile::from_file(file).unwrap();
        assert_eq!(h.as_fd().as_raw_fd(), fd);
        assert_eq!(sys::fcntl_getfl(h.as_fd()).unwrap(), status);
        assert_eq!(sys::seek(&alias, sys::SeekFrom::Current(0)).unwrap(), 3);
        assert!(rustix::io::fcntl_getfd(h.as_fd())
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
        assert!(rustix::io::fcntl_getfd(&alias)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
        rustix::io::fcntl_setfd(&alias, rustix::io::FdFlags::empty()).unwrap();
        assert!(rustix::io::fcntl_getfd(h.as_fd())
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
    }
}
#[test]
fn missing_input_returns_original_errno() {
    let f = Fixture::new();
    let r = ProcFdResolver::open_self().unwrap();
    let e = HeldFile::open(&f.0.join("absent"), &r, SymlinkPolicy::Follow).unwrap_err();
    assert_eq!(
        (e.stage(), e.reason()),
        (Stage::AcquirePath, Reason::Disappeared)
    );
    assert_eq!(e.source().unwrap().raw_os_error(), Some(2));
    assert_eq!(e.charges().syscall_attempts(), 1);
    let through_trait = std::error::Error::source(&e)
        .unwrap()
        .downcast_ref::<std::io::Error>()
        .unwrap();
    assert!(std::ptr::eq(e.source().unwrap(), through_trait));
}
#[test]
fn raw_path_admission_and_non_utf8() {
    let r = ProcFdResolver::open_self().unwrap();
    for bytes in [vec![], vec![b'a'; 4096], vec![0], vec![b'a', 0, b'b']] {
        let e = HeldFile::open(
            Path::new(std::ffi::OsStr::from_bytes(&bytes)),
            &r,
            SymlinkPolicy::Follow,
        )
        .unwrap_err();
        assert_eq!(e.reason(), Reason::InvalidInput);
        assert_eq!(e.charges().syscall_attempts(), 0);
        assert_eq!(e.effect().attempted_operations(), 0);
    }
    for size in [1, 4095] {
        let raw = vec![b'a'; size];
        let e = HeldFile::open(
            Path::new(std::ffi::OsStr::from_bytes(&raw)),
            &r,
            SymlinkPolicy::Follow,
        )
        .unwrap_err();
        assert_eq!(e.charges().syscall_attempts(), 1);
    }
    let f = Fixture::new();
    let p = f.0.join(std::ffi::OsStr::from_bytes(b"nonutf8-\xff"));
    fs::write(&p, b"payload").unwrap();
    assert_eq!(
        read_held(&HeldFile::open(&p, &r, SymlinkPolicy::Follow).unwrap()),
        b"payload"
    );
}
#[test]
fn debug_escapes_without_payload() {
    let f = Fixture::new();
    let p = f.write("CANARY-\n\x1b", b"PAYLOAD-CANARY");
    let r = ProcFdResolver::open_self().unwrap();
    let h = HeldFile::open(&p, &r, SymlinkPolicy::Follow).unwrap();
    let s = h.stat().unwrap();
    let e = HeldFile::open(&f.0.join("CANARY-absent"), &r, SymlinkPolicy::Follow).unwrap_err();
    for text in [
        format!("{h:?}"),
        format!("{h:#?}"),
        format!("{r:?}"),
        format!("{s:?}"),
        format!("{:?}", s.key()),
        format!("{e}"),
        format!("{e:#?}"),
        format!("{:?}", e.effect()),
        format!("{:?}", e.charges()),
    ] {
        assert!(text.is_ascii() && text.len() <= 256);
        assert!(
            text.bytes().all(|b| (0x20..=0x7e).contains(&b)),
            "diagnostic must contain only printable bytes"
        );
        assert!(!text.contains("CANARY"));
    }
}
#[test]
fn resolver_shared_thread_positive() {
    let r = Arc::new(ProcFdResolver::open_self().unwrap());
    let f = Fixture::new();
    let p = f.write("a", b"A");
    let h = std::thread::spawn(move || HeldFile::open(&p, &r, SymlinkPolicy::Follow).unwrap())
        .join()
        .unwrap();
    assert_eq!(read_held(&h), b"A");
}
#[test]
fn cloexec_survives_exec_fixture() {
    let f = Fixture::new();
    let p = f.write("a", b"A");
    let r = ProcFdResolver::open_self().unwrap();
    let h = HeldFile::open(&p, &r, SymlinkPolicy::Follow).unwrap();
    let canary = sys::open(&p, OFlags::RDONLY, Mode::empty()).unwrap();
    let m = fs::metadata(&p).unwrap();
    let exe = std::env::var_os("SCOPEBASE_EXEC_PROBE")
        .map(PathBuf::from)
        .unwrap_or(std::env::current_exe().unwrap());
    let mut command = std::process::Command::new(exe);
    if std::env::var_os("SCOPEBASE_EXEC_PROBE").is_none() {
        command.args(["--exact", "exec_probe_child", "--nocapture"]);
    }
    let out = command
        .env(
            "LX02_EXEC",
            format!(
                "{} {} {} {}",
                h.as_fd().as_raw_fd(),
                canary.as_raw_fd(),
                m.dev(),
                m.ino()
            ),
        )
        .output()
        .unwrap();
    assert!(out.status.success(), "{:?}", out);
    if std::env::var_os("SCOPEBASE_EXEC_PROBE").is_some() {
        assert!(
            out.stdout.is_empty() && out.stderr.is_empty(),
            "standalone helper must be silent"
        );
    }
}
#[test]
fn exec_probe_child() {
    if let Ok(value) = std::env::var("LX02_EXEC") {
        fd_probe::exec_check(&value);
    }
}

#[allow(dead_code)]
#[path = "support/fd_probe.rs"]
mod fd_probe;
#[test]
fn final_drop_releases_original_fd_with_live_alias() {
    let f = Fixture::new();
    let p = f.write("a", b"A");
    let helper = std::env::var_os("SCOPEBASE_EXEC_PROBE");
    let exe = helper
        .clone()
        .map(PathBuf::from)
        .unwrap_or(std::env::current_exe().unwrap());
    let mut cmd = std::process::Command::new(exe);
    if helper.is_none() {
        cmd.args(["--exact", "retirement_probe_child", "--nocapture"]);
    }
    let out = cmd.env("LX02_RETIRE", &p).output().unwrap();
    assert!(out.status.success(), "{:?}", out);
    if std::env::var_os("SCOPEBASE_EXEC_PROBE").is_some() {
        assert!(
            out.stdout.is_empty() && out.stderr.is_empty(),
            "standalone helper must be silent"
        );
    }
}
#[test]
fn retirement_probe_child() {
    if let Some(p) = std::env::var_os("LX02_RETIRE") {
        fd_probe::retirement_check(Path::new(&p));
    }
}
#[test]
fn stat_preserves_pre_epoch_seconds() {
    let f = Fixture::new();
    let p = f.write("a", b"A");
    let original = OpenOptions::new().read(true).write(true).open(&p).unwrap();
    original
        .set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::UNIX_EPOCH - std::time::Duration::from_secs(1)),
        )
        .unwrap();
    let h = HeldFile::from_file(original.try_clone().unwrap()).unwrap();
    assert_eq!(h.stat().unwrap().mtime(), (-1, 0));
    assert_truth(&h, &original);
}

#[test]
fn empty_and_nonempty_regular_open_and_adopt() {
    let fixture = Fixture::new();
    let resolver = ProcFdResolver::open_self().unwrap();
    for (name, payload) in [("empty", b"".as_slice()), ("nonempty", b"A".as_slice())] {
        let path = fixture.write(name, payload);
        let original = File::open(&path).unwrap();
        let opened = HeldFile::open(&path, &resolver, SymlinkPolicy::Follow).unwrap();
        assert_truth(&opened, &original);
        assert_eq!(read_held(&opened), payload);
        let adopted = HeldFile::from_file(original.try_clone().unwrap()).unwrap();
        assert_truth(&adopted, &original);
        assert_eq!(read_held(&adopted), payload);
    }
}
#[test]
fn fifo_adoption_and_owned_directory_socket_refusals() {
    use std::os::unix::net::UnixListener;
    let fixture = Fixture::new();
    let fifo = fixture.0.join("fifo");
    sys::mknodat(
        sys::CWD,
        &fifo,
        sys::FileType::Fifo,
        Mode::RUSR | Mode::WUSR,
        0,
    )
    .unwrap();
    let original = File::from(
        sys::open(
            &fifo,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap(),
    );
    let fd = original.as_raw_fd();
    let truth = original.metadata().unwrap();
    let status = sys::fcntl_getfl(&original).unwrap();
    let refusal = HeldFile::from_file(original).unwrap_err();
    assert_eq!(refusal.file.as_raw_fd(), fd);
    assert_eq!(
        (
            refusal.file.metadata().unwrap().dev(),
            refusal.file.metadata().unwrap().ino()
        ),
        (truth.dev(), truth.ino())
    );
    assert_eq!(sys::fcntl_getfl(&refusal.file).unwrap(), status);
    assert_eq!(
        (refusal.error.stage(), refusal.error.reason()),
        (Stage::ValidateFile, Reason::NonRegular)
    );
    assert!(refusal.error.source().is_none());
    let socket = fixture.0.join("socket");
    // Unix socket address limits are smaller than this job's TMPDIR. Bind
    // through our own retained directory, without changing process cwd.
    let socket_directory = File::open(&fixture.0).unwrap();
    let socket_alias = format!("/proc/self/fd/{}/socket", socket_directory.as_raw_fd());
    let _listener = UnixListener::bind(&socket_alias).unwrap();
    let resolver = ProcFdResolver::open_self().unwrap();
    for path in [&fixture.0, &socket] {
        let refusal = HeldFile::open(path, &resolver, SymlinkPolicy::Follow).unwrap_err();
        assert_eq!(
            (refusal.stage(), refusal.reason()),
            (Stage::ValidateFile, Reason::NonRegular)
        );
        assert_eq!(refusal.charges().syscall_attempts(), 2);
        assert_eq!(refusal.charges().fd_acquisitions(), 1);
        assert!(refusal.source().is_none());
    }
}
