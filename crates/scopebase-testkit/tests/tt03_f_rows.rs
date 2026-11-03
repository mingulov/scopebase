// SPDX-License-Identifier: Apache-2.0
//! TT03 F-row closure increment: seccomp strict-denial helper mechanisms,
//! the restricted-credential live row, and TT04 realm-lease admission.
//!
//! Binding authority: `docs/superpowers/specs/2026-10-22-scopebase-tt03-linux-fixture.md`
//! plus packet `docs/provenance/tt03-packet-20261023.md` §12.
//!
//! Honest scope of this file (see packet for the full row ledger):
//! - `f_seccomp_*_strict_denial_mechanism`: LIVE mechanism populations for
//!   F seccomp_eperm/enosys rows (fresh confined helper, pre-filter pidfd
//!   retained, exact reached errno, readable stat). The ROWS stay open:
//!   they additionally require the LX08 actual-consumer helper with
//!   CreateEpoch/OpenPidfd/CreatorPidfd refusal precedence (LX08 PLANNED).
//! - `f_restricted_credential_dumpability_is_real`: CLOSES F
//!   restricted_credential_is_real with a live dumpability recipe (same
//!   target both phases, actual credentials, denied raw open stage).
//! - `f_tt04_realm_leases_admitted`: binds the TT04 target-side realm
//!   leases for the nested/view F rows (admission only, not row closure).
//!   SKIPs with an exact reason when `TT04_MANIFEST` is absent.
//! - `f_mount_view_change_and_retained_root`: CLOSES F
//!   mount_view_change_and_retained_root with four phased target-ns
//!   populations on one rootless userns+mountns target (child
//!   overmount + unmount churn, symlink swap, procfs-root replacement
//!   via marker tmpfs, chroot filesystem-root replacement), each with
//!   retained-vs-fresh oracles, one-deadline handshakes, and a scoped
//!   no-propagation check. Plus the `handshake_read_timeout_and_eof`
//!   mechanism control (timeout/EOF/dribble-deadline).
use scopebase_testkit::fixture::linux::parse_stat_comm_state_starttime;
use scopebase_testkit::fixture::linux::seccomp::{install_deny_one, DenyAction};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn seccomp_probe_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_scopebase-tt03-seccomp-probe"))
}

fn parse_report(stdout: &str) -> BTreeMap<String, String> {
    stdout
        .split_whitespace()
        .filter_map(|field| {
            field
                .split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

/// S225: post-fork pipe helpers. The child side must never panic —
/// only async-signal-safe syscalls on stack memory, EINTR retried,
/// every other shortfall reported as `false` so the caller can
/// `_exit(13)`. The parent side keeps asserting (its own helpers in
/// the dumpability test), where a panic is a proper red test.
unsafe fn child_pipe_read_exact(fd: libc::c_int, mut buf: &mut [u8]) -> bool {
    while !buf.is_empty() {
        let n = libc::read(fd, buf.as_mut_ptr().cast(), buf.len());
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if n <= 0 {
            return false;
        }
        buf = &mut buf[n as usize..];
    }
    true
}

unsafe fn child_pipe_write_all(fd: libc::c_int, mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        let n = libc::write(fd, buf.as_ptr().cast(), buf.len());
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if n <= 0 {
            return false;
        }
        buf = &buf[n as usize..];
    }
    true
}

/// Fresh confined-helper population: pre-filter pidfd_open succeeds, the
/// deny-one filter installs, post-filter pidfd_open reaches exactly
/// `expect_errno`, the retained pre-filter pidfd stays usable and stat
/// stays readable. The target sleeper stays live throughout.
/// A spawned sleeper that is always killed and reaped, even when an
/// assertion panics mid-case.
#[cfg(target_arch = "x86_64")]
struct SleepTarget(std::process::Child);
#[cfg(target_arch = "x86_64")]
impl Drop for SleepTarget {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

#[cfg(target_arch = "x86_64")]
fn run_seccomp_case(mode: &str, expect_errno: i32) {
    let mut target = SleepTarget(
        std::process::Command::new("sleep")
            .arg("60")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn sleep target"),
    );
    let pid = target.0.id() as libc::pid_t;
    let out = std::process::Command::new(seccomp_probe_bin())
        .arg(mode)
        .arg(pid.to_string())
        .output()
        .expect("spawn seccomp probe");
    assert!(
        target.0.try_wait().expect("poll target").is_none(),
        "confined probe must not disturb the live target"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        if stderr.contains("TT03-F-INSTALL-UNAVAILABLE") {
            println!("TT03-F-SKIP f_seccomp_{mode}: {stderr}");
            return;
        }
        panic!(
            "seccomp probe failed ({mode}): status {:?}: {stderr}",
            out.status
        );
    }
    let report = parse_report(&String::from_utf8_lossy(&out.stdout));
    assert_eq!(
        report.get("mode").map(String::as_str),
        Some(mode),
        "probe mode echo"
    );
    let pre_fd: i64 = report
        .get("pre_fd")
        .expect("pre_fd")
        .parse()
        .expect("pre_fd int");
    assert!(
        pre_fd >= 0,
        "pre-filter pidfd_open must succeed: {report:?}"
    );
    assert_eq!(report.get("pre_errno").map(String::as_str), Some("0"));
    assert_eq!(report.get("prefix_fstat").map(String::as_str), Some("ok"));
    assert_eq!(
        report.get("install").map(String::as_str),
        Some("ok"),
        "{report:?}"
    );
    assert_eq!(
        report.get("nnp").map(String::as_str),
        Some("1"),
        "{report:?}"
    );
    assert_eq!(
        report.get("post_errno").map(String::as_str),
        Some(expect_errno.to_string()).as_deref(),
        "post-filter pidfd_open must reach errno {expect_errno}: {report:?}"
    );
    assert_eq!(
        report.get("retained_fstat").map(String::as_str),
        Some("ok"),
        "{report:?}"
    );
    assert_eq!(
        report.get("stat_ok").map(String::as_str),
        Some("1"),
        "{report:?}"
    );
    target.0.kill().expect("kill target");
    let status = target.0.wait().expect("reap target");
    assert!(!status.success(), "sleep target must die by signal");
}

#[cfg(target_arch = "x86_64")]
#[test]
fn f_seccomp_eperm_strict_denial_mechanism() {
    run_seccomp_case("eperm", libc::EPERM);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn f_seccomp_enosys_strict_denial_mechanism() {
    run_seccomp_case("enosys", libc::ENOSYS);
}

#[test]
fn f_seccomp_unit_shapes() {
    // The deny-one filter is x86_64-only; elsewhere install refuses
    // without touching process state. On x86_64 this test only pins
    // the public error shape via a bogus action path is unavailable,
    // so it asserts the action mapping round-trips through Debug.
    // S226: the rendering operators read in refusal logs is asserted,
    // not discarded — a swapped/renamed variant fails here.
    assert_eq!(
        format!("{:?} {:?}", DenyAction::Eperm, DenyAction::Enosys),
        "Eperm Enosys"
    );
    let _ = install_deny_one;
}

/// F restricted_credential_is_real, live dumpability recipe: the same
/// target PID serves both phases. Dumpable phase: same-credential
/// observer opens /proc/PID/mem. Non-dumpable phase (target-settled via
/// PR_SET/GET_DUMPABLE): the same open is denied EACCES at the open
/// stage. Observer/target Uid/Gid rows must match exactly, proving the
/// denial is purely credential-state, not identity.
#[test]
fn f_restricted_credential_dumpability_is_real() {
    unsafe fn read_exact(fd: libc::c_int, mut buf: &mut [u8]) {
        while !buf.is_empty() {
            let n = libc::read(fd, buf.as_mut_ptr().cast(), buf.len());
            assert!(n > 0, "pipe read must deliver");
            buf = &mut buf[n as usize..];
        }
    }
    unsafe fn write_all(fd: libc::c_int, mut buf: &[u8]) {
        while !buf.is_empty() {
            let n = libc::write(fd, buf.as_ptr().cast(), buf.len());
            assert!(n > 0, "pipe write must deliver");
            buf = &buf[n as usize..];
        }
    }

    /// SIGKILLs and exactly reaps the fork child unless disarmed, so a
    /// failed assertion can never orphan a pipe-holding sleeper.
    struct ChildGuard {
        pid: libc::pid_t,
        fds: [libc::c_int; 2],
        done: bool,
    }
    impl ChildGuard {
        fn disarm(&mut self) {
            self.done = true;
        }
    }
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if self.done {
                return;
            }
            unsafe {
                // The child naps in killable nanosleep; SIGKILL always
                // lands, so the blocking reap below cannot hang.
                libc::kill(self.pid, libc::SIGKILL);
                let mut status_code = 0;
                libc::waitpid(self.pid, &mut status_code, 0);
                for fd in self.fds {
                    libc::close(fd);
                }
            }
        }
    }

    let mut ready = [0 as libc::c_int; 2];
    let mut cmd = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { libc::pipe(cmd.as_mut_ptr()) }, 0);
    // SAFETY: the child performs only async-signal-safe syscalls
    // (read/write/prctl/nanosleep/close/_exit) on stack memory; it never
    // allocates, locks, touches std I/O, panics, or returns into test
    // code. Pipe shortfalls `_exit(13)`, protocol mismatch `_exit(14)`.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork must succeed");
    if pid == 0 {
        // S225 exit contract: 11/12 prctl (below), 13 pipe IO, 14
        // protocol. The child never panics: every shortfall `_exit`s.
        unsafe {
            libc::close(ready[0]);
            libc::close(cmd[1]);
            if !child_pipe_write_all(ready[1], b"R") {
                libc::_exit(13);
            }
            let mut one = [0u8; 1];
            if !child_pipe_read_exact(cmd[0], &mut one) {
                libc::_exit(13);
            }
            if one != *b"D" {
                libc::_exit(14);
            }
            if libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) != 0 {
                libc::_exit(11);
            }
            // PORT P `p11scope/crates/discover/src/main.rs`
            // @`7f8ca02bf926a5cbd4345180bbe7367c4f1abdf4` lines 126-137
            // (`set_dumpable_zero`: set then GET-verify zero, never
            // assumed). Tracked at that commit in frozen history
            // r001. Grant: OWNER-2026-10-23.
            if libc::prctl(libc::PR_GET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) != 0 {
                libc::_exit(12);
            }
            if !child_pipe_write_all(ready[1], b"A") {
                libc::_exit(13);
            }
            let nap = libc::timespec {
                tv_sec: 3600,
                tv_nsec: 0,
            };
            loop {
                libc::nanosleep(&nap, std::ptr::null_mut());
            }
        }
    }
    unsafe {
        libc::close(ready[1]);
        libc::close(cmd[0]);
    }
    let mut guard = ChildGuard {
        pid,
        fds: [ready[0], cmd[1]],
        done: false,
    };
    let mut byte = [0u8; 1];
    unsafe { read_exact(ready[0], &mut byte) };
    assert_eq!(byte, [b'R'], "target must report ready");

    let observer = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    };
    // Positive phase: dumpable target, same-credential observer.
    let positive = std::fs::File::open(format!("/proc/{pid}/mem"));
    assert!(
        positive.is_ok(),
        "dumpable-phase mem open must succeed: {positive:?}"
    );
    drop(positive);

    unsafe { write_all(cmd[1], b"D") };
    unsafe { read_exact(ready[0], &mut byte) };
    assert_eq!(
        byte,
        [b'A'],
        "target must settle non-dumpable (PR_SET+GET verified)"
    );

    // Negative phase: same target, same observer, denied at open.
    match std::fs::File::open(format!("/proc/{pid}/mem")) {
        Err(e) if e.raw_os_error() == Some(libc::EACCES) => {}
        other => panic!("non-dumpable-phase mem open must fail EACCES, got {other:?}"),
    }

    // Actual credentials: observer and target rows must match exactly
    // (parsed as numbers: status rows are tab-separated quadruples).
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("target status");
    let row = |key: &str| {
        status
            .lines()
            .find_map(|l| {
                l.strip_prefix(key).map(|v| {
                    v.split_whitespace()
                        .map(|n| n.parse::<u32>().expect("id number"))
                        .collect::<Vec<_>>()
                })
            })
            .unwrap_or_else(|| panic!("{key} row present"))
    };
    assert_eq!(
        row("Uid:"),
        vec![observer.0, observer.1, observer.0, observer.1]
    );
    assert_eq!(
        row("Gid:"),
        vec![observer.2, observer.3, observer.2, observer.3]
    );

    unsafe {
        assert_eq!(libc::kill(pid, libc::SIGKILL), 0);
        let mut status_code = 0;
        let reaped = libc::waitpid(pid, &mut status_code, 0);
        assert_eq!(reaped, pid, "exact child reap");
        assert!(libc::WIFSIGNALED(status_code), "target must die by signal");
        libc::close(ready[0]);
        libc::close(cmd[1]);
    }
    guard.disarm();
}

/// TT04 realm-lease admission for the nested/view F rows: the admitted
/// pidns sleeper really sits in a nested PID namespace (multi-entry
/// NSpid, foreign pidns inode), the same live process (starttime
/// match, no PID reuse), and the foreign-mount sleeper really serves a
/// foreign view (target-root bytes differ from observer bytes).
/// Admission only: the nested/mount ROWS stay open (no admitted adapter
/// realm, no LX08 adapter/epoch/view tracker).
#[test]
fn f_tt04_realm_leases_admitted() {
    let Some(path) = std::env::var("TT04_MANIFEST").ok() else {
        println!(
            "TT03-F-SKIP f_tt04_realm_leases_admitted: missing TT04_MANIFEST \
             (run provision_fs.py create --privileged)"
        );
        return;
    };
    let text = std::fs::read_to_string(&path).expect("manifest readable");
    let value: serde_json::Value = serde_json::from_str(&text).expect("manifest parses");
    assert_eq!(
        value["schema"].as_str(),
        Some("tt04-fs-manifest-v1"),
        "TT03-F-ADMIT-REFUSED: schema mismatch"
    );
    let run_root = value["run_root"].as_str().expect("run_root").to_string();
    for prefix in ["/tmp/", "/var/tmp/", "/dev/shm/"] {
        if run_root.starts_with(prefix) {
            break;
        }
    }
    assert!(
        ["/tmp/", "/var/tmp/", "/dev/shm/"]
            .iter()
            .any(|p| run_root.starts_with(p)),
        "TT03-F-ADMIT-REFUSED: foreign run-root {run_root}"
    );
    let procs = value["procs"].as_array().expect("procs");
    let find = |role: &str| {
        procs
            .iter()
            .find(|p| p["role"].as_str() == Some(role))
            .unwrap_or_else(|| panic!("TT03-F-ADMIT-REFUSED: proc role {role} missing"))
    };
    let live_starttime = |pid: i64| {
        let stat = std::fs::read(format!("/proc/{pid}/stat")).expect("live stat");
        let (_, _, starttime) = parse_stat_comm_state_starttime(&stat).expect("stat parses");
        starttime
    };
    // Nested pidns lease: multi-entry NSpid plus a foreign pidns inode,
    // re-read live (manifest values alone prove nothing).
    let pidns = find("pidns-sleeper");
    let pid = pidns["pid"].as_i64().expect("pid");
    assert_eq!(
        live_starttime(pid),
        pidns["starttime"].as_u64().expect("starttime"),
        "admitted pidns sleeper must be the same live process"
    );
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("live status");
    let nspid = status
        .lines()
        .find(|l| l.starts_with("NSpid:"))
        .expect("NSpid row")
        .split(':')
        .nth(1)
        .expect("NSpid values");
    assert!(
        nspid.split_whitespace().count() >= 2,
        "pidns sleeper must show nested NSpid, got:{nspid}"
    );
    let mine = std::fs::read_link("/proc/self/ns/pid").expect("own pidns");
    let theirs = std::fs::read_link(format!("/proc/{pid}/ns/pid")).expect("sleeper pidns");
    assert_ne!(
        mine, theirs,
        "sleeper pidns must differ from observer pidns"
    );
    // Foreign mount-view lease: target-root bytes differ from observer
    // bytes for the same owned path.
    let mnt = find("mnt-sleeper");
    let mnt_pid = mnt["pid"].as_i64().expect("pid");
    assert_eq!(
        live_starttime(mnt_pid),
        mnt["starttime"].as_u64().expect("starttime"),
        "admitted mnt sleeper must be the same live process"
    );
    let view = PathBuf::from(&run_root).join("ns/view/data.txt");
    assert!(view.starts_with(&run_root), "view stays under run-root");
    let observer_bytes = std::fs::read(&view).expect("observer view bytes");
    assert!(
        observer_bytes.starts_with(b"observer-view-bytes\n"),
        "observer sees own view"
    );
    let foreign_path = format!("/proc/{mnt_pid}/root{}", view.display());
    let foreign_bytes = std::fs::read(&foreign_path).expect("foreign view bytes");
    assert!(
        foreign_bytes.starts_with(b"foreign-view-bytes\n"),
        "mnt sleeper must serve the foreign overmount"
    );
    assert_ne!(observer_bytes, foreign_bytes, "views must actually differ");
    println!(
        "TT03-F-PASS f_tt04_realm_leases_admitted: pidns={pid} mnt={mnt_pid} \
         nested={:?}",
        value["evidence"]["nested_pidns"].as_str()
    );
}

/// S225: a fork child facing pipe EOF must `_exit(13)`, never panic.
/// The parent closes the write end first so the child's read hits EOF
/// deterministically; the reaped exit code is 13 (pipe IO failure),
/// not a panic/abort/signal. Pre-fix the child asserted and died
/// dirty, risking a hung suite instead of a red test.
#[test]
fn s225_fork_child_pipe_eof_exits_13() {
    let mut pipe = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
    // SAFETY: the child performs only async-signal-safe syscalls on
    // stack memory and `_exit`s; it never allocates, locks, or
    // returns into test code.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork must succeed");
    if pid == 0 {
        unsafe {
            libc::close(pipe[1]);
            let mut one = [0u8; 1];
            if !child_pipe_read_exact(pipe[0], &mut one) {
                libc::_exit(13);
            }
            libc::_exit(99);
        }
    }
    unsafe {
        // Close the write end FIRST: the child's read hits EOF.
        libc::close(pipe[1]);
        libc::close(pipe[0]);
        let mut status_code = 0;
        let reaped = libc::waitpid(pid, &mut status_code, 0);
        assert_eq!(reaped, pid, "exact child reap");
        assert!(
            libc::WIFEXITED(status_code),
            "child must exit, not die by signal/panic: {status_code}"
        );
        assert_eq!(
            libc::WEXITSTATUS(status_code),
            13,
            "pipe EOF must exit 13"
        );
    }
}

/// Owned FD, closed on drop. Pipe ends are armed in these from
/// creation, so a second-pipe/fork/setup failure cannot strand raw
/// descriptors (finding 2). Parent side only.
#[cfg(target_os = "linux")]
struct FdGuard(Option<libc::c_int>);
#[cfg(target_os = "linux")]
impl FdGuard {
    fn new(fd: libc::c_int) -> Self {
        Self(Some(fd))
    }
    fn raw(&self) -> libc::c_int {
        self.0.expect("live FD")
    }
    fn close(&mut self) {
        if let Some(fd) = self.0.take() {
            unsafe {
                libc::close(fd);
            }
        }
    }
}
#[cfg(target_os = "linux")]
impl Drop for FdGuard {
    fn drop(&mut self) {
        self.close();
    }
}

/// Fork-child owner: SIGKILLs + exactly reaps unless done, and ALWAYS
/// closes owned FDs even on the done path (finding 2: the SKIP/
/// setup-failure path must not leak the retained pipe ends). Parent
/// side only; `pid` is None until fork succeeds.
#[cfg(target_os = "linux")]
struct NsChildGuard {
    pid: Option<libc::pid_t>,
    done: bool,
}
/// Blocking waitpid that retries EINTR (CONSIDER: an interrupted
/// reap must not silently pass). Returns the raw waitpid result.
/// Parent side only.
#[cfg(target_os = "linux")]
fn waitpid_eintr(pid: libc::pid_t, status: &mut libc::c_int) -> libc::pid_t {
    loop {
        let reaped = unsafe { libc::waitpid(pid, status, 0) };
        if reaped < 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
        {
            continue;
        }
        return reaped;
    }
}
#[cfg(target_os = "linux")]
impl Drop for NsChildGuard {
    fn drop(&mut self) {
        if !self.done {
            if let Some(pid) = self.pid {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                let mut status_code = 0;
                // EINTR retried; any other failure leaves the kill
                // issued with nothing provable — the loud paths are
                // the explicit reaps, which assert.
                waitpid_eintr(pid, &mut status_code);
            }
        }
    }
}

/// Outcome of one bounded handshake read (finding 3).
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
enum Handshake {
    Data,
    Eof,
    Timeout,
}

/// Dribble-producer owner (R4): shutdown + join, including on unwind.
/// The reader must stay open until the join lands, so this guard is
/// always declared AFTER the reader guard (drops first). Parent side.
#[cfg(target_os = "linux")]
struct ProducerGuard {
    tx: Option<std::sync::mpsc::Sender<()>>,
    handle: Option<std::thread::JoinHandle<()>>,
}
#[cfg(target_os = "linux")]
impl ProducerGuard {
    /// Release the producer and join it, returning the join result.
    /// Idempotent: second call is a no-op Ok.
    fn shutdown_and_join(&mut self) -> std::thread::Result<()> {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.join()
        } else {
            Ok(())
        }
    }
}
#[cfg(target_os = "linux")]
impl Drop for ProducerGuard {
    fn drop(&mut self) {
        // Unwind path: a producer panic here must not panic again
        // (abort during unwind) — the loud signal on the normal path
        // is the expect below plus the outcome assertion (a dead
        // producer surfaces EOF, never Timeout).
        let _ = self.shutdown_and_join();
    }
}

/// Handshake waits are bounded (finding 3): a child that never ACKs
/// must surface as Timeout, never wedge the suite. Operations here
/// complete in milliseconds; the bound only trips on a stuck child.
#[cfg(target_os = "linux")]
const HANDSHAKE_TIMEOUT_MS: libc::c_int = 30_000;

/// Blocking exact read against ONE monotonic deadline (finding 3:
/// EINTR and partial reads must not extend the allowance). Parent
/// side only.
#[cfg(target_os = "linux")]
fn handshake_read(fd: libc::c_int, mut buf: &mut [u8], timeout_ms: libc::c_int) -> Handshake {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms.max(0) as u64);
    while !buf.is_empty() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        // Poll takes i32 ms; clamp (the 30s operational bound is far
        // below saturation, this only hardens the helper contract).
        let wait_ms: libc::c_int = remaining.as_millis().min(i32::MAX as u128) as libc::c_int;
        if remaining.is_zero() {
            return Handshake::Timeout;
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pfd, 1, wait_ms) };
        if ready < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            panic!("handshake poll failed");
        }
        if ready == 0 {
            return Handshake::Timeout;
        }
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            panic!("handshake read failed");
        }
        if n == 0 {
            return Handshake::Eof;
        }
        buf = &mut buf[n as usize..];
    }
    Handshake::Data
}

/// Finding-3 mechanism control: a held-open pipe times out within the
/// bound (no writer, no EOF), and EOF surfaces promptly after the
/// writer closes. No fork needed — the mechanism is what's pinned.
#[cfg(target_os = "linux")]
#[test]
fn handshake_read_timeout_and_eof() {
    let mut raw = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(raw.as_mut_ptr()) }, 0);
    let mut rd = FdGuard::new(raw[0]);
    let mut wr = FdGuard::new(raw[1]);
    let start = std::time::Instant::now();
    assert_eq!(
        handshake_read(rd.raw(), &mut [0u8; 1], 100),
        Handshake::Timeout
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "timeout must fire within the bound"
    );
    wr.close();
    assert_eq!(
        handshake_read(rd.raw(), &mut [0u8; 1], 100),
        Handshake::Eof
    );
    rd.close();

    // Deadline control (finding 3): a writer dribbling 1 byte at
    // ~0/300/600ms must NOT extend a 400ms bound for 5 bytes — partial
    // reads share the one deadline. The deadline version times out at
    // ~400ms; a restart-per-read version would read all three bytes
    // and time out at ~1000ms. The outcome + elapsed are SAVED first;
    // shutdown/join/reader-close complete BEFORE any assertion, and
    // the producer guard covers unwind during the measured call (R4).
    let mut raw2 = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(raw2.as_mut_ptr()) }, 0);
    let mut rd2 = FdGuard::new(raw2[0]);
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
    let dribbler = std::thread::spawn(move || {
        let _wr2 = FdGuard::new(raw2[1]);
        for _ in 0..3 {
            let n = unsafe { libc::write(_wr2.raw(), b"x".as_ptr().cast(), 1) };
            assert_eq!(n, 1);
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        // No EOF is delivered during the measurement; block until the
        // main thread releases us, then drop (close) the write end.
        let _ = shutdown_rx.recv();
    });
    // Declared after rd2: on unwind this drops (shutdown+join) FIRST,
    // while the reader is still open — no write can hit a closed
    // reader on any path.
    let mut producer = ProducerGuard {
        tx: Some(shutdown_tx),
        handle: Some(dribbler),
    };
    let start = std::time::Instant::now();
    let outcome = handshake_read(rd2.raw(), &mut [0u8; 5], 400);
    let elapsed = start.elapsed();
    producer
        .shutdown_and_join()
        .expect("producer exits cleanly");
    rd2.close();
    assert_eq!(outcome, Handshake::Timeout);
    assert!(
        elapsed < std::time::Duration::from_millis(700),
        "partial reads must not extend the deadline"
    );
}

/// Scratch tree removed on drop. Shared by the mount-row tests.
#[cfg(target_os = "linux")]
struct ScratchGuard(PathBuf);
#[cfg(target_os = "linux")]
impl Drop for ScratchGuard {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

#[cfg(target_os = "linux")]
fn make_scratch(tag: &str) -> (PathBuf, ScratchGuard) {
    let dir = std::env::temp_dir().join(format!(
        "tt03-f-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let guard = ScratchGuard(dir.clone());
    (dir, guard)
}

/// Mount ID backing an open FD, via fdinfo (finding 1: distinguishes
/// the retained old proc instance from a fresh mount). Parent side.
#[cfg(target_os = "linux")]
fn fd_mnt_id(fd: libc::c_int) -> u64 {
    std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
        .expect("fdinfo readable")
        .lines()
        .find_map(|l| {
            l.strip_prefix("mnt_id:")
                .and_then(|v| v.trim().parse::<u64>().ok())
        })
        .expect("mnt_id present")
}

/// Append `suffix` to `scratch` into `buf` NUL-terminated.
/// Child-safe: stack writes + inherited read-only bytes only.
/// Returns false if it would not fit (including NUL).
fn child_join(scratch: &std::path::Path, suffix: &[u8], buf: &mut [u8; 4096]) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let base = scratch.as_os_str().as_bytes();
    if base.len() + suffix.len() + 1 > buf.len() {
        return false;
    }
    buf[..base.len()].copy_from_slice(base);
    buf[base.len()..base.len() + suffix.len()].copy_from_slice(suffix);
    buf[base.len() + suffix.len()] = 0;
    true
}

/// F mount_view_change_and_retained_root, live target-ns recipe.
///
/// Rootless target (fork + CLONE_NEWUSER/CLONE_NEWNS, self-mapped ids):
/// four phased populations on one target, each with its independent
/// oracle — (1) actual child overmount + unmount churn on a real file
/// (v1→v2→v1 via fresh proc-root reads, retained FD pins v1 throughout);
/// (2) symlink population (atomic link swap v1s→v2b, retained FD pins
/// v1s); (3) procfs-root replacement (/proc → marker tmpfs: fresh shows
/// the marker + a new mnt_id, retained FD pins the old proc without the
/// marker);
/// (4) filesystem-root replacement (chroot to newroot: fresh root shows
/// v3, retained old-root FD still serves v1, old tree unreachable via
/// the new root). Target/observer mntns differ; no scratch-path mount
/// may appear in the observer table (no propagation leak). All
/// handshakes run against one monotonic deadline; SKIPs with an exact
/// reason where userns creation is denied (EPERM/EACCES only).
#[cfg(target_os = "linux")]
#[test]
fn f_mount_view_change_and_retained_root() {
    let (scratch, _scratch) = make_scratch("mount");
    std::fs::create_dir_all(scratch.join("view")).unwrap();
    std::fs::write(scratch.join("view/data.txt"), b"v1-target-view-bytes\n").unwrap();
    std::fs::write(scratch.join("alt.txt"), b"v2-target-view-bytes\n").unwrap();
    // Symlink population: link.txt -> target_a (v1s); swap moves it to
    // target_b (v2b). Absolute targets keep child path building exact.
    std::fs::write(scratch.join("target_a.txt"), b"v1s-symlink-view-bytes\n").unwrap();
    std::fs::write(scratch.join("target_b.txt"), b"v2b-symlink-view-bytes\n").unwrap();
    std::os::unix::fs::symlink(scratch.join("target_a.txt"), scratch.join("view/link.txt"))
        .unwrap();
    // Chroot population: newroot carries a distinct view (v3).
    std::fs::create_dir_all(scratch.join("newroot/view")).unwrap();
    std::fs::write(
        scratch.join("newroot/view/data.txt"),
        b"v3-newroot-view-bytes\n",
    )
    .unwrap();

    // Pipe ends are guard-armed from creation (finding 2).
    let mut raw_ready = [0 as libc::c_int; 2];
    let mut raw_cmd = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(raw_ready.as_mut_ptr()) }, 0);
    let mut ready_r = FdGuard::new(raw_ready[0]);
    let mut ready_w = FdGuard::new(raw_ready[1]);
    assert_eq!(unsafe { libc::pipe(raw_cmd.as_mut_ptr()) }, 0);
    let mut cmd_r = FdGuard::new(raw_cmd[0]);
    let mut cmd_w = FdGuard::new(raw_cmd[1]);
    // Raw numbers for the child branch: plain ints, so the child makes
    // no guard calls (no panic paths) post-fork.
    let (rr_n, rw_n, cr_n, cw_n) = (ready_r.raw(), ready_w.raw(), cmd_r.raw(), cmd_w.raw());
    let mut guard = NsChildGuard {
        pid: None,
        done: false,
    };
    // SAFETY: the child performs only async-signal-safe syscalls on
    // stack memory and `_exit`s with a diagnostic code; it never
    // allocates, locks, touches std I/O, panics, or returns into test
    // code. 13 pipe IO, 14 protocol, 21 unshare denied (EPERM/EACCES,
    // SKIP-qualifying), 22 idmap, 23 self-bind/rprivate, 24 bind, 25
    // unmount, 26 unshare unsupported (EINVAL, fail), 27 unshare other
    // errno (fail), 28 symlink swap, 29 chroot, 30 proc replacement.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork must succeed");
    guard.pid = Some(pid);
    if pid == 0 {
        unsafe {
            libc::close(rr_n);
            libc::close(cw_n);
            // Capture ids BEFORE unshare: inside the new userns and
            // before the map is written, getuid/getgid report the
            // overflow id, which the kernel refuses to map back.
            let uid = libc::getuid();
            let gid = libc::getgid();
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
                // Finding 5: only denial qualifies for SKIP; anything
                // else is a loud, distinct failure.
                match std::io::Error::last_os_error().raw_os_error() {
                    Some(e) if e == libc::EPERM || e == libc::EACCES => libc::_exit(21),
                    Some(e) if e == libc::EINVAL => libc::_exit(26),
                    _ => libc::_exit(27),
                }
            }
            // Self idmap (rootless): deny setgroups, map own uid/gid.
            let mut deny = [0u8; 64];
            let deny_n = b"deny".len();
            deny[..deny_n].copy_from_slice(b"deny");
            let mut map = [0u8; 64];
            let map_txt = alloc_free_map(uid, gid, &mut map);
            if !write_file_at("/proc/self/setgroups", &deny[..deny_n])
                || !write_file_at("/proc/self/uid_map", map_txt.0)
                || !write_file_at("/proc/self/gid_map", map_txt.1)
            {
                libc::_exit(22);
            }
            if !child_pipe_write_all(rw_n, b"R") {
                libc::_exit(13);
            }
            // Fixed 5-command dispatch, one ACK each: B bind, U
            // unmount, S symlink swap, P proc remount, C chroot. Any
            // deviation exits.
            for _ in 0..5 {
                let mut one = [0u8; 1];
                if !child_pipe_read_exact(cr_n, &mut one) {
                    libc::_exit(13);
                }
                let ok = match one[0] {
                    // NOTE: the bind helper's own code (23 vs 24)
                    // exits directly — the dispatch map below only
                    // covers the bool legs.
                    b'B' => match child_bind_mutation(&scratch) {
                        Ok(()) => true,
                        Err(code) => libc::_exit(code),
                    },
                    b'U' => child_unmount_data(&scratch),
                    b'S' => child_symlink_swap(&scratch),
                    b'P' => child_replace_proc(),
                    b'C' => child_chroot_newroot(&scratch),
                    _ => libc::_exit(14),
                };
                if !ok {
                    let code = match one[0] {
                        // B exits with its own code above; this arm
                        // is unreachable-by-construction contract text.
                        b'B' => 24,
                        b'U' => 25,
                        b'S' => 28,
                        b'P' => 30,
                        _ => 29,
                    };
                    libc::_exit(code);
                }
                if !child_pipe_write_all(rw_n, b"A") {
                    libc::_exit(13);
                }
            }
            let nap = libc::timespec {
                tv_sec: 3600,
                tv_nsec: 0,
            };
            loop {
                libc::nanosleep(&nap, std::ptr::null_mut());
            }
        }
    }
    // Parent drops its unused ends promptly: the ready pipe must EOF
    // (not hang) if the child exits before R, so the SKIP path stays
    // prompt under the bounded handshake.
    ready_w.close();
    cmd_r.close();
    // Parent-side pipe IO may assert (a panic here is a proper red).
    unsafe fn pwrite_all(fd: libc::c_int, mut buf: &[u8]) {
        while !buf.is_empty() {
            let n = libc::write(fd, buf.as_ptr().cast(), buf.len());
            assert!(n > 0, "parent pipe write must deliver");
            buf = &buf[n as usize..];
        }
    }
    use std::io::{Read, Seek};
    // One bounded command round-trip; panics with the exact outcome.
    let cmd_roundtrip = |byte: u8, what: &str| {
        unsafe { pwrite_all(cmd_w.raw(), &[byte]) };
        let mut ack = [0u8; 1];
        match handshake_read(ready_r.raw(), &mut ack, HANDSHAKE_TIMEOUT_MS) {
            Handshake::Data => assert_eq!(ack, [b'A'], "{what} must ACK"),
            Handshake::Eof => panic!("{what}: child exited without ACK"),
            Handshake::Timeout => panic!("{what}: ACK timed out"),
        }
    };
    // Rewind + full re-read of a retained FD.
    let read_retained = |f: &mut std::fs::File, what: &str| -> Vec<u8> {
        f.seek(std::io::SeekFrom::Start(0)).expect(what);
        let mut v = Vec::new();
        f.read_to_end(&mut v).expect(what);
        v
    };

    let mut byte = [0u8; 1];
    match handshake_read(ready_r.raw(), &mut byte, HANDSHAKE_TIMEOUT_MS) {
        Handshake::Data => assert_eq!(byte, [b'R'], "target must report ready"),
        Handshake::Eof => {
            // Child exited before ready: reap exactly. 21 (unshare
            // denied, EPERM/EACCES) is an environmental SKIP; 26/27
            // and all else fail loudly. FD guards drop on every path.
            let mut status_code = 0;
            let reaped = waitpid_eintr(pid, &mut status_code);
            assert_eq!(reaped, pid, "exact child reap");
            guard.done = true;
            if libc::WIFEXITED(status_code) && libc::WEXITSTATUS(status_code) == 21 {
                println!(
                    "TT03-F-SKIP f_mount_view_change_and_retained_root: unshare denied (EPERM/EACCES)"
                );
                return;
            }
            panic!("target setup failed before ready: status={status_code}");
        }
        Handshake::Timeout => panic!("target ready handshake timed out"),
    }

    // Namespaces really differ.
    let mine = std::fs::read_link("/proc/self/ns/mnt").expect("own mntns");
    let theirs = std::fs::read_link(format!("/proc/{pid}/ns/mnt")).expect("target mntns");
    assert_ne!(mine, theirs, "target must live in its own mount ns");

    // Phase 1: actual child overmount + unmount churn on a real file.
    let target_view = format!("/proc/{pid}/root{}", scratch.join("view/data.txt").display());
    let mut retained = std::fs::File::open(&target_view).expect("retained view open");
    assert_eq!(
        read_retained(&mut retained, "retained v1 read"),
        b"v1-target-view-bytes\n",
        "pre-mutation view is v1"
    );
    cmd_roundtrip(b'B', "bind");
    assert_eq!(
        std::fs::read(&target_view).expect("post-bind view read"),
        b"v2-target-view-bytes\n",
        "post-bind view must show v2 bytes"
    );
    assert_eq!(
        read_retained(&mut retained, "retained v1 re-read"),
        b"v1-target-view-bytes\n",
        "retained FD must still read v1 (old mount pinned)"
    );
    cmd_roundtrip(b'U', "unmount");
    assert_eq!(
        std::fs::read(&target_view).expect("post-unmount view read"),
        b"v1-target-view-bytes\n",
        "post-unmount view must show v1 bytes again"
    );
    assert_eq!(
        read_retained(&mut retained, "retained v1 third read"),
        b"v1-target-view-bytes\n",
        "retained FD must still read v1 after unmount"
    );
    assert_eq!(
        std::fs::read(scratch.join("view/data.txt")).expect("own view read"),
        b"v1-target-view-bytes\n",
        "observer view file unchanged"
    );

    // Phase 2: symlink population. The swap is a shared-tree mutation
    // (visible to the observer too); the oracle is retained-vs-fresh,
    // not observer isolation.
    let target_link = format!("/proc/{pid}/root{}", scratch.join("view/link.txt").display());
    let mut retained_link = std::fs::File::open(&target_link).expect("retained link open");
    assert_eq!(
        read_retained(&mut retained_link, "retained v1s read"),
        b"v1s-symlink-view-bytes\n",
        "pre-swap link reads v1s"
    );
    cmd_roundtrip(b'S', "symlink swap");
    assert_eq!(
        std::fs::read(&target_link).expect("post-swap link read"),
        b"v2b-symlink-view-bytes\n",
        "post-swap link must show v2b bytes"
    );
    assert_eq!(
        read_retained(&mut retained_link, "retained v1s re-read"),
        b"v1s-symlink-view-bytes\n",
        "retained link FD must still read v1s (old target pinned)"
    );

    // Phase 3: procfs-root replacement (finding 1). Retain the
    // target's proc root, replace the target's /proc mount with a
    // marker tmpfs (proc→proc needs a new pid ns or privilege — see
    // child_replace_proc), then prove BOTH directions: the retained
    // FD still serves the OLD proc (stable mnt_id, uptime readable,
    // marker absent) while fresh acquisition serves the NEW mount
    // (mnt_id differs, marker present with exact bytes).
    use std::os::unix::io::AsRawFd;
    let target_proc = format!("/proc/{pid}/root/proc");
    let retained_proc = std::fs::File::open(&target_proc).expect("retained proc root open");
    let mnt_before = fd_mnt_id(retained_proc.as_raw_fd());
    let fresh_pre = std::fs::File::open(&target_proc).expect("pre-replacement proc open");
    assert_eq!(
        fd_mnt_id(fresh_pre.as_raw_fd()),
        mnt_before,
        "same proc instance before replacement"
    );
    drop(fresh_pre);
    cmd_roundtrip(b'P', "proc replacement");
    let fresh_proc = std::fs::File::open(&target_proc).expect("fresh proc root open");
    assert_ne!(
        fd_mnt_id(fresh_proc.as_raw_fd()),
        mnt_before,
        "fresh proc root must be the replacement mount"
    );
    assert_eq!(
        fd_mnt_id(retained_proc.as_raw_fd()),
        mnt_before,
        "retained proc FD must pin the old instance"
    );
    let old_uptime = std::fs::read(format!("/proc/self/fd/{}/uptime", retained_proc.as_raw_fd()))
        .expect("old proc readable");
    assert!(
        !old_uptime.is_empty(),
        "old proc instance stays readable via retained FD"
    );
    assert!(
        std::fs::read(format!(
            "/proc/self/fd/{}/replaced-marker",
            retained_proc.as_raw_fd()
        ))
        .is_err(),
        "retained proc FD must not see the replacement marker"
    );
    assert_eq!(
        std::fs::read(format!("{target_proc}/replaced-marker")).expect("fresh marker read"),
        b"replaced-proc-marker\n",
        "fresh acquisition must serve the replacement marker"
    );

    // Phase 4: filesystem-root replacement via chroot (last: it
    // repoints /proc/PID/root for everything after).
    let old_root = std::fs::File::open(format!("/proc/{pid}/root")).expect("old root open");
    let old_rel = scratch
        .strip_prefix("/")
        .expect("scratch is absolute")
        .join("view/data.txt");
    cmd_roundtrip(b'C', "chroot");
    assert_eq!(
        std::fs::read(format!("/proc/{pid}/root/view/data.txt")).expect("new root view read"),
        b"v3-newroot-view-bytes\n",
        "fresh root must show the v3 newroot view"
    );
    let via_old_root = format!("/proc/self/fd/{}/{}", old_root.as_raw_fd(), old_rel.display());
    assert_eq!(
        std::fs::read(&via_old_root).expect("retained root read"),
        b"v1-target-view-bytes\n",
        "retained old-root FD must still serve the v1 old tree"
    );
    assert!(
        std::fs::read(format!("/proc/{pid}/root/tmp")).is_err(),
        "old tree must be unreachable via the new root"
    );

    // Observer mount table carries none of our mounts (finding 4):
    // the child's rprivate is defense-in-depth over the kernel's
    // automatic shared->slave downgrade for userns-owned mount
    // namespaces, so this assertion proves no-propagation rather than
    // discriminating the rprivate call itself. Scoped to our paths so
    // unrelated table churn elsewhere cannot flake it.
    let scratch_pat = format!("{}", scratch.display());
    for line in std::fs::read_to_string("/proc/self/mountinfo")
        .expect("observer mountinfo")
        .lines()
    {
        assert!(
            !line.contains(&scratch_pat),
            "observer table must not reference our scratch mounts: {line}"
        );
    }

    unsafe {
        assert_eq!(libc::kill(pid, libc::SIGKILL), 0);
    }
    let mut status_code = 0;
    let reaped = waitpid_eintr(pid, &mut status_code);
    assert_eq!(reaped, pid, "exact child reap");
    assert!(libc::WIFSIGNALED(status_code), "target must die by signal");
    ready_r.close();
    cmd_w.close();
    guard.done = true;
}

/// Format "0 <id> 1" idmap lines without allocation (child-safe).
unsafe fn alloc_free_map(
    uid: libc::uid_t,
    gid: libc::gid_t,
    buf: &mut [u8; 64],
) -> (&[u8], &[u8]) {
    unsafe fn num(mut n: u32, out: &mut [u8]) -> usize {
        if n == 0 {
            out[0] = b'0';
            return 1;
        }
        let mut tmp = [0u8; 16];
        let mut len = 0;
        while n > 0 {
            tmp[len] = b'0' + (n % 10) as u8;
            n /= 10;
            len += 1;
        }
        for i in 0..len {
            out[i] = tmp[len - 1 - i];
        }
        len
    }
    let (u, g) = buf.split_at_mut(32);
    let mut ul = 0;
    u[ul..ul + 2].copy_from_slice(b"0 ");
    ul += 2;
    ul += num(uid, &mut u[ul..]);
    u[ul..ul + 2].copy_from_slice(b" 1");
    ul += 2;
    let mut gl = 0;
    g[gl..gl + 2].copy_from_slice(b"0 ");
    gl += 2;
    gl += num(gid, &mut g[gl..]);
    g[gl..gl + 2].copy_from_slice(b" 1");
    gl += 2;
    let (u, g) = buf.split_at(32);
    (&u[..ul], &g[..gl])
}

/// Self-bind + rprivate the scratch tree, then bind `alt.txt` over
/// `view/data.txt` — all inside the child's own mount namespace.
/// Child-safe: stack buffers, inherited read-only path bytes, raw
/// syscalls only. `Err(23)` = self-bind/rprivate failed, `Err(24)` =
/// file bind failed.
unsafe fn child_bind_mutation(scratch: &std::path::Path) -> Result<(), i32> {
    use std::os::unix::ffi::OsStrExt;
    let base = scratch.as_os_str().as_bytes();
    // NUL-terminated stack copies: scratch, view, data, alt.
    let mut s = [0u8; 4096];
    let mut v = [0u8; 4096];
    let mut d = [0u8; 4096];
    let mut a = [0u8; 4096];
    if base.len() + 16 > 4096 {
        return Err(24);
    }
    s[..base.len()].copy_from_slice(base);
    let mut n = base.len();
    v[..n].copy_from_slice(base);
    v[n..n + 5].copy_from_slice(b"/view");
    n += 5;
    d[..n].copy_from_slice(&v[..n]);
    d[n..n + 9].copy_from_slice(b"/data.txt");
    let dn = n + 9;
    a[..base.len()].copy_from_slice(base);
    a[base.len()..base.len() + 8].copy_from_slice(b"/alt.txt");
    let an = base.len() + 8;
    let ret = unsafe {
        libc::mount(
            s.as_ptr().cast(),
            s.as_ptr().cast(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(23);
    }
    let ret = unsafe {
        libc::mount(
            std::ptr::null(),
            s.as_ptr().cast(),
            std::ptr::null(),
            libc::MS_PRIVATE | libc::MS_REC,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(23);
    }
    let ret = unsafe {
        libc::mount(
            a.as_ptr().cast(),
            d.as_ptr().cast(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(24);
    }
    let _ = (dn, an);
    Ok(())
}

/// Unmount the file bind created by `child_bind_mutation` (churn
/// leg). Child-safe. False = path build or umount2 failed.
unsafe fn child_unmount_data(scratch: &std::path::Path) -> bool {
    let mut d = [0u8; 4096];
    if !child_join(scratch, b"/view/data.txt", &mut d) {
        return false;
    }
    unsafe { libc::umount2(d.as_ptr().cast(), 0) == 0 }
}

/// Atomically swap the view symlink from target_a to target_b via a
/// `.new` link + rename. Child-safe. False = path build, symlink or
/// rename failed.
unsafe fn child_symlink_swap(scratch: &std::path::Path) -> bool {
    let mut link = [0u8; 4096];
    let mut tmp = [0u8; 4096];
    let mut tgt = [0u8; 4096];
    if !child_join(scratch, b"/view/link.txt", &mut link)
        || !child_join(scratch, b"/view/link.txt.new", &mut tmp)
        || !child_join(scratch, b"/target_b.txt", &mut tgt)
    {
        return false;
    }
    if unsafe { libc::symlink(tgt.as_ptr().cast(), tmp.as_ptr().cast()) } != 0 {
        return false;
    }
    unsafe { libc::rename(tmp.as_ptr().cast(), link.as_ptr().cast()) == 0 }
}

/// Chroot into `<scratch>/newroot` (filesystem-root replacement
/// leg). Child-safe. False = path build or chroot failed.
unsafe fn child_chroot_newroot(scratch: &std::path::Path) -> bool {
    let mut n = [0u8; 4096];
    if !child_join(scratch, b"/newroot", &mut n) {
        return false;
    }
    unsafe { libc::chroot(n.as_ptr().cast()) == 0 }
}

/// Replace the target's own /proc with a marker-carrying tmpfs
/// (procfs-root replacement leg, finding 1). A fresh proc instance
/// for the SAME pid namespace is not mountable rootless on this
/// kernel (EPERM; only a new pid ns or privilege mints one), so the
/// replacement mount is a tmpfs — the retained-vs-fresh mechanism is
/// identical, and LX08's own privileged row covers proc→proc.
/// Child-safe. False = mount/marker failed.
unsafe fn child_replace_proc() -> bool {
    if unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            c"/proc".as_ptr(),
            c"tmpfs".as_ptr(),
            0,
            std::ptr::null(),
        )
    } != 0
    {
        return false;
    }
    let fd = unsafe {
        libc::open(
            c"/proc/replaced-marker".as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd < 0 {
        return false;
    }
    let bytes = b"replaced-proc-marker\n";
    let mut rest = &bytes[..];
    while !rest.is_empty() {
        let n = unsafe { libc::write(fd, rest.as_ptr().cast(), rest.len()) };
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if n <= 0 {
            unsafe { libc::close(fd) };
            return false;
        }
        rest = &rest[n as usize..];
    }
    unsafe { libc::close(fd) };
    true
}

/// Open/write/close a small proc file without allocation (child-safe).
unsafe fn write_file_at(path: &str, bytes: &[u8]) -> bool {
    let mut cpath = [0u8; 64];
    if path.len() + 1 > cpath.len() {
        return false;
    }
    cpath[..path.len()].copy_from_slice(path.as_bytes());
    let fd = unsafe {
        libc::open(
            cpath.as_ptr().cast(),
            libc::O_WRONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return false;
    }
    let mut rest = bytes;
    while !rest.is_empty() {
        let n = unsafe { libc::write(fd, rest.as_ptr().cast(), rest.len()) };
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if n <= 0 {
            unsafe { libc::close(fd) };
            return false;
        }
        rest = &rest[n as usize..];
    }
    unsafe { libc::close(fd) };
    true
}
