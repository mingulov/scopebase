// SPDX-License-Identifier: Apache-2.0
//! Single-threaded explicit opt-in fixture; creates no BPF program or host CPU change.
#[path = "../tests/support/native_fixture.rs"]
mod fixture;
#[path = "../tests/support/mount_custody.rs"]
mod mount_custody;
use scopebase_bpf::{ErrorKind, LiveCpuTopology, ValidatedMap};
use std::{ffi::CString, os::unix::ffi::OsStrExt, path::Path};
fn c(p: impl AsRef<Path>) -> CString {
    CString::new(p.as_ref().as_os_str().as_bytes()).unwrap()
}
fn mount(source: Option<&Path>, target: &Path, ty: Option<&str>, flags: libc::c_ulong) {
    let s = source.map(c);
    let t = c(target);
    let f = ty.map(|s| CString::new(s).unwrap());
    // SAFETY: initialized C strings live through synchronous mount; explicitly owned namespace only.
    let r = unsafe {
        libc::mount(
            s.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            t.as_ptr(),
            f.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            std::ptr::null(),
        )
    };
    assert_eq!(r, 0, "fixture mount: {}", std::io::Error::last_os_error());
}
fn isolated_mounts() {
    // SAFETY: single-threaded opt-in helper owns its new mount namespace.
    assert_eq!(
        unsafe { libc::unshare(libc::CLONE_NEWNS) },
        0,
        "owned mount namespace unavailable"
    );
    mount(None, Path::new("/"), None, libc::MS_PRIVATE | libc::MS_REC);
}
#[derive(Debug)]
struct InternalWait {
    pid: i32,
    returned_pid: Option<i32>,
    status: Option<i32>,
    errno: Option<i32>,
    attempts: usize,
    retries: usize,
}
impl InternalWait {
    fn reaped(&self) -> bool {
        self.returned_pid == Some(self.pid)
    }
    fn success(&self) -> bool {
        self.reaped()
            && self
                .status
                .is_some_and(|status| libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0)
    }
    fn emit(&self) {
        println!("BP02_INTERNAL_CHILD_CUSTODY={{\"schema_version\":1,\"child_pid\":{},\"returned_pid\":{},\"status\":{},\"errno\":{},\"attempts\":{},\"retries\":{},\"child_reaped\":{},\"child_success\":{},\"custody_unresolved\":{}}}", self.pid, self.returned_pid.map_or_else(|| "null".into(), |pid| pid.to_string()), self.status.map_or_else(|| "null".into(), |status| status.to_string()), self.errno.map_or_else(|| "null".into(), |errno| errno.to_string()), self.attempts, self.retries, self.reaped(), self.success(), !self.reaped());
    }
}
fn wait_result(pid: i32, mut call: impl FnMut(&mut i32) -> Result<i32, i32>) -> InternalWait {
    let mut outcome = InternalWait {
        pid,
        returned_pid: None,
        status: None,
        errno: None,
        attempts: 0,
        retries: 0,
    };
    for _ in 0..8 {
        let mut status = 0;
        outcome.attempts += 1;
        match call(&mut status) {
            Ok(returned) => {
                outcome.returned_pid = Some(returned);
                outcome.status = Some(status);
                break;
            }
            Err(libc::EINTR) => {
                outcome.errno = Some(libc::EINTR);
                outcome.retries += 1;
            }
            Err(errno) => {
                outcome.errno = Some(errno);
                break;
            }
        }
    }
    if outcome.reaped() {
        outcome.errno = None;
    }
    outcome
}
fn actual_wait(pid: i32, status: &mut i32) -> Result<i32, i32> {
    // SAFETY: pid is the exact freshly forked child, status writable; no PID signaling.
    let returned = unsafe { libc::waitpid(pid, status, 0) };
    if returned < 0 {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    } else {
        Ok(returned)
    }
}
fn wait(pid: i32) {
    let outcome = wait_result(pid, |status| actual_wait(pid, status));
    outcome.emit();
    assert!(
        outcome.reaped() && outcome.success(),
        "fixture internal child failed/unresolved: {outcome:?}"
    );
}
fn source(case: &str) {
    isolated_mounts();
    let root = std::env::temp_dir().join(format!("scopebase-bp02-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    mount_custody::report_root(&root).unwrap();
    std::fs::create_dir(root.join("proc")).unwrap();
    mount(
        Some(Path::new("/proc")),
        &root.join("proc"),
        None,
        libc::MS_BIND,
    );
    if case == "symlink-root" {
        std::fs::create_dir(root.join("real-sys")).unwrap();
        mount(
            Some(Path::new("/sys")),
            &root.join("real-sys"),
            None,
            libc::MS_BIND | libc::MS_REC,
        );
        std::os::unix::fs::symlink("real-sys", root.join("sys")).unwrap();
    } else {
        std::fs::create_dir(root.join("sys")).unwrap();
        match case {
            "full-root" | "replace-root" | "online-leaf" | "symlink-leaf" => mount(
                Some(Path::new("/sys")),
                &root.join("sys"),
                None,
                libc::MS_BIND | libc::MS_REC,
            ),
            "subtree" => mount(
                Some(Path::new("/sys/devices")),
                &root.join("sys"),
                None,
                libc::MS_BIND,
            ),
            "fake" => {
                mount(None, &root.join("sys"), Some("tmpfs"), 0);
                std::fs::create_dir_all(root.join("sys/devices/system/cpu")).unwrap();
                std::fs::write(root.join("sys/devices/system/cpu/possible"), b"0\n").unwrap();
            }
            _ => panic!("unknown source case"),
        }
    }
    if case == "online-leaf" {
        mount(
            Some(Path::new("/sys/devices/system/cpu/online")),
            &root.join("sys/devices/system/cpu/possible"),
            None,
            libc::MS_BIND,
        );
    }
    if case == "symlink-leaf" {
        let p = root.join("sys/devices/system/cpu");
        mount(None, &p, Some("tmpfs"), 0);
        std::os::unix::fs::symlink("online", p.join("possible")).unwrap();
        std::fs::write(p.join("online"), b"0\n").unwrap();
    }
    let fd = fixture::create(6, 4, 8, 2, 0, None).unwrap();
    fixture::update(&fd, &0u32.to_le_bytes(), &fixture::pattern(8)).unwrap();
    // SAFETY: chroot changes only this explicitly disposable single-threaded child;
    // it contains complete authentic proc/sys roots or the named adversarial source.
    assert_eq!(unsafe { libc::chroot(c(&root).as_ptr()) }, 0);
    std::env::set_current_dir("/").unwrap();
    let result =
        ValidatedMap::from_owned_fd(fd, &fixture::expected(6, 4, 8, 2, 0), &fixture::limits());
    if case == "full-root" || case == "replace-root" {
        let mut map = result.unwrap();
        assert!(map.lookup(&0u32.to_le_bytes()).unwrap().is_some());
        if case == "replace-root" {
            mount(None, Path::new("/sys"), Some("tmpfs"), 0);
            let mut out = vec![0xa5; map.geometry().buffer_len()];
            let e = map.lookup_into(&0u32.to_le_bytes(), &mut out).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Changed);
            assert!(out.iter().all(|b| *b == 0xa5));
            assert_eq!(
                map.lookup(&0u32.to_le_bytes()).unwrap_err().kind(),
                ErrorKind::Poisoned
            );
        }
    } else {
        let e = match result {
            Err(e) => e,
            Ok(_) => panic!("false source accepted {case}"),
        };
        if case == "symlink-root" {
            assert_eq!(
                (e.kind(), e.stage(), e.raw_os_error()),
                (
                    ErrorKind::Unsupported,
                    scopebase_bpf::Stage::Admission,
                    Some(libc::ELOOP)
                ),
                "existing authentic symlink target must refuse traversal"
            );
        } else {
            assert!(matches!(
                e.kind(),
                ErrorKind::Unsupported | ErrorKind::Disappeared
            ));
        }
    }
    println!("PASS source {case}");
    // Namespace/process exit releases mounts; external runner owns temporary root
    // directories and removes them only after exact helper exit/custody proof.
}
fn context(nested: bool) {
    let fd = fixture::create(6, 4, 8, 2, 0, None).unwrap();
    fixture::update(&fd, &0u32.to_le_bytes(), &fixture::pattern(8)).unwrap();
    let mut map = ValidatedMap::from_owned_fd(
        fd.try_clone().unwrap(),
        &fixture::expected(6, 4, 8, 2, 0),
        &fixture::limits(),
    )
    .unwrap();
    if nested {
        // SAFETY: single-thread helper is PID1 in explicit outer fixture; future child
        // enters a fresh namespace, original proc remains an ancestor namespace.
        assert_eq!(
            unsafe { libc::getpid() },
            1,
            "nested fixture must start as outer PID1"
        );
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWPID) }, 0);
    }
    // SAFETY: this main has never started threads; parent retains exact child ID.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        if nested {
            assert_eq!(unsafe { libc::getpid() }, 1);
        }
        let mut out = vec![0xa5; map.geometry().buffer_len()];
        let e = map.lookup_into(&0u32.to_le_bytes(), &mut out).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Changed);
        assert!(out.iter().all(|b| *b == 0xa5));
        assert_eq!(
            map.lookup(&0u32.to_le_bytes()).unwrap_err().kind(),
            ErrorKind::Poisoned
        );
        let mut fresh =
            ValidatedMap::from_owned_fd(fd, &fixture::expected(6, 4, 8, 2, 0), &fixture::limits())
                .unwrap();
        assert!(fresh.lookup(&0u32.to_le_bytes()).unwrap().is_some());
        println!("PASS child context nested={nested}");
        // SAFETY: single-thread fixture child completes its owned work and exits.
        unsafe { libc::_exit(0) }
    }
    wait(pid);
    assert!(map.lookup(&0u32.to_le_bytes()).unwrap().is_some());
    println!("PASS parent context nested={nested}");
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(
        args.iter().any(|a| a == "--owned-namespace"),
        "explicit --owned-namespace required"
    );
    fixture::require_offline();
    match args.get(1).map(String::as_str) {
        Some("fork") => context(false),
        Some("nested") => context(true),
        Some("topology") => {
            let t = LiveCpuTopology::acquire(&fixture::limits()).unwrap();
            t.revalidate().unwrap();
            println!("PASS authentic topology {:?}", t.snapshot().ids());
        }
        Some(case) => source(case),
        None => panic!("named case required"),
    }
}

#[cfg(test)]
mod wait_controls {
    use super::*;
    fn child(exit: i32) -> i32 {
        // SAFETY: the control child performs only async-signal-safe _exit after
        // fork from libtest. All allocation/assertions/waiting stay in parent.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe { libc::_exit(exit) }
        }
        pid
    }
    #[test]
    fn owned_internal_wait_success_failure_and_eintr_twins() {
        for exit in [0, 7] {
            let pid = child(exit);
            let mut first = true;
            let outcome = wait_result(pid, |status| {
                if first {
                    first = false;
                    Err(libc::EINTR)
                } else {
                    actual_wait(pid, status)
                }
            });
            outcome.emit();
            assert!(outcome.reaped());
            assert_eq!(
                (outcome.attempts, outcome.retries, outcome.errno),
                (2, 1, None)
            );
            assert_eq!(outcome.success(), exit == 0);
        }
    }
    #[test]
    fn owned_internal_wait_unexpected_and_exhaustion_retain_unresolved() {
        for errno in [libc::EIO, libc::ECHILD, libc::EINTR] {
            let pid = child(0);
            let outcome = wait_result(pid, |_| Err(errno));
            outcome.emit();
            // Retain the failed observation; separately recover only the exact
            // child still owned by this injected control, without signaling.
            let recovered = wait_result(pid, |status| actual_wait(pid, status));
            assert!(recovered.reaped());
            assert!(!outcome.reaped() && !outcome.success());
            assert_eq!(outcome.errno, Some(errno));
            assert_eq!(outcome.attempts, if errno == libc::EINTR { 8 } else { 1 });
        }
    }
}
