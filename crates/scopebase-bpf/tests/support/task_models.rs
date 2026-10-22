// SPDX-License-Identifier: Apache-2.0
// Included only in private provenance unit tests. Models never create live owners.
use super::*;
use std::cell::Cell;
struct Model {
    calls: Cell<usize>,
    fail: usize,
    errno: i32,
    result: usize,
    wrong_fs: bool,
}
impl Model {
    fn good() -> Self {
        Self {
            calls: Cell::new(0),
            fail: 0,
            errno: libc::ENOENT,
            result: 1,
            wrong_fs: false,
        }
    }
    fn step(&self, stage: S) -> Result<(), OperationError> {
        let n = self.calls.get() + 1;
        self.calls.set(n);
        if n == self.fail {
            Err(native::os_error(self.errno, stage))
        } else {
            Ok(())
        }
    }
}
fn original() -> Identity {
    Identity {
        major: 0,
        minor: 1,
        ino: 123,
        mount: 9,
        kind: DIR,
    }
}
impl ProbeIo for Model {
    type File = ();
    fn open(&self) -> Result<(), OperationError> {
        self.step(S::Admission)
    }
    fn stat(&self, _: &()) -> Result<Identity, OperationError> {
        self.step(S::Admission)?;
        Ok(Identity {
            kind: REG,
            mount: if self.wrong_fs { 10 } else { 9 },
            ..original()
        })
    }
    fn read(&self, _: &(), byte: &mut [u8; 1]) -> Result<usize, OperationError> {
        self.step(S::Read)?;
        assert_eq!(byte, &[0]);
        byte[0] = b'7';
        Ok(self.result)
    }
}
#[test]
fn same_inode_different_task_text_refuses() {
    // All model tuples/local IDs deliberately equal; text is the distinguishing fact.
    let saved = b"12/task/12";
    let mut w = Work::new(1000);
    assert!(task_text_equal(saved, saved, &mut w).is_ok());
    let e = task_text_equal(saved, b"13/task/13", &mut w).unwrap_err();
    assert_eq!((e.kind(), e.stage()), (K::Changed, S::Admission));
}
#[test]
fn reused_numbers_dead_original_refuse() {
    for (fail, errno, result) in [(1, 2, 1), (1, 3, 1), (2, 2, 1), (3, 3, 1), (0, 0, 0)] {
        let m = Model {
            fail,
            errno,
            result,
            ..Model::good()
        };
        let e = probe_io(&m, original(), &mut Work::new(1000), true).unwrap_err();
        assert_eq!((e.kind(), e.stage()), (K::Changed, S::Admission));
        assert_eq!(e.raw_os_error(), if fail == 0 { None } else { Some(errno) });
    }
    assert!(probe_io(&Model::good(), original(), &mut Work::new(1000), true).is_ok());
}
#[test]
fn task_probe_errors_sticky_and_output() {
    for fail in [1, 2, 3] {
        for errno in [
            libc::EACCES,
            libc::EPERM,
            libc::EIO,
            libc::EINTR,
            libc::EXDEV,
            libc::ELOOP,
        ] {
            let m = Model {
                fail,
                errno,
                ..Model::good()
            };
            let e = probe_io(&m, original(), &mut Work::new(1000), true).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(errno));
            assert_eq!(e.stage(), if fail == 3 { S::Read } else { S::Admission });
            assert_eq!(m.calls.get(), fail);
        }
    }
    let m = Model {
        wrong_fs: true,
        ..Model::good()
    };
    assert_eq!(
        probe_io(&m, original(), &mut Work::new(1000), true)
            .unwrap_err()
            .kind(),
        K::Changed
    );
    assert_eq!(m.calls.get(), 2);
    let m = Model {
        result: 0,
        ..Model::good()
    };
    let e = probe_io(&m, original(), &mut Work::new(1000), false).unwrap_err();
    assert_eq!((e.kind(), e.stage()), (K::Malformed, S::Read));
}
#[test]
fn task_probe_budget_fd_and_storage() {
    for cap in 0..5 {
        let m = Model::good();
        let e = probe_io(&m, original(), &mut Work::new(cap), true).unwrap_err();
        assert_eq!(e.kind(), K::LimitExceeded);
        assert!(m.calls.get() < 3);
    }
    let m = Model::good();
    assert!(probe_io(&m, original(), &mut Work::new(5), true).is_ok());
    assert_eq!(m.calls.get(), 3);
}
#[test]
#[ignore = "N8 actual held-original-task probe; admitted owned Linux fixture only"]
fn owned_task_probe_dead_and_living_twins() {
    let mut work = Work::new(1_000_000);
    let (proc, id) = root("/proc", 0x9fa0, &mut work, false).unwrap();
    let mut dead = native::task_fixture::Child::start();
    let mut living = native::task_fixture::Child::start();
    let (task, _) = child(
        &proc,
        &format!("{}/task/{}", dead.pid, dead.pid),
        OFlags::PATH | OFlags::DIRECTORY,
        id,
        DIR,
        &mut work,
        false,
    )
    .unwrap();
    let (twin, _) = child(
        &proc,
        &format!("{}/task/{}", living.pid, living.pid),
        OFlags::PATH | OFlags::DIRECTORY,
        id,
        DIR,
        &mut work,
        false,
    )
    .unwrap();
    STAT_OPENS.with(|n| n.set(0));
    probe(&task, id, &mut work, true).unwrap();
    probe(&twin, id, &mut work, true).unwrap();
    println!(
        "anchored living probes positive; fresh opens={}",
        STAT_OPENS.with(|n| n.get())
    );
    assert_eq!(
        STAT_OPENS.with(|n| n.get()),
        2,
        "each original anchor probe must perform a new open description"
    );
    println!("owned child ready pid={} living={}", dead.pid, living.pid);
    dead.finish();
    let e = probe(&task, id, &mut work, true).unwrap_err();
    assert_eq!((e.kind(), e.stage()), (K::Changed, S::Admission));
    assert!(matches!(e.raw_os_error(), Some(2 | 3) | None));
    probe(&twin, id, &mut work, true).unwrap();
    living.finish();
    println!("PASS dead original refused, independent living twin retained; both reaped");
}
#[test]
fn held_fd_errors_preserve_ordinary_mapper() {
    for n in [18, 40] {
        for prior in [false, true] {
            let e = errno(rustix::io::Errno::from_raw_os_error(n), S::Read, prior);
            assert_eq!(
                (e.kind(), e.stage(), e.raw_os_error()),
                (K::Backend, S::Read, Some(n))
            );
        }
    }
}

#[test]
fn constrained_open_retains_traversal_override() {
    for n in [18, 40] {
        for prior in [false, true] {
            let e = traversal_errno(rustix::io::Errno::from_raw_os_error(n), S::Admission, prior);
            assert_eq!(
                (e.kind(), e.stage(), e.raw_os_error()),
                (
                    if prior { K::Changed } else { K::Unsupported },
                    S::Admission,
                    Some(n)
                )
            );
        }
    }
}
#[test]
fn sysfs_complete_prefix_or_refusal() {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let limits = Limits {
        input_bytes: 65536,
        retained_bytes: 1 << 20,
        work_steps: 1_000_000,
        sites: 0,
        live_links: 0,
        pending_retirements: 0,
    };
    let read = |bytes: &[u8]| {
        let path = std::env::temp_dir().join(format!(
            "scopebase-bp02-cpulist-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.write_all(bytes).unwrap();
        drop(f);
        let fd: OwnedFd = std::fs::File::open(&path).unwrap().into();
        let r = read_topology(&fd, &limits, 0, &mut Work::new(limits.work_steps));
        drop(fd);
        std::fs::remove_file(path).unwrap();
        r
    };
    assert_eq!(read(b"0\n").unwrap().ids(), &[0]);
    let mut good = vec![b' '; 4092];
    good.extend_from_slice(b"0\n");
    assert_eq!(good.len(), 4094);
    assert_eq!(read(&good).unwrap().ids(), &[0]);
    for len in [4095, 4096, 65535, 65536] {
        let mut bytes = vec![b' '; len - 2];
        bytes.extend_from_slice(b"0\n");
        let e = read(&bytes).unwrap_err();
        assert_eq!((e.kind(), e.stage()), (K::LimitExceeded, S::Read));
    }
    for prefix in [b"0".as_slice(), b""] {
        let e = read(prefix).unwrap_err();
        assert_eq!((e.kind(), e.stage()), (K::Malformed, S::Read));
    }
}
struct CompleteModel {
    checks: Cell<usize>,
    values: Cell<usize>,
    invalid: Cell<bool>,
    post: bool,
    different_text: bool,
    probe_failure: usize,
    probe_errno: i32,
    probe_result: usize,
    map_errno: Option<i32>,
    absent: bool,
}
impl CompleteModel {
    fn good() -> Self {
        Self {
            checks: Cell::new(0),
            values: Cell::new(0),
            invalid: Cell::new(false),
            post: false,
            different_text: false,
            probe_failure: 0,
            probe_errno: libc::ENOENT,
            probe_result: 1,
            map_errno: None,
            absent: false,
        }
    }
}
impl super::super::handle::LookupIo for CompleteModel {
    fn extent(&self) -> usize {
        16
    }
    fn retained(&self) -> usize {
        0
    }
    fn revalidate(&self, w: &mut Work, _: usize) -> Result<(), OperationError> {
        run_revalidation(&self.invalid, || {
            let n = self.checks.get() + 1;
            self.checks.set(n);
            let inject = !self.post || n == 2;
            // Equal local IDs and every identity tuple in both populations. Only exact
            // original text/fresh original-anchor probe distinguishes these scenarios.
            let current = if inject && self.different_text {
                b"13/task/13".as_slice()
            } else {
                b"12/task/12".as_slice()
            };
            task_text_equal(b"12/task/12", current, w)?;
            let io = Model {
                fail: if inject { self.probe_failure } else { 0 },
                errno: self.probe_errno,
                result: if inject { self.probe_result } else { 1 },
                ..Model::good()
            };
            probe_io(&io, original(), w, true)
        })
    }
    fn value(&self, _: &[u8], scratch: &mut [u8], _: &mut Work) -> Result<bool, OperationError> {
        self.values.set(self.values.get() + 1);
        scratch.fill(42);
        if let Some(n) = self.map_errno {
            return Err(native::os_error(n, S::Read));
        }
        Ok(!self.absent)
    }
}
#[test]
fn complete_owner_task_loss_poisoning_and_output() {
    let limits = Limits {
        input_bytes: 4096,
        retained_bytes: 4096,
        work_steps: 100000,
        sites: 0,
        live_links: 0,
        pending_retirements: 0,
    };
    for post in [false, true] {
        for scenario in 0..6 {
            let io = CompleteModel {
                post,
                different_text: scenario == 0,
                probe_failure: match scenario {
                    1 => 1,
                    2 => 2,
                    3 | 4 => 3,
                    _ => 0,
                },
                probe_errno: if scenario == 4 {
                    libc::ESRCH
                } else {
                    libc::ENOENT
                },
                probe_result: if scenario == 5 { 0 } else { 1 },
                ..CompleteModel::good()
            };
            let mut out = [0xa5; 20];
            let e = super::super::handle::copy_read(
                &io,
                &[0; 4],
                &mut out,
                &limits,
                &mut Work::new(100000),
            )
            .unwrap_err();
            assert_eq!((e.kind(), e.stage()), (K::Changed, S::Admission));
            assert_eq!(out, [0xa5; 20]);
            assert_eq!(io.values.get(), usize::from(post));
            let e = super::super::handle::copy_read(
                &io,
                &[0; 4],
                &mut out,
                &limits,
                &mut Work::new(100000),
            )
            .unwrap_err();
            assert_eq!((e.kind(), e.stage()), (K::Poisoned, S::Admission));
            assert_eq!(out, [0xa5; 20]);
        }
    }
    for post in [false, true] {
        for errno in [libc::EXDEV, libc::ELOOP] {
            let io = CompleteModel {
                post,
                probe_failure: 3,
                probe_errno: errno,
                ..CompleteModel::good()
            };
            let mut out = [0xa5; 20];
            let e = super::super::handle::copy_read(
                &io,
                &[0; 4],
                &mut out,
                &limits,
                &mut Work::new(100000),
            )
            .unwrap_err();
            assert_eq!(
                (e.kind(), e.stage(), e.raw_os_error()),
                (K::Backend, S::Read, Some(errno))
            );
            assert!(io.invalid.get());
            assert_eq!(out, [0xa5; 20]);
        }
    }
    let io = CompleteModel::good();
    let mut out = [0xa5; 20];
    assert!(super::super::handle::copy_read(
        &io,
        &[0; 4],
        &mut out,
        &limits,
        &mut Work::new(100000)
    )
    .unwrap());
    assert_eq!(&out[..16], &[42; 16]);
    assert_eq!(io.checks.get(), 2);
}
#[test]
#[ignore = "N6 genuine sysfs leaf-symlink refusal independent of NO_XDEV"]
fn authentic_sysfs_leaf_symlink_refuses() {
    let mut work = Work::new(1_000_000);
    let (sys, id) = root("/sys", 0x62656572, &mut work, false).unwrap();
    let (genuine, _) = child(
        &sys,
        "devices/system/cpu/cpu0",
        OFlags::PATH | OFlags::DIRECTORY,
        id,
        DIR,
        &mut work,
        false,
    )
    .expect("required genuine CPU0 source positive");
    drop(genuine);
    let e = match child(
        &sys,
        "bus/cpu/devices/cpu0",
        OFlags::PATH | OFlags::DIRECTORY,
        id,
        DIR,
        &mut work,
        false,
    ) {
        Err(e) => e,
        Ok(_) => panic!("authentic symlink leaf accepted"),
    };
    assert_eq!(
        (e.kind(), e.stage(), e.raw_os_error()),
        (K::Unsupported, S::Admission, Some(libc::ELOOP))
    );
    println!("PASS genuine same-mount leaf positive and exact ELOOP symlink refusal");
}
