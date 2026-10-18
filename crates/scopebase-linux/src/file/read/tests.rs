// SPDX-License-Identifier: Apache-2.0
//! R01–R15: original selected P/O regressions plus ratified bounds/control seams.
use super::*;
use crate::{control::CancelToken, FD_TABLE};
use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
type EventHook = Box<dyn FnMut(Point) -> Option<Instant> + Send>;
type FaultHook = Box<dyn FnMut(Call) -> Option<Errno> + Send>;
type StatHook = Box<dyn FnMut(bool, &mut fs::Stat) + Send>;
type ReadHook = Box<dyn FnMut(&HeldFile, &mut [u8], u64) -> Result<usize, Errno> + Send>;
type ReserveHook =
    Box<dyn FnMut(usize) -> Result<Vec<u8>, std::collections::TryReserveError> + Send>;
#[derive(Default)]
pub(super) struct Hooks {
    pub flags: Option<OFlags>,
    pub initialized: Vec<usize>,
    pub event: Option<EventHook>,
    pub fault: Option<FaultHook>,
    pub stat: Option<StatHook>,
    pub read: Option<ReadHook>,
    pub reserve: Option<ReserveHook>,
    pub calls: Vec<Call>,
    pub reads: Vec<(u64, usize, Option<usize>)>,
    pub reservations: Vec<(usize, usize, usize)>,
    pub points: Vec<Point>,
}
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        loop {
            let p = std::env::temp_dir().join(format!(
                "lx03-unit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match OpenOptions::new().write(true).create_new(true).open(&p) {
                Ok(mut f) => {
                    f.write_all(bytes).unwrap();
                    return Self(p);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("fixture: {e}"),
            }
        }
    }
    fn held(&self) -> HeldFile {
        HeldFile::from_file(File::open(&self.0).unwrap()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}
fn limits() -> ReadLimits {
    ReadLimits {
        max_bytes: 200_000,
        max_buffer_capacity: 200_001,
        max_read_calls: 32,
    }
}
fn run(h: &HeldFile, l: ReadLimits, o: &mut ReadOps) -> Result<FileRead, LinuxError> {
    read_all_with(h, l, &OperationControl::unlimited(), o)
}
fn refusal(e: &LinuxError, reason: Reason, calls: u64, bytes: u64, sys: u64, done: u64) {
    assert_eq!(e.stage(), Stage::ReadFile);
    assert_eq!(e.reason(), reason, "semantic refusal");
    let c = e.charges().read().unwrap();
    assert_eq!(
        (c.read_calls(), c.bytes_read(), c.retained_capacity()),
        (calls, bytes, 0),
        "read work must not be refunded"
    );
    assert_eq!(
        (
            e.effect().attempted_operations(),
            e.charges().syscall_attempts(),
            e.effect().completed_operations()
        ),
        (sys, sys, done),
        "exact incurred syscall prefix"
    );
    assert_eq!(
        (
            e.charges().fd_acquisitions(),
            e.charges().peak_new_fds(),
            e.effect().target_mappings_created(),
            e.effect().target_mappings_retired()
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(e.effect().cleanup(), CleanupDisposition::NotNeeded);
    assert_eq!(
        e.effect().descriptor_flags(),
        DescriptorFlagEffect::NotAttempted
    );
}
#[test]
fn an_early_zero_read_is_rejected_as_a_short_read() {
    let _guard = FD_TABLE.lock().unwrap();
    let f = Fixture::new(b"0123456789");
    let h = f.held();
    let mut o = ReadOps::default();
    o.hooks.read = Some(Box::new(|_, _, _| Ok(0)));
    let e = run(&h, limits(), &mut o).unwrap_err();
    refusal(&e, Reason::ChangedSource, 1, 0, 3, 3);
    assert_eq!(
        o.hooks.calls.len(),
        3,
        "early zero stops before retry/final stat"
    );
}
#[test]
fn short_positive_reads_advance_only_local_offset() {
    let _guard = FD_TABLE.lock().unwrap();
    let f = Fixture::new(b"0123456789");
    let h = f.held();
    let mut o = ReadOps::default();
    let mut sizes = VecDeque::from([2, 3, 5, 1]);
    o.hooks.read = Some(Box::new(move |h, b, off| {
        let n = sizes.pop_front().expect("finite read script").min(b.len());
        io::pread(h, &mut b[..n], off)
    }));
    let r = run(&h, limits(), &mut o).unwrap();
    assert_eq!(
        r.bytes(),
        b"0123456789",
        "short reads preserve literal payload"
    );
    assert_eq!(
        o.hooks.reads,
        [
            (0, 11, Some(2)),
            (2, 9, Some(3)),
            (5, 6, Some(5)),
            (10, 1, Some(0))
        ]
    );
    let mut o = ReadOps::default();
    let path = f.0.clone();
    o.hooks.event = Some(Box::new(move |p| {
        if p == Point::AfterGetFl {
            OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(0)
                .unwrap();
        }
        None
    }));
    refusal(
        &run(&h, limits(), &mut o).unwrap_err(),
        Reason::ChangedSource,
        1,
        0,
        3,
        3,
    );
}
#[test]
fn r14_caps_empty_and_huge_before_allocation() {
    let _guard = FD_TABLE.lock().unwrap();
    let small = Fixture::new(&[0x7f; 65]);
    let small_h = small.held();
    let mut small_ops = ReadOps::default();
    let e = run(
        &small_h,
        ReadLimits {
            max_bytes: 64,
            max_buffer_capacity: 128,
            ..limits()
        },
        &mut small_ops,
    )
    .unwrap_err();
    refusal(&e, Reason::LimitExceeded(LimitKind::InputBytes), 0, 0, 2, 2);
    assert!(
        small_ops.hooks.reservations.is_empty(),
        "cap refuses before reservation"
    );
    assert!(small_ops.hooks.reads.is_empty(), "cap refuses before read");

    let f = Fixture::new(b"sparse");
    OpenOptions::new()
        .write(true)
        .open(&f.0)
        .unwrap()
        .set_len(1 << 40)
        .expect("real sparse setup");
    let h = f.held();
    assert_eq!(h.stat().unwrap().len(), 1 << 40);
    let mut o = ReadOps::default();
    let e = run(&h, limits(), &mut o).unwrap_err();
    refusal(&e, Reason::LimitExceeded(LimitKind::InputBytes), 0, 0, 2, 2);
    assert!(
        o.hooks.reservations.is_empty(),
        "cap refuses before reservation"
    );
    assert!(o.hooks.reads.is_empty(), "cap refuses before read");
}
#[test]
fn growth_requires_positive_sentinel() {
    let _guard = FD_TABLE.lock().unwrap();
    for cap in [64, 128] {
        for stable_stat in [true, false] {
            let f = Fixture::new(&[0x7f; 64]);
            let h = f.held();
            let initial = fs::fstat(&h).unwrap();
            let path = f.0.clone();
            let mut o = ReadOps::default();
            o.hooks.event = Some(Box::new(move |p| {
                if p == Point::AfterInitialStat {
                    OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .unwrap()
                        .write_all(&[0x33; 6])
                        .unwrap();
                }
                None
            }));
            if stable_stat {
                o.hooks.stat = Some(Box::new(move |_, s| *s = initial));
            }
            let e = run(
                &h,
                ReadLimits {
                    max_bytes: cap,
                    ..limits()
                },
                &mut o,
            )
            .unwrap_err();
            refusal(
                &e,
                if cap == 64 {
                    Reason::LimitExceeded(LimitKind::InputBytes)
                } else {
                    Reason::ChangedSource
                },
                1,
                65,
                3,
                3,
            );
            assert_eq!(
                o.hooks.reads,
                [(0, 65, Some(65))],
                "positive sentinel stops at initial length plus one"
            );
        }
    }
}
#[test]
fn final_identity_and_size_changes_refuse() {
    let _guard = FD_TABLE.lock().unwrap();
    let f = Fixture::new(&[0x7f; 64]);
    let h = f.held();
    for mutation in 0..5 {
        let mut o = ReadOps::default();
        o.hooks.stat = Some(Box::new(move |final_stat, s| {
            if final_stat {
                match mutation {
                    0 => s.st_dev ^= 1,
                    1 => s.st_ino ^= 1,
                    2 => s.st_size += 1,
                    3 => s.st_mode = 0,
                    4 => s.st_mtime_nsec = 1_000_000_000,
                    _ => unreachable!(),
                }
            }
        }));
        let e = run(&h, limits(), &mut o).unwrap_err();
        refusal(
            &e,
            if mutation == 4 {
                Reason::Malformed
            } else {
                Reason::ChangedSource
            },
            2,
            64,
            5,
            5,
        );
    }
    let mut o = ReadOps::default();
    let r = run(&h, limits(), &mut o).unwrap();
    assert_eq!(r.observations().before(), h.stat().unwrap());
    assert_eq!(r.observations().before(), r.observations().after());
    assert_eq!(r.bytes(), &[0x7f; 64]);
    assert_eq!(
        o.hooks.calls,
        [
            Call::InitialStat,
            Call::GetFl,
            Call::Read(0),
            Call::Read(1),
            Call::FinalStat
        ]
    );
}
#[test]
fn raced_file_read_is_discarded_clean_sibling_survives() {
    let _guard = FD_TABLE.lock().unwrap();
    let clean = Fixture::new(b"CLEAN");
    let clean_h = clean.held();
    assert_eq!(
        run(&clean_h, limits(), &mut ReadOps::default())
            .unwrap()
            .bytes(),
        b"CLEAN"
    );
    for which in 0..3 {
        let f = Fixture::new(b"AAAAAAAAAA");
        let h = f.held();
        let initial = fs::fstat(&h).unwrap();
        let path = f.0.clone();
        let mut o = ReadOps::default();
        o.hooks.event = Some(Box::new(move |p| {
            if p == Point::AfterRead(0) {
                OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .write_all(b"BBBBBBBBBB")
                    .unwrap();
            }
            None
        }));
        o.hooks.read = Some(Box::new(|h, b, off| {
            let n = b.len().min(5);
            io::pread(h, &mut b[..n], off)
        }));
        if which < 2 {
            o.hooks.stat = Some(Box::new(move |last, s| {
                *s = initial;
                if last {
                    if which == 0 {
                        s.st_mtime += 1
                    } else {
                        s.st_ctime += 1
                    }
                }
            }));
        }
        let e = run(&h, limits(), &mut o).unwrap_err();
        refusal(&e, Reason::ChangedSource, 3, 10, 6, 6);
        if which == 2 {
            let actual = fs::fstat(&h).unwrap();
            assert_ne!(
                (
                    actual.st_mtime,
                    actual.st_mtime_nsec,
                    actual.st_ctime,
                    actual.st_ctime_nsec
                ),
                (
                    initial.st_mtime,
                    initial.st_mtime_nsec,
                    initial.st_ctime,
                    initial.st_ctime_nsec
                ),
                "real same-size mutation metadata observed"
            );
        }
    }
    let f = Fixture::new(b"AAAAAAAAAA");
    let h = f.held();
    let initial = fs::fstat(&h).unwrap();
    let path = f.0.clone();
    let mut o = ReadOps::default();
    o.hooks.read = Some(Box::new(|h, b, off| {
        let n = b.len().min(5);
        io::pread(h, &mut b[..n], off)
    }));
    o.hooks.event = Some(Box::new(move |p| {
        if p == Point::AfterRead(0) {
            OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .write_all(b"BBBBBBBBBB")
                .unwrap();
        }
        None
    }));
    o.hooks.stat = Some(Box::new(move |_, s| *s = initial));
    let r = run(&h, limits(), &mut o).unwrap();
    assert_eq!(
        r.bytes(),
        b"AAAAABBBBB",
        "identical metadata can hide torn content"
    );
    assert_eq!(
        r.observations().content_snapshot(),
        ContentSnapshot::NotProven,
        "metadata never proves snapshot"
    );
}
#[test]
fn clone_keeps_one_payload_and_capacity() {
    let _guard = FD_TABLE.lock().unwrap();
    for bytes in [b"payload".as_slice(), b""] {
        let f = Fixture::new(bytes);
        let h = f.held();
        let mut o = ReadOps::default();
        let r = run(&h, limits(), &mut o).unwrap();
        assert_eq!(
            o.hooks.reservations.len(),
            1,
            "exactly one payload reservation"
        );
        let (requested, granted, ptr) = o.hooks.reservations[0];
        assert_eq!(requested, bytes.len() + 1);
        assert_eq!(
            r.bytes().as_ptr() as usize,
            ptr,
            "publication does not relocate payload"
        );
        assert_eq!(r.charges().granted_capacity(), granted);
        let clone = r.clone();
        assert_eq!(
            r.bytes().as_ptr(),
            clone.bytes().as_ptr(),
            "clone shares payload allocation"
        );
        drop(r);
        drop(h);
        assert_eq!(clone.bytes(), bytes);
    }
}
#[test]
fn eintr_budget_counts_every_attempt() {
    let _guard = FD_TABLE.lock().unwrap();
    let f = Fixture::new(b"x");
    let h = f.held();
    for budget in [3, 4] {
        let mut o = ReadOps::default();
        o.hooks.fault = Some(Box::new(|call| {
            if matches!(call, Call::Read(0 | 1)) {
                Some(Errno::INTR)
            } else {
                None
            }
        }));
        let result = run(
            &h,
            ReadLimits {
                max_read_calls: budget,
                ..limits()
            },
            &mut o,
        );
        if budget == 4 {
            let r = result.unwrap();
            assert_eq!(r.bytes(), b"x");
            assert_eq!(r.charges().read_calls(), 4);
        } else {
            refusal(
                &result.unwrap_err(),
                Reason::LimitExceeded(LimitKind::ReadCalls),
                3,
                1,
                5,
                3,
            );
        }
        assert_eq!(
            o.hooks.reads.len(),
            budget as usize,
            "EINTR consumes every actual read attempt"
        );
    }
    let mut o = ReadOps::default();
    o.hooks.fault = Some(Box::new(|call| match call {
        Call::Read(n) if n < 8 => Some(Errno::INTR),
        Call::Read(_) => Some(Errno::IO),
        _ => None,
    }));
    let e = run(
        &h,
        ReadLimits {
            max_read_calls: 3,
            ..limits()
        },
        &mut o,
    )
    .unwrap_err();
    refusal(&e, Reason::LimitExceeded(LimitKind::ReadCalls), 3, 0, 5, 2);
    assert_eq!(
        o.hooks.reads.len(),
        3,
        "finite negative guard must not be reached"
    );
}
#[test]
fn work_budget_allows_exact_ceiling_and_rejects_overflow() {
    let mut o = ReadOps::default();
    for _ in 0..4 {
        o.charge_read(4).unwrap();
    }
    assert_eq!(o.charge_read(4), Err(LimitKind::ReadCalls));
    assert_eq!(o.read.read_calls, 4);
    o.read.read_calls = u64::MAX;
    assert_eq!(o.charge_read(u64::MAX), Err(LimitKind::ReadCalls));
    o.read.read_calls = 0;
    o.attempted = u64::MAX;
    assert_eq!(o.charge_read(4), Err(LimitKind::ReadCalls));
    assert_eq!(o.read.read_calls, 0, "checked charge is atomic on overflow");
}
#[test]
fn control_before_effect_and_after_success() {
    let _guard = FD_TABLE.lock().unwrap();
    let f = Fixture::new(b"0123456789");
    let h = f.held();
    let points = [
        (Point::Entry, 0, 0, 0, 0),
        (Point::AfterInitialStat, 1, 1, 0, 0),
        (Point::AfterGetFl, 2, 2, 0, 0),
        (Point::AfterReserve, 2, 2, 0, 0),
        (Point::AfterInit(0), 2, 2, 0, 0),
        (Point::AfterRead(0), 3, 3, 1, 10),
        (Point::AfterRead(1), 4, 4, 2, 10),
        (Point::AfterFinalStat, 5, 5, 2, 10),
        (Point::BeforeArc, 5, 5, 2, 10),
        (Point::Publish, 5, 5, 2, 10),
    ];
    for (point, sys, done, calls, bytes) in points {
        for deadline in [false, true] {
            let token = CancelToken::new();
            let signal = token.clone();
            let now = Instant::now();
            let at = now + Duration::from_secs(10);
            let control = OperationControl::with_test_deadline(at, token);
            let mut o = ReadOps::default();
            o.test_now = Some(now);
            o.hooks.event = Some(Box::new(move |p| {
                if p == point {
                    if deadline {
                        Some(at)
                    } else {
                        signal.cancel();
                        None
                    }
                } else {
                    None
                }
            }));
            let e = read_all_with(&h, limits(), &control, &mut o).unwrap_err();
            refusal(
                &e,
                if deadline {
                    Reason::Deadline
                } else {
                    Reason::Cancelled
                },
                calls,
                bytes,
                sys,
                done,
            );
            assert_eq!(
                o.hooks.calls.len(),
                sys as usize,
                "checkpoint stops following syscall"
            );
            assert_eq!(
                o.hooks.points.last(),
                Some(&point),
                "checkpoint stops following CPU/publication effect"
            );
            let c = e.charges().read().unwrap();
            if matches!(
                point,
                Point::Entry | Point::AfterInitialStat | Point::AfterGetFl
            ) {
                assert_eq!((c.requested_capacity(), c.granted_capacity()), (0, 0));
                assert!(o.hooks.reservations.is_empty());
            } else {
                assert_eq!(c.requested_capacity(), 11);
                assert!(c.granted_capacity() >= 11);
            }
        }
    }
    let token = CancelToken::new();
    token.cancel();
    let now = Instant::now();
    let c = OperationControl::with_test_deadline(now, token);
    let mut o = ReadOps::default();
    o.test_now = Some(now);
    refusal(
        &read_all_with(&h, limits(), &c, &mut o).unwrap_err(),
        Reason::Cancelled,
        0,
        0,
        0,
        0,
    );
}
#[test]
fn primary_errno_survives_concurrent_stop() {
    let _guard = FD_TABLE.lock().unwrap();
    let f = Fixture::new(b"x");
    let h = f.held();
    for (call, sys, done, calls, bytes) in [
        (Call::InitialStat, 1, 0, 0, 0),
        (Call::GetFl, 2, 1, 0, 0),
        (Call::Read(0), 3, 2, 1, 0),
        (Call::Read(1), 4, 3, 2, 1),
        (Call::FinalStat, 5, 4, 2, 1),
    ] {
        for (errno, reason) in [
            (Errno::ACCESS, Reason::Denied),
            (Errno::IO, Reason::Inconclusive),
            (Errno::INVAL, Reason::Inconclusive),
            (Errno::INTR, Reason::Inconclusive),
        ] {
            let token = CancelToken::new();
            let signal = token.clone();
            let c = OperationControl::new(None, token);
            let mut o = ReadOps::default();
            o.hooks.fault = Some(Box::new(move |actual| {
                if actual == call {
                    signal.cancel();
                    Some(errno)
                } else {
                    None
                }
            }));
            let e = read_all_with(&h, limits(), &c, &mut o).unwrap_err();
            refusal(&e, reason, calls, bytes, sys, done);
            assert_eq!(
                e.source().unwrap().raw_os_error(),
                Some(errno.raw_os_error()),
                "failed syscall remains primary"
            );
            assert_eq!(
                o.hooks.calls.len(),
                sys as usize,
                "no call after primary failure"
            );
        }
    }
}
#[test]
fn capacity_allocation_and_overflow_are_distinct() {
    let _guard = FD_TABLE.lock().unwrap();
    let f = Fixture::new(b"x");
    let h = f.held();
    for l in [
        ReadLimits {
            max_read_calls: 0,
            ..limits()
        },
        ReadLimits {
            max_read_calls: u64::MAX,
            ..limits()
        },
        ReadLimits {
            max_read_calls: u64::MAX - 2,
            ..limits()
        },
        ReadLimits {
            max_buffer_capacity: 0,
            ..limits()
        },
    ] {
        let mut o = ReadOps::default();
        refusal(
            &run(&h, l, &mut o).unwrap_err(),
            Reason::InvalidInput,
            0,
            0,
            0,
            0,
        );
        assert!(o.hooks.calls.is_empty());
        assert!(o.hooks.reservations.is_empty());
    }
    let broad = ReadLimits {
        max_read_calls: u64::MAX - 3,
        max_bytes: u64::MAX,
        max_buffer_capacity: usize::MAX,
    };
    assert_eq!(
        run(&h, broad, &mut ReadOps::default()).unwrap().bytes(),
        b"x"
    );
    for size in [u64::MAX, isize::MAX as u64, i64::MAX as u64 + 1] {
        assert_eq!(
            admit_size(size, broad),
            Err(LimitKind::BufferCapacity),
            "overflow refuses before allocation"
        );
    }
    assert_eq!(
        admit_size(isize::MAX as u64 - 1, broad),
        Ok((isize::MAX as usize - 1, isize::MAX as usize))
    );
    assert_eq!(admit_size(u64::MAX, limits()), Err(LimitKind::InputBytes));
    assert_eq!(
        admit_size(
            2,
            ReadLimits {
                max_buffer_capacity: 2,
                ..limits()
            }
        ),
        Err(LimitKind::BufferCapacity)
    );
    let mut o = ReadOps::default();
    o.hooks.reserve = Some(Box::new(|_| {
        let mut v = Vec::<u8>::new();
        v.try_reserve_exact(usize::MAX).map(|_| v)
    }));
    let e = run(&h, limits(), &mut o).unwrap_err();
    refusal(&e, Reason::Allocation, 0, 0, 2, 2);
    let c = e.charges().read().unwrap();
    assert_eq!(
        (c.requested_capacity(), c.granted_capacity()),
        (2, 0),
        "allocation failure preserves requested history"
    );
    assert!(e.source().is_none());
    let mut o = ReadOps::default();
    o.hooks.reserve = Some(Box::new(|_| {
        let mut v = Vec::new();
        v.try_reserve_exact(16)?;
        Ok(v)
    }));
    let e = run(
        &h,
        ReadLimits {
            max_buffer_capacity: 2,
            ..limits()
        },
        &mut o,
    )
    .unwrap_err();
    refusal(
        &e,
        Reason::LimitExceeded(LimitKind::BufferCapacity),
        0,
        0,
        2,
        2,
    );
    assert_eq!(
        e.charges().read().unwrap().granted_capacity(),
        16,
        "overgrant remains historical"
    );
    assert!(
        !o.hooks.points.contains(&Point::BeforeInit(0)),
        "overgrant refuses before initialization"
    );
}
#[test]
fn requests_never_exceed_64k_or_initial_plus_one() {
    let _guard = FD_TABLE.lock().unwrap();
    for n in [65535, 65536, 65537, 131072] {
        let bytes: Vec<u8> = (0..n).map(|i| ((i * 17 + 3) % 251) as u8).collect();
        let f = Fixture::new(&bytes);
        let h = f.held();
        let mut o = ReadOps::default();
        let r = run(&h, limits(), &mut o).unwrap();
        assert_eq!(r.bytes(), bytes);
        let mut initialized = 0;
        for end in &o.hooks.initialized {
            assert!(
                *end - initialized <= 65536,
                "initialization must be at most 64 KiB"
            );
            initialized = *end;
        }
        assert_eq!(
            initialized,
            n + 1,
            "only requested payload plus sentinel initialized"
        );
        let mut offset = 0;
        for (off, request, got) in &o.hooks.reads {
            assert_eq!(*off, offset);
            assert!(
                *request > 0 && *request <= 65536,
                "request must be at most 64 KiB"
            );
            assert!(
                *off + *request as u64 <= n as u64 + 1,
                "request stays inside initial length plus sentinel"
            );
            offset += got.unwrap() as u64;
        }
        assert_eq!(offset, n as u64);
        assert_eq!(
            o.hooks.reads.last(),
            Some(&(n as u64, 1, Some(0))),
            "success requires actual EOF"
        );
    }
    assert_eq!(checked_offset(i64::MAX as u64), Some(i64::MAX as u64));
    assert_eq!(
        checked_offset(i64::MAX as u64 + 1),
        None,
        "signed offsets refuse wrapping"
    );
}
#[test]
fn read_errors_keep_original_authority() {
    let _guard = FD_TABLE.lock().unwrap();
    let f = Fixture::new(b"0123456789");
    let mut file = File::open(&f.0).unwrap();
    file.seek(SeekFrom::Start(4)).unwrap();
    let mut alias = file.try_clone().unwrap();
    let h = HeldFile::from_file(file).unwrap();
    let key = h.stat().unwrap().key();
    let mut o = ReadOps::default();
    o.hooks.fault = Some(Box::new(|c| {
        if c == Call::Read(0) {
            Some(Errno::IO)
        } else {
            None
        }
    }));
    let e = run(&h, limits(), &mut o).unwrap_err();
    refusal(&e, Reason::Inconclusive, 1, 0, 3, 2);
    assert_eq!(h.stat().unwrap().key(), key);
    let mut bytes = [0; 10];
    assert_eq!(io::pread(&h, &mut bytes[..], 0).unwrap(), 10);
    assert_eq!(&bytes, b"0123456789", "original authority survives failure");
    assert_eq!(alias.stream_position().unwrap(), 4);
    assert_eq!(
        run(&h, limits(), &mut ReadOps::default()).unwrap().bytes(),
        b"0123456789"
    );
}
#[test]
fn malformed_backend_result_and_stat_refuse() {
    let _guard = FD_TABLE.lock().unwrap();
    let f = Fixture::new(b"x");
    let h = f.held();
    let mut o = ReadOps::default();
    o.hooks.read = Some(Box::new(|_, b, _| Ok(b.len() + 1)));
    let e = run(&h, limits(), &mut o).unwrap_err();
    assert_eq!(e.reason(), Reason::Malformed);
    for regular in [false, true] {
        let mut o = ReadOps::default();
        o.hooks.stat = Some(Box::new(move |_, s| {
            if regular {
                s.st_size = -1
            } else {
                s.st_mode = 0
            }
        }));
        let e = run(&h, limits(), &mut o).unwrap_err();
        refusal(
            &e,
            if regular {
                Reason::Malformed
            } else {
                Reason::NonRegular
            },
            0,
            0,
            1,
            1,
        );
        assert!(o.hooks.reservations.is_empty());
    }
}
// Also retain watchdog child custody if a fixture/setup assertion unwinds.
struct OwnedChild(std::process::Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
#[test]
fn blocked_read_is_not_cancelled_until_return() {
    if std::env::var_os("LX03_BLOCK_CHILD").is_none() {
        let _guard = FD_TABLE.lock().unwrap();
        let mut child = OwnedChild(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "file::read::tests::blocked_read_is_not_cancelled_until_return",
                    "--nocapture",
                ])
                .env("LX03_BLOCK_CHILD", "1")
                .spawn()
                .unwrap(),
        );
        let stop = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(s) = child.0.try_wait().unwrap() {
                assert!(s.success(), "owned blocking child must pass");
                break;
            }
            if Instant::now() >= stop {
                child.0.kill().unwrap();
                child.0.wait().unwrap();
                panic!("watchdog fired; owned child killed/reaped");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        return;
    }
    let _guard = FD_TABLE.lock().unwrap();
    for deadline in [false, true] {
        let f = Fixture::new(b"x");
        let h = f.held();
        let token = CancelToken::new();
        let signal = token.clone();
        let now = Instant::now();
        let at = now + Duration::from_secs(1);
        let control = OperationControl::with_test_deadline(at, token);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let expire = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let clock = expire.clone();
        let worker = std::thread::spawn(move || {
            let mut o = ReadOps::default();
            o.test_now = Some(now);
            o.hooks.read = Some(Box::new(move |h, b, off| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                io::pread(h, b, off)
            }));
            o.hooks.event = Some(Box::new(move |_| {
                if clock.load(Ordering::Acquire) {
                    Some(at)
                } else {
                    None
                }
            }));
            let e = read_all_with(&h, limits(), &control, &mut o).unwrap_err();
            done_tx.send(e).unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        if deadline {
            expire.store(true, Ordering::Release)
        } else {
            signal.cancel();
        }
        let pending = done_rx.recv_timeout(Duration::from_millis(30));
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        assert!(
            matches!(pending, Err(std::sync::mpsc::RecvTimeoutError::Timeout)),
            "synchronous read retains custody until explicit release"
        );
        let e = done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        refusal(
            &e,
            if deadline {
                Reason::Deadline
            } else {
                Reason::Cancelled
            },
            1,
            1,
            3,
            3,
        );
    }
}

#[test]
fn read_readability_and_errno_classification_are_stage_local() {
    let _guard = FD_TABLE.lock().unwrap();
    let f = Fixture::new(b"x");
    let h = f.held();
    for flags in [OFlags::PATH, OFlags::WRONLY, OFlags::ACCMODE] {
        let mut o = ReadOps::default();
        o.hooks.flags = Some(flags);
        let e = run(&h, limits(), &mut o).unwrap_err();
        refusal(&e, Reason::Unreadable, 0, 0, 2, 2);
        assert!(o.hooks.reservations.is_empty());
    }
    for (errno, want) in [
        (Errno::PERM, Reason::Denied),
        (Errno::ACCESS, Reason::Denied),
        (Errno::NOSYS, Reason::Unavailable),
        (Errno::OPNOTSUPP, Reason::Unavailable),
        (Errno::MFILE, Reason::Unavailable),
        (Errno::NFILE, Reason::Unavailable),
        (Errno::NOMEM, Reason::Unavailable),
        (Errno::NOENT, Reason::Disappeared),
        (Errno::STALE, Reason::Disappeared),
        (Errno::BADF, Reason::Inconclusive),
        (Errno::INVAL, Reason::Inconclusive),
        (Errno::OVERFLOW, Reason::Inconclusive),
        (Errno::SPIPE, Reason::Inconclusive),
        (Errno::INTR, Reason::Inconclusive),
    ] {
        let e = ReadOps::default().errno(errno);
        assert_eq!(e.reason(), want);
        assert_eq!(
            e.source().unwrap().raw_os_error(),
            Some(errno.raw_os_error())
        );
    }
}
#[test]
fn read_diagnostics_omit_source_and_payload() {
    let o = ReadOps::default();
    for kind in [
        LimitKind::InputBytes,
        LimitKind::ReadCalls,
        LimitKind::BufferCapacity,
    ] {
        let e = o.error(
            Reason::LimitExceeded(kind),
            Some(std::io::Error::other("CANARY\n\x1b".repeat(10_000))),
        );
        for label in [format!("{e}"), format!("{e:?}"), format!("{e:#?}")] {
            assert!(label.len() <= 256 && label.is_ascii());
            assert!(label.bytes().all(|b| (0x20..=0x7e).contains(&b)));
            assert!(!label.contains("CANARY"));
        }
    }
}
#[test]
fn shared_cursor_advances_at_read_barriers_without_suffix_success() {
    let _guard = FD_TABLE.lock().unwrap();
    let f = Fixture::new(b"0123456789");
    let mut original = File::open(&f.0).unwrap();
    original.seek(SeekFrom::Start(4)).unwrap();
    let mut alias = original.try_clone().unwrap();
    let h = Arc::new(HeldFile::from_file(original).unwrap());
    let enter = Arc::new(std::sync::Barrier::new(3));
    let release = Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let h = h.clone();
        let enter = enter.clone();
        let release = release.clone();
        workers.push(std::thread::spawn(move || {
            let mut o = ReadOps::default();
            o.hooks.event = Some(Box::new(move |p| {
                if p == Point::BeforeRead(0) {
                    enter.wait();
                    release.wait();
                }
                None
            }));
            run(&h, limits(), &mut o).unwrap()
        }));
    }
    enter.wait();
    alias.seek(SeekFrom::Start(7)).unwrap();
    release.wait();
    for worker in workers {
        assert_eq!(
            worker.join().unwrap().bytes(),
            b"0123456789",
            "alias movement cannot create suffix success"
        );
    }
    assert_eq!(
        alias.stream_position().unwrap(),
        7,
        "library never moves shared cursor"
    );
}
