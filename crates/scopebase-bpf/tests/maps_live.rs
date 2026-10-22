// SPDX-License-Identifier: Apache-2.0
// Required privileged cells. Explicit --ignored execution; absence is NOT_RUN.
#[path = "support/aggregate_fixture.rs"]
mod aggregate;
#[path = "support/native_fixture.rs"]
mod fixture;
#[path = "support/who_fixture.rs"]
mod who;
use scopebase_bpf::{
    ArtifactId, ErrorKind, LiveCpuTopology, MapBtfExpectation, Stage, ValidatedMap,
};
#[test]
#[ignore = "N1 requires admitted owned SMP/offline BPF resource"]
fn n1_geometry_activity() {
    fixture::require_offline();
    let ids = fixture::possible();
    for kind in [5, 6] {
        for size in [1, 7, 8, 9, 13, 88, 120] {
            let fd = fixture::create(kind, 4, size, 2, 0, None).unwrap();
            let backing = fixture::pattern(size as usize);
            fixture::update(&fd, &0u32.to_le_bytes(), &backing).unwrap();
            let mut map = ValidatedMap::from_owned_fd(
                fd,
                &fixture::expected(kind, 4, size as usize, 2, 0),
                &fixture::limits(),
            )
            .unwrap();
            assert_eq!(map.topology().ids(), ids);
            let extent = ids.len() * ((size as usize + 7) / 8 * 8);
            assert_eq!(map.geometry().buffer_len(), extent);
            let bytes = map.lookup(&0u32.to_le_bytes()).unwrap().unwrap();
            assert_eq!(bytes.len(), extent);
            for lane in 0..ids.len() {
                let stride = (size as usize + 7) / 8 * 8;
                assert_eq!(
                    &bytes[lane * stride..lane * stride + size as usize],
                    &backing[lane * stride..lane * stride + size as usize]
                );
            }
            let mut output = vec![0xa5; extent + 7];
            assert!(map.lookup_into(&0u32.to_le_bytes(), &mut output).unwrap());
            assert_eq!(&output[extent..], &[0xa5; 7]);
            let mut short = vec![0xa5; extent - 1];
            let e = map
                .lookup_into(&0u32.to_le_bytes(), &mut short)
                .unwrap_err();
            assert_eq!(e.required_size(), Some(extent));
            assert!(short.iter().all(|x| *x == 0xa5));
            if kind == 5 {
                let mut absent = vec![0xa5; extent + 7];
                assert!(!map.lookup_into(&99u32.to_le_bytes(), &mut absent).unwrap());
                assert!(absent.iter().all(|x| *x == 0xa5));
            }
        }
    }
}
#[test]
#[ignore = "N2 requires admitted owned BPF resource"]
fn n2_flags_metadata() {
    for kind in [5, 6] {
        let flags = if kind == 5 {
            vec![0, 1, 0x40, 0x80, 0x100]
        } else {
            vec![0, 0x80, 0x100]
        };
        for flag in flags {
            let fd = fixture::create(kind, 4, 8, 2, flag, None).unwrap();
            let expected = fixture::expected(kind, 4, 8, 2, flag);
            let mut map =
                ValidatedMap::from_owned_fd(fd.try_clone().unwrap(), &expected, &fixture::limits())
                    .unwrap();
            assert_eq!(map.metadata().flags, flag);
            map.lookup(&0u32.to_le_bytes()).unwrap();
            for bad in [
                fixture::expected(kind, 8, 8, 2, flag),
                fixture::expected(kind, 4, 9, 2, flag),
                fixture::expected(kind, 4, 8, 3, flag),
                fixture::expected(if kind == 5 { 6 } else { 5 }, 4, 8, 2, flag),
            ] {
                assert!(ValidatedMap::from_owned_fd(
                    fd.try_clone().unwrap(),
                    &bad,
                    &fixture::limits()
                )
                .is_err());
            }
            if flag == 0 {
                let missing = fixture::expected(kind, 4, 8, 2, 0x80);
                let e = match ValidatedMap::from_owned_fd(
                    fd.try_clone().unwrap(),
                    &missing,
                    &fixture::limits(),
                ) {
                    Err(e) => e,
                    Ok(_) => panic!("missing required flag accepted"),
                };
                assert_eq!(
                    (e.kind(), e.stage()),
                    (ErrorKind::Incompatible, Stage::Metadata)
                );
            }
            let unreadable = fixture::write_only(map.metadata().map_id).unwrap();
            let err = match ValidatedMap::from_owned_fd(unreadable, &expected, &fixture::limits()) {
                Err(e) => e,
                Ok(_) => panic!("write-only map accepted"),
            };
            assert_eq!(err.kind(), ErrorKind::Denied);
            assert!(err.raw_os_error().is_some());
        }
    }
}
#[test]
#[ignore = "N3 requires real BTF/map creation"]
fn n3_linked_btf() {
    let digest = ArtifactId([
        0xe1, 0x7f, 0x95, 0x29, 0x3a, 0x58, 0x59, 0x4a, 0x1f, 0xa2, 0x38, 0xc9, 0x77, 0x78, 0x77,
        0x8a, 0x8b, 0x2b, 0xe5, 0xab, 0x5, 0xa7, 0xb0, 0x1b, 0x2, 0x64, 0xea, 0x36, 0x54, 0xd9,
        0x25, 0xca,
    ]);
    // Literal digest is also checked by independent Python generator.
    let image = fixture::load_btf().unwrap();
    let e = match ValidatedMap::from_owned_fd(
        image.try_clone().unwrap(),
        &fixture::expected(6, 4, 8, 2, 0),
        &fixture::limits(),
    ) {
        Err(e) => e,
        Ok(_) => panic!("BTF FD accepted as map"),
    };
    assert!(matches!(
        e.kind(),
        ErrorKind::Incompatible | ErrorKind::Unsupported | ErrorKind::Backend
    ));
    let linked_maps = [
        (5, fixture::create(5, 4, 8, 2, 0, Some(&image)).unwrap()),
        (6, fixture::create(6, 4, 8, 2, 0, Some(&image)).unwrap()),
    ];
    drop(image);
    for (kind, fd) in linked_maps {
        let mut expected = fixture::expected(kind, 4, 8, 2, 0);
        expected.btf = Some(MapBtfExpectation {
            image: digest,
            key_type_id: 1,
            value_type_id: 2,
        });
        let mut map =
            ValidatedMap::from_owned_fd(fd.try_clone().unwrap(), &expected, &fixture::limits())
                .unwrap();
        map.lookup(&0u32.to_le_bytes()).unwrap();
        for wrong in [
            MapBtfExpectation {
                image: ArtifactId([0; 32]),
                key_type_id: 1,
                value_type_id: 2,
            },
            MapBtfExpectation {
                image: digest,
                key_type_id: 2,
                value_type_id: 2,
            },
        ] {
            expected.btf = Some(wrong);
            let e = match ValidatedMap::from_owned_fd(
                fd.try_clone().unwrap(),
                &expected,
                &fixture::limits(),
            ) {
                Err(e) => e,
                Ok(_) => panic!("wrong BTF accepted"),
            };
            assert_eq!(
                (e.kind(), e.stage()),
                (ErrorKind::Incompatible, Stage::BtfQuery)
            );
        }
    }
    let plain = fixture::create(6, 4, 8, 2, 0, None).unwrap();
    let mut expected = fixture::expected(6, 4, 8, 2, 0);
    expected.btf = Some(MapBtfExpectation {
        image: digest,
        key_type_id: 1,
        value_type_id: 2,
    });
    let e = match ValidatedMap::from_owned_fd(plain, &expected, &fixture::limits()) {
        Err(e) => e,
        Ok(_) => panic!("missing linked BTF accepted"),
    };
    assert_eq!(
        (e.kind(), e.stage()),
        (ErrorKind::Incompatible, Stage::BtfQuery)
    );
}
#[test]
#[ignore = "N4 real bloom and BPF map"]
fn n4_bloom_output() {
    let fd = fixture::create(30, 0, 8, 16, 0, None).unwrap();
    let e = match ValidatedMap::from_owned_fd(
        fd,
        &fixture::expected(5, 4, 8, 16, 0),
        &fixture::limits(),
    ) {
        Err(e) => e,
        Ok(_) => panic!("bloom accepted"),
    };
    assert_eq!(
        (e.kind(), e.stage()),
        (ErrorKind::Unsupported, Stage::Metadata)
    );
}
#[test]
#[ignore = "N5 real WHO/KAGG/KTOT/diagnostic maps"]
fn n5_who_consumers() {
    let fd = fixture::create(5, 16, 88, 2, 0, None).unwrap();
    let key = *include_bytes!("fixtures/bp02/kwho-key16.bin");
    let mut second = key;
    second[8..12].copy_from_slice(&4243u32.to_le_bytes());
    let mut raw = vec![0; 65536 * 88];
    raw[..176].copy_from_slice(include_bytes!("fixtures/bp02/who88-two-lanes.bin"));
    fixture::update(&fd, &key, &raw).unwrap();
    let mut second_row = raw.clone();
    second_row[56..64].copy_from_slice(&6u64.to_le_bytes());
    fixture::update(&fd, &second, &second_row).unwrap();
    let mut map =
        ValidatedMap::from_owned_fd(fd, &fixture::expected(5, 16, 88, 2, 0), &fixture::limits())
            .unwrap();
    let count = map.topology().count();
    let reports = who::report_rows(&[&key, &second], count, |k| {
        map.lookup(k).map_err(|e| e.to_string())
    })
    .unwrap();
    assert_eq!(reports.len(), 2);
    for (k, v) in reports {
        assert_eq!(
            (v.calls, v.uid, v.stack, v.tid, v.first_ns, v.last_ns),
            (if k.tgid == 4242 { 12 } else { 13 }, 0, 0, 101, 11, 44)
        );
    }
    let mut into = vec![0; count * 88];
    let reports = who::report_rows(&[&key, &second], count, |k| {
        let found = map.lookup_into(k, &mut into).map_err(|e| e.to_string())?;
        Ok(found.then(|| into.clone()))
    })
    .unwrap();
    assert_eq!(reports.len(), 2);
    let acquired = map.lookup(&key).unwrap().unwrap();
    let stale = acquired[..count * 80].to_vec();
    assert!(who::report_rows(&[&key], count, |_| Ok(Some(stale.clone()))).is_err());
    let mut missing = second;
    missing[8..12].copy_from_slice(&4244u32.to_le_bytes());
    assert!(who::report_rows(&[&key, &missing], count, |k| map
        .lookup(k)
        .map_err(|e| e.to_string()))
    .is_err());
    let expected_sum = (count as u64) * (count as u64 + 1) / 2;
    for (kind, keysize, size) in [(5, 260, 120), (6, 4, 120), (6, 4, 8)] {
        let fd = fixture::create(kind, keysize, size, 2, 0, None).unwrap();
        let key = vec![0; keysize as usize];
        let mut backing = vec![0; 65536 * size as usize];
        for lane in 0..count {
            backing[lane * size as usize..lane * size as usize + 8]
                .copy_from_slice(&(lane as u64 + 1).to_le_bytes());
        }
        fixture::update(&fd, &key, &backing).unwrap();
        let mut map = ValidatedMap::from_owned_fd(
            fd.try_clone().unwrap(),
            &fixture::expected(kind, keysize, size as usize, 2, 0),
            &fixture::limits(),
        )
        .unwrap();
        if size == 8 {
            assert_eq!(
                aggregate::diagnostic(count, |k| map.lookup(k).map_err(|e| e.to_string())).unwrap(),
                (1..=count as u64).collect::<Vec<_>>()
            );
            assert!(aggregate::diagnostic(count, |_| map
                .lookup(&99u32.to_le_bytes())
                .map_err(|e| e.to_string()))
            .is_err());
        } else if kind == 5 {
            let mut second_key = key.clone();
            second_key[259] = 1;
            let mut second_backing = backing.clone();
            for lane in 0..count {
                second_backing[lane * 120..lane * 120 + 8]
                    .copy_from_slice(&(lane as u64 + 2).to_le_bytes());
            }
            fixture::update(&fd, &second_key, &second_backing).unwrap();
            let rows = aggregate::walk(&[&key, &second_key], count, |k| {
                map.lookup(k).map_err(|e| e.to_string())
            })
            .unwrap();
            assert_eq!(
                (rows[0][0], rows[1][0]),
                (expected_sum, expected_sum + count as u64)
            );
            let mut missing = second_key;
            missing[258] = 1;
            assert!(aggregate::walk(&[&key, &missing], count, |k| map
                .lookup(k)
                .map_err(|e| e.to_string()))
            .is_err());
        } else {
            fixture::update(&fd, &1u32.to_le_bytes(), &backing).unwrap();
            assert_eq!(
                aggregate::totals(2, count, true, |k| map.lookup(k).map_err(|e| e.to_string()))
                    .unwrap()
                    .unwrap()[0],
                expected_sum * 2
            );
            assert!(aggregate::totals(3, count, true, |k| map
                .lookup(k)
                .map_err(|e| e.to_string()))
            .is_err());
            backing[..8].copy_from_slice(&u64::MAX.to_le_bytes());
            fixture::update(&fd, &0u32.to_le_bytes(), &backing).unwrap();
            assert_eq!(
                aggregate::totals(2, count, false, |k| map
                    .lookup(k)
                    .map_err(|e| e.to_string()))
                .unwrap()
                .unwrap()[0],
                u64::MAX
            );
            assert!(aggregate::totals(2, count, true, |k| map
                .lookup(k)
                .map_err(|e| e.to_string()))
            .is_err());
        }
    }
}
#[test]
#[ignore = "N9 retained aliases and repeated source views"]
fn n9_retention() {
    let fd = fixture::create(6, 4, 8, 2, 0, None).unwrap();
    let alias = fd.try_clone().unwrap();
    let backing = fixture::pattern(8);
    fixture::update(&alias, &0u32.to_le_bytes(), &backing).unwrap();
    let mut map =
        ValidatedMap::from_owned_fd(fd, &fixture::expected(6, 4, 8, 2, 0), &fixture::limits())
            .unwrap();
    let other = fixture::reuse_external_number(&alias).unwrap();
    fixture::update(&alias, &0u32.to_le_bytes(), &vec![0; 65536 * 8]).unwrap();
    drop(other);
    drop(alias);
    for _ in 0..20 {
        assert_eq!(
            &map.lookup(&0u32.to_le_bytes()).unwrap().unwrap()[..8],
            &backing[..8]
        );
    }
    let topology = LiveCpuTopology::acquire(&fixture::limits()).unwrap();
    assert_eq!(topology.snapshot().ids(), fixture::possible());
    topology.revalidate().unwrap();
}
#[derive(Debug)]
struct Guard {
    base: *mut u8,
    page: usize,
    active: bool,
    cleanup_attempted: bool,
}
#[derive(Debug)]
struct GuardFailure {
    stage: &'static str,
    primary_errno: i32,
    cleanup_errno: Option<i32>,
    base: usize,
    extent: usize,
    unresolved_owner: Option<Guard>,
    log_error: Option<String>,
}
fn unmap_guard(base: *mut u8, extent: usize) -> Result<(), i32> {
    // SAFETY: only the exact mapping retained by this private fixture owner.
    if unsafe { libc::munmap(base.cast(), extent) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    }
}
impl Guard {
    fn new() -> Self {
        Self::try_new_with(0, unmap_guard)
            .unwrap_or_else(|error| panic!("guard acquisition failed: {error:?}"))
    }
    fn try_new_with(
        protect_offset: usize,
        mut unmap: impl FnMut(*mut u8, usize) -> Result<(), i32>,
    ) -> Result<Self, GuardFailure> {
        // SAFETY: fixture owns a fresh two-page mapping, protects only its second page.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                8192,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(GuardFailure {
                stage: "mmap",
                primary_errno: std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
                cleanup_errno: None,
                base: 0,
                extent: 0,
                unresolved_owner: None,
                log_error: None,
            });
        }
        // Establish custody before the first fallible operation after mmap.
        let mut owner = Self {
            base: p.cast(),
            page: 4096,
            active: true,
            cleanup_attempted: false,
        };
        let protected = unsafe {
            libc::mprotect(
                owner.base.add(4096 + protect_offset).cast(),
                4096,
                libc::PROT_NONE,
            )
        };
        if protected != 0 {
            let primary_errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            let cleanup_errno = owner.close_with(&mut unmap).err();
            use std::io::Write;
            let log_error = writeln!(std::io::stdout().lock(), "BP02_GUARD_CUSTODY={{\"stage\":\"mprotect\",\"primary_errno\":{primary_errno},\"cleanup_errno\":{},\"base\":{},\"extent\":8192,\"cleanup_status\":\"{}\"}}", cleanup_errno.map_or_else(|| "null".into(), |errno| errno.to_string()), owner.base as usize, if owner.active { "UNRESOLVED" } else { "PASS" }).err().map(|error| error.to_string());
            return Err(GuardFailure {
                stage: "mprotect",
                primary_errno,
                cleanup_errno,
                base: owner.base as usize,
                extent: 8192,
                unresolved_owner: if owner.active { Some(owner) } else { None },
                log_error,
            });
        }
        unsafe { std::ptr::write_bytes(owner.base, 0xa5, 4096) };
        Ok(owner)
    }
    fn close_with(
        &mut self,
        mut unmap: impl FnMut(*mut u8, usize) -> Result<(), i32>,
    ) -> Result<(), i32> {
        self.cleanup_attempted = true;
        unmap(self.base, 8192)?;
        self.active = false;
        Ok(())
    }
    fn output(&mut self, len: usize) -> &mut [u8] {
        assert!(len + 16 <= self.page);
        // SAFETY: unique initialized in-bounds first-page suffix; second page is guard.
        unsafe { std::slice::from_raw_parts_mut(self.base.add(self.page - len), len) }
    }
    fn prefix(&self, len: usize) {
        assert!(len + 16 <= self.page);
        let bytes = unsafe { std::slice::from_raw_parts(self.base.add(self.page - len - 16), 16) };
        assert_eq!(bytes, &[0xa5; 16]);
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if !self.active || self.cleanup_attempted {
            return;
        }
        let result = self.close_with(unmap_guard);
        use std::io::Write;
        let logged = writeln!(std::io::stdout().lock(), "BP02_GUARD_CUSTODY={{\"stage\":\"munmap\",\"primary_errno\":null,\"cleanup_errno\":{},\"base\":{},\"extent\":8192,\"cleanup_status\":\"{}\"}}", result.err().map_or_else(|| "null".into(), |errno| errno.to_string()), self.base as usize, if self.active { "UNRESOLVED" } else { "PASS" });
        if (result.is_err() || logged.is_err()) && !std::thread::panicking() {
            panic!("UNRESOLVED guarded fixture mapping/log: {result:?} {logged:?}");
        }
    }
}
#[test]
fn guard_setup_failure_rolls_back_and_aligned_twin_closes_once() {
    let mut calls = Vec::new();
    let failure = Guard::try_new_with(1, |base, extent| {
        calls.push((base as usize, extent));
        unmap_guard(base, extent)
    })
    .unwrap_err();
    assert_eq!(
        (failure.stage, failure.primary_errno, failure.cleanup_errno),
        ("mprotect", libc::EINVAL, None)
    );
    assert_eq!(
        calls,
        vec![(failure.base, 8192)],
        "BP02_GUARD_SETUP_ROLLBACK"
    );
    assert!(failure.unresolved_owner.is_none());
    let mut positive = Guard::try_new_with(0, unmap_guard).unwrap();
    let address = positive.base as usize;
    let mut calls = Vec::new();
    positive
        .close_with(|base, extent| {
            calls.push((base as usize, extent));
            unmap_guard(base, extent)
        })
        .unwrap();
    drop(positive);
    assert_eq!(calls, vec![(address, 8192)]);
}
#[test]
fn guard_setup_and_rollback_errors_preserve_exact_owner() {
    let mut calls = Vec::new();
    let mut failure = Guard::try_new_with(1, |base, extent| {
        calls.push((base as usize, extent));
        Err(libc::EIO)
    })
    .unwrap_err();
    assert_eq!(
        (failure.stage, failure.primary_errno, failure.cleanup_errno),
        ("mprotect", libc::EINVAL, Some(libc::EIO))
    );
    assert_eq!(calls, vec![(failure.base, failure.extent)]);
    let owner = failure
        .unresolved_owner
        .as_mut()
        .expect("rollback failure must retain mapping owner");
    assert!(owner.active && owner.cleanup_attempted);
    // Independent test recovery of exactly the mapping still held by this error.
    unmap_guard(owner.base, 8192).unwrap();
    owner.active = false;
    drop(failure); // No second cleanup attempt or second panic.
    assert_eq!(calls.len(), 1);
}
#[test]
#[ignore = "N9 actual map output at protected page boundary"]
fn n9_guarded_output() {
    for kind in [5, 6] {
        for size in [1usize, 7, 8, 9, 13, 88, 120] {
            let fd = fixture::create(kind, 4, size as u32, 2, 0, None).unwrap();
            let pattern = fixture::pattern(size);
            fixture::update(&fd, &0u32.to_le_bytes(), &pattern).unwrap();
            let mut map = ValidatedMap::from_owned_fd(
                fd,
                &fixture::expected(kind, 4, size, 2, 0),
                &fixture::limits(),
            )
            .unwrap();
            let extent = map.geometry().buffer_len();
            for delta in [-1i32, 0, 1] {
                let n = (extent as i32 + delta) as usize;
                let mut guard = Guard::new();
                let r = map.lookup_into(&0u32.to_le_bytes(), guard.output(n));
                if delta < 0 {
                    assert_eq!(r.unwrap_err().required_size(), Some(extent));
                    assert!(guard.output(n).iter().all(|b| *b == 0xa5));
                } else {
                    assert!(r.unwrap());
                    if delta > 0 {
                        assert_eq!(guard.output(n)[extent], 0xa5);
                    }
                }
                guard.prefix(n);
            }
        }
    }
}
#[test]
#[ignore = "N9 full physical raw-copy canary and logical boundary control"]
fn n9_raw_guard() {
    let count = fixture::possible().len();
    assert!(count >= 2);
    for kind in [5, 6] {
        for size in [1usize, 7, 8, 9, 13, 88, 120] {
            let stride = (size + 7) / 8 * 8;
            let fd = fixture::create(kind, 4, size as u32, 2, 0, None).unwrap();
            fixture::update(&fd, &0u32.to_le_bytes(), &fixture::pattern(size)).unwrap();
            let extent = count * stride;
            let mut backing = vec![0xa5; 65536 * stride + 32];
            fixture::raw_full_copy(&fd, &0u32.to_le_bytes(), &mut backing).unwrap();
            assert_eq!(
                &backing[extent..extent + 16],
                &[0xa5; 16],
                "full physical backing canary"
            );
            let boundary = if std::env::var_os("SCOPEBASE_BP02_SHORT_LOGICAL_BOUNDARY").is_some() {
                extent - 1
            } else {
                extent
            };
            assert_eq!(
                &backing[boundary..boundary + 16],
                &[0xa5; 16],
                "raw logical-boundary sentinel"
            );
        }
    }
}
