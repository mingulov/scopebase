// SPDX-License-Identifier: Apache-2.0
//! The only production unsafe boundary. No caller-injectable raw syscall API.
use super::{budget::Work, error, handle::ValidatedMap};
use crate::{ErrorKind as K, OperationError, Stage as S};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
pub(super) fn os_error(errno: i32, stage: S) -> OperationError {
    let kind = match errno {
        libc::EPERM | libc::EACCES => K::Denied,
        libc::ENOSYS | libc::EOPNOTSUPP => K::Unsupported,
        libc::ENOENT => K::Disappeared,
        _ => K::Backend,
    };
    OperationError::new(kind, stage, Some(errno), None)
}
fn call(
    command: u32,
    attr: &mut [u8],
    stage: S,
    work: &mut Work,
) -> Result<libc::c_long, OperationError> {
    work.charge(1, stage)?;
    #[cfg(test)]
    CALLS.with(|c| {
        let mut counts = c.get();
        counts[match command {
            15 => 0,
            4 => 1,
            1 => 2,
            _ => 3,
        }] += 1;
        c.set(counts);
    });
    // SAFETY: every private caller supplies exactly the initialized Linux ABI
    // attribute and live, initialized pointees for this synchronous syscall.
    // Each command-specific wrapper documents the output extent proof.
    let r = unsafe { libc::syscall(libc::SYS_bpf, command, attr.as_mut_ptr(), attr.len()) };
    if r < 0 {
        // SAFETY: libc's thread-local errno location is valid; capture immediately.
        let errno = unsafe { *libc::__errno_location() };
        Err(os_error(errno, stage))
    } else {
        Ok(r)
    }
}
fn zero(r: libc::c_long, stage: S) -> Result<(), OperationError> {
    if r == 0 {
        Ok(())
    } else {
        Err(error(K::Backend, stage))
    }
}
pub(super) fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
pub(super) fn u32at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("fixed field"))
}
pub(super) fn u64at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("fixed field"))
}
fn fd_number(fd: &OwnedFd) -> Result<u32, OperationError> {
    u32::try_from(fd.as_raw_fd()).map_err(|_| error(K::Overflow, S::Admission))
}
fn info(fd: &OwnedFd, out: &mut [u8], stage: S, work: &mut Work) -> Result<usize, OperationError> {
    let mut a = [0u8; 16];
    put32(&mut a, 0, fd_number(fd)?);
    put32(
        &mut a,
        4,
        u32::try_from(out.len()).map_err(|_| error(K::Overflow, stage))?,
    );
    put64(&mut a, 8, out.as_mut_ptr() as u64);
    // OBJ_GET_INFO limits its write to initialized out.len(), including for a
    // nonmap object. Returned info_len is checked by command-specific callers.
    zero(call(15, &mut a, stage, work)?, stage)?;
    Ok(u32at(&a, 4) as usize)
}
/// Only native map_info can construct this witness; metadata is immutable for fd.
pub(super) struct MapInfo<'a> {
    fd: &'a OwnedFd,
    bytes: [u8; 88],
    len: usize,
}
impl MapInfo<'_> {
    pub(super) fn bytes(&self) -> &[u8; 88] {
        &self.bytes
    }
    pub(super) fn len(&self) -> usize {
        self.len
    }
}
pub(super) fn map_info<'a>(
    fd: &'a OwnedFd,
    work: &mut Work,
) -> Result<MapInfo<'a>, OperationError> {
    work.charge(88, S::Metadata)?;
    let mut bytes = [0; 88];
    let len = info(fd, &mut bytes, S::Metadata, work)?;
    if !(76..=88).contains(&len) {
        return Err(error(K::Incompatible, S::Metadata));
    }
    work.charge(88, S::Metadata)?;
    Ok(MapInfo { fd, bytes, len })
}
pub(super) fn key_witness(
    info: &MapInfo<'_>,
    scratch: &mut [u8],
    work: &mut Work,
) -> Result<(), OperationError> {
    // Only handle construction calls this after map_info validation, before
    // constructing any public owner. Nonmaps fail __bpf_map_get before output;
    // actual maps write exactly their immutable key_size checked here.
    if !matches!(u32at(&info.bytes, 0), 5 | 6) || scratch.len() != u32at(&info.bytes, 8) as usize {
        return Err(error(K::Backend, S::Metadata));
    }
    let mut a = [0u8; 24];
    put32(&mut a, 0, fd_number(info.fd)?);
    put64(&mut a, 16, scratch.as_mut_ptr() as u64);
    match call(4, &mut a, S::Metadata, work) {
        Ok(r) => zero(r, S::Metadata),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        Err(e) => Err(e),
    }
}
pub(super) fn btf_fd(id: u32, work: &mut Work) -> Result<OwnedFd, OperationError> {
    let mut a = id.to_le_bytes();
    let n = call(19, &mut a, S::BtfQuery, work)?;
    let n = i32::try_from(n).map_err(|_| error(K::Backend, S::BtfQuery))?;
    // SAFETY: successful BTF_GET_FD_BY_ID returned a newly owned, nonnegative fd.
    Ok(unsafe { OwnedFd::from_raw_fd(n) })
}
pub(super) fn btf_info(
    fd: &OwnedFd,
    data: Option<&mut [u8]>,
    work: &mut Work,
) -> Result<[u8; 32], OperationError> {
    work.charge(32, S::BtfQuery)?;
    let mut out = [0; 32];
    if let Some(data) = data {
        put64(&mut out, 0, data.as_mut_ptr() as u64);
        put32(
            &mut out,
            8,
            u32::try_from(data.len()).map_err(|_| error(K::Overflow, S::BtfQuery))?,
        );
    }
    // BTF info copies min(supplied length, immutable object size), never more.
    let len = info(fd, &mut out, S::BtfQuery, work)?;
    if len != 32 {
        return Err(error(K::Incompatible, S::BtfQuery));
    }
    work.charge(32, S::BtfQuery)?;
    Ok(out)
}
pub(super) fn lookup(
    map: &ValidatedMap,
    key: &[u8],
    out: &mut [u8],
    work: &mut Work,
) -> Result<bool, OperationError> {
    // SAFE EXTENT PROOF: map is constructible only from its held fd's actual
    // metadata, real-map witness, authentic held global possible mask and
    // admitted immutable-mask Linux ABI. Parsed caller topology never enters
    // this route. Its fixed geometry stays valid across mount substitution.
    // Both owners and initialized exact full scratch are borrowed for the call.
    if key.len() != map.metadata.key_size as usize || out.len() != map.geometry.buffer_len() {
        return Err(error(K::Backend, S::Read));
    }
    let mut a = [0u8; 32];
    put32(&mut a, 0, fd_number(&map.fd)?);
    put64(&mut a, 8, key.as_ptr() as u64);
    put64(&mut a, 16, out.as_mut_ptr() as u64);
    match call(1, &mut a, S::Read, work) {
        Ok(r) => {
            zero(r, S::Read)?;
            Ok(true)
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(e) => Err(e),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bad_fd_byte_ops_report_stage_and_errno() {
        for command in [1, 4] {
            let mut a = [0; 32];
            put32(&mut a, 0, u32::MAX);
            let e = call(
                command,
                &mut a[..if command == 1 { 32 } else { 24 }],
                S::Read,
                &mut Work::new(1),
            )
            .unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::EBADF));
            assert_eq!(e.stage(), S::Read);
        }
    }
}
#[cfg(test)]
#[path = "../../tests/support/native_fixture.rs"]
mod live_fixture;
#[cfg(test)]
#[path = "../../tests/support/task_fixture.rs"]
pub(super) mod task_fixture;
#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::{ErrorKind, ValidatedMap};
    #[test]
    #[ignore = "N7 actual postvalidation suppression in explicitly owned mount namespace"]
    fn source_replaced_after_precheck_suppresses_output() {
        // SAFETY: test thread enters its own mount namespace; no host namespace change.
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
        assert_eq!(
            unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            },
            0
        );
        let fd = live_fixture::create(6, 4, 8, 2, 0, None).unwrap();
        live_fixture::update(&fd, &0u32.to_le_bytes(), &live_fixture::pattern(8)).unwrap();
        let mut map = ValidatedMap::from_owned_fd(
            fd,
            &live_fixture::expected(6, 4, 8, 2, 0),
            &live_fixture::limits(),
        )
        .unwrap();
        super::super::handle::BEFORE_VALUE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                // SAFETY: only the current owned test namespace receives this fake root.
                assert_eq!(
                    unsafe {
                        libc::mount(
                            std::ptr::null(),
                            c"/sys".as_ptr(),
                            c"tmpfs".as_ptr(),
                            0,
                            std::ptr::null(),
                        )
                    },
                    0
                );
            }))
        });
        let mut out = vec![0xa5; map.geometry().buffer_len() + 8];
        let r = map.lookup_into(&0u32.to_le_bytes(), &mut out);
        // SAFETY: detach exactly the test-created top mount in the owned namespace.
        assert_eq!(unsafe { libc::umount2(c"/sys".as_ptr(), 0) }, 0);
        let e = r.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Changed);
        assert!(out.iter().all(|b| *b == 0xa5));
        assert_eq!(
            map.lookup(&0u32.to_le_bytes()).unwrap_err().kind(),
            ErrorKind::Poisoned
        );
    }
}

#[cfg(test)]
thread_local! {static CALLS:std::cell::Cell<[usize;4]>=const{std::cell::Cell::new([0;4])};}
#[cfg(test)]
mod call_order_live_tests {
    use super::*;
    use crate::{ErrorKind, Stage, ValidatedMap};
    fn reset() {
        CALLS.with(|c| c.set([0; 4]));
        super::super::budget::ALLOCATIONS.with(|c| c.set(0));
        super::super::provenance::QUERIES.with(|c| c.set(0));
    }
    #[test]
    #[ignore = "N4 actual permitted metadata query and forbidden downstream counters"]
    fn bloom_and_argument_call_order() {
        let bloom = live_fixture::create(30, 0, 8, 16, 0, None).unwrap();
        reset();
        let e = match ValidatedMap::from_owned_fd(
            bloom,
            &live_fixture::expected(5, 4, 8, 16, 0),
            &live_fixture::limits(),
        ) {
            Err(e) => e,
            Ok(_) => panic!("bloom accepted"),
        };
        assert_eq!(
            (e.kind(), e.stage()),
            (ErrorKind::Unsupported, Stage::Metadata)
        );
        CALLS.with(|c| assert_eq!(c.get(), [1, 0, 0, 0]));
        super::super::budget::ALLOCATIONS.with(|c| assert_eq!(c.get(), 0));
        super::super::provenance::QUERIES.with(|c| assert_eq!(c.get(), 0));
        let fd = live_fixture::create(6, 4, 8, 2, 0, None).unwrap();
        live_fixture::update(&fd, &0u32.to_le_bytes(), &live_fixture::pattern(8)).unwrap();
        let mut map = ValidatedMap::from_owned_fd(
            fd,
            &live_fixture::expected(6, 4, 8, 2, 0),
            &live_fixture::limits(),
        )
        .unwrap();
        let mut out = vec![0xa5; map.geometry().buffer_len()];
        reset();
        let e = map.lookup_into(&[0; 3], &mut out).unwrap_err();
        assert_eq!(
            (e.kind(), e.stage()),
            (ErrorKind::InvalidInput, Stage::Admission)
        );
        assert!(out.iter().all(|b| *b == 0xa5));
        CALLS.with(|c| assert_eq!(c.get(), [0; 4]));
        super::super::provenance::QUERIES.with(|c| assert_eq!(c.get(), 0));
        let len = out.len();
        let e = map.lookup_into(&[0; 4], &mut out[..len - 1]).unwrap_err();
        assert_eq!(e.required_size(), Some(len));
        CALLS.with(|c| assert_eq!(c.get(), [0; 4]));
        super::super::provenance::QUERIES.with(|c| assert_eq!(c.get(), 0));
        assert!(map.lookup_into(&[0; 4], &mut out).unwrap());
        CALLS.with(|c| assert_eq!(c.get(), [0, 0, 1, 0]));
        println!(
            "PASS bloom metadata1 downstream0; wrong-key/short output queries0; restored value1"
        );
    }
}
