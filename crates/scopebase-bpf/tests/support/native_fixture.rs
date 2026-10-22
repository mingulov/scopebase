// SPDX-License-Identifier: Apache-2.0
//! Test-only privileged map/BTF fixture. Never used to supply library authority.
#![allow(dead_code)]
use scopebase_bpf::{Limits, MapExpectation, ValueLayout};
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
pub fn limits() -> Limits {
    Limits {
        input_bytes: 32 << 20,
        retained_bytes: 64 << 20,
        work_steps: 100_000_000,
        sites: 0,
        live_links: 0,
        pending_retirements: 0,
    }
}
pub fn put(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn ptr(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
fn call(cmd: u32, a: &mut [u8]) -> io::Result<i64> {
    // SAFETY: this test module initializes exact attributes and owns each pointee
    // through synchronous calls. Every caller documents its input/output extent.
    let r = unsafe { libc::syscall(libc::SYS_bpf, cmd, a.as_mut_ptr(), a.len()) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}
fn adopt(n: i64) -> OwnedFd {
    assert!(n >= 0 && n <= i32::MAX as i64);
    // SAFETY: a successful fixture creation/query returns a fresh owned fd.
    unsafe { OwnedFd::from_raw_fd(n as i32) }
}
pub fn create(
    kind: u32,
    key: u32,
    value: u32,
    max: u32,
    flags: u32,
    btf: Option<&OwnedFd>,
) -> io::Result<OwnedFd> {
    let mut a = [0; 72];
    for (o, v) in [(0, kind), (4, key), (8, value), (12, max), (16, flags)] {
        put(&mut a, o, v);
    }
    if let Some(fd) = btf {
        put(&mut a, 48, fd.as_raw_fd() as u32);
        put(&mut a, 52, 1);
        put(&mut a, 56, 2);
    }
    call(0, &mut a).map(adopt)
}
pub fn load_btf() -> io::Result<OwnedFd> {
    let bytes = include_bytes!("../fixtures/bp02/btf-u32-u64.bin");
    let mut a = [0; 32];
    ptr(&mut a, 0, bytes.as_ptr() as u64);
    put(&mut a, 16, bytes.len() as u32);
    call(18, &mut a).map(adopt)
}
pub fn write_only(id: u32) -> io::Result<OwnedFd> {
    let mut a = [0; 12];
    put(&mut a, 0, id);
    put(&mut a, 8, 16);
    call(14, &mut a).map(adopt)
}
pub fn update(fd: &OwnedFd, key: &[u8], backing: &[u8]) -> io::Result<()> {
    let _bounded_independent_ids = possible();
    let mut a = [0; 32];
    put(&mut a, 0, fd.as_raw_fd() as u32);
    ptr(&mut a, 8, key.as_ptr() as u64);
    ptr(&mut a, 16, backing.as_ptr() as u64);
    // backing has conservative maximum65,536-lane storage for exact map stride;
    // kernel update reads only its actual possible lanes. No subject geometry used.
    call(2, &mut a).map(|_| ())
}
pub fn expected(kind: u32, key: u32, size: usize, max: u32, flags: u32) -> MapExpectation {
    MapExpectation {
        map_type: kind,
        key_size: key,
        value: ValueLayout {
            size,
            alignment: 1,
            schema: [0; 32],
        },
        max_entries: max,
        required_flags: flags,
        btf: None,
    }
}
pub fn possible() -> Vec<u32> {
    let s = std::fs::read_to_string("/sys/devices/system/cpu/possible")
        .expect("fixture possible setup");
    let mut set = [false; 65536];
    for part in s.trim().split(',') {
        let mut ends = part.split('-');
        let lo: usize = ends.next().unwrap().parse().unwrap();
        let hi: usize = ends.next().map(|v| v.parse().unwrap()).unwrap_or(lo);
        assert!(ends.next().is_none() && lo <= hi && hi < 65536);
        for slot in &mut set[lo..=hi] {
            assert!(!*slot);
            *slot = true;
        }
    }
    set.iter()
        .enumerate()
        .filter_map(|(n, on)| on.then_some(n as u32))
        .collect()
}
pub fn require_offline() {
    let p = possible();
    let online = std::fs::read_to_string("/sys/devices/system/cpu/online").unwrap();
    assert!(p.len() >= 2, "BLOCKED_ENVIRONMENT >=2 possible required");
    let count = online
        .trim()
        .split(',')
        .map(|s| {
            let mut e = s.split('-');
            let lo: usize = e.next().unwrap().parse().unwrap();
            e.next()
                .map(|v| v.parse::<usize>().unwrap() - lo + 1)
                .unwrap_or(1)
        })
        .sum::<usize>();
    assert!(count < p.len(), "BLOCKED_ENVIRONMENT offline lane required");
}
pub fn pattern(value: usize) -> Vec<u8> {
    let stride = (value + 7) / 8 * 8;
    let mut out = vec![0; 65536 * stride];
    for (slot, bytes) in out.chunks_exact_mut(stride).enumerate() {
        for (j, b) in bytes.iter_mut().enumerate() {
            *b = (17 + slot * 19 + j) as u8;
        }
    }
    out
}
/// Raw fixture copy always has full conservative physical backing. The logical
/// sentinel boundary is test data and never a kernel allocation limit.
pub fn raw_full_copy(fd: &OwnedFd, key: &[u8], backing: &mut [u8]) -> io::Result<()> {
    let mut a = [0; 32];
    put(&mut a, 0, fd.as_raw_fd() as u32);
    ptr(&mut a, 8, key.as_ptr() as u64);
    ptr(&mut a, 16, backing.as_mut_ptr() as u64);
    call(1, &mut a).map(|_| ())
}
pub fn reuse_external_number(fd: &OwnedFd) -> io::Result<OwnedFd> {
    let number = fd.as_raw_fd();
    // SAFETY: replace only the exact externally held alias with another owned map
    // reference, keeping that alias's Rust owner and the original map's private FD.
    let other = create(6, 4, 8, 2, 0, None)?;
    let ret = unsafe { libc::dup3(other.as_raw_fd(), number, libc::O_CLOEXEC) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    assert_eq!(ret, number);
    Ok(other)
}
