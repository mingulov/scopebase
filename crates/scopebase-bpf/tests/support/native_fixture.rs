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
    let _bounded_independent_ids = possible()?;
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
/// Pure cpulist parser core (S188): `None` on any malformed shape —
/// empty reads, truncated/inverted ranges, non-numeric content,
/// duplicate lanes or lanes past the 65536 physical bound. Never panics.
pub fn parse_cpulist(text: &str) -> Option<Vec<u32>> {
    let mut set = [false; 65536];
    for part in text.trim().split(',') {
        let mut ends = part.split('-');
        let lo: usize = ends.next()?.parse().ok()?;
        let hi: usize = match ends.next() {
            Some(v) => v.parse().ok()?,
            None => lo,
        };
        if ends.next().is_some() || lo > hi || hi >= 65536 {
            return None;
        }
        for slot in &mut set[lo..=hi] {
            if *slot {
                return None;
            }
            *slot = true;
        }
    }
    Some(
        set.iter()
            .enumerate()
            .filter_map(|(n, on)| on.then_some(n as u32))
            .collect(),
    )
}

fn malformed_cpulist(detail: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}

/// Possible-CPU ids from live sysfs. Missing `/sys` or malformed
/// content is an `io::Result` error; privileged call sites label it
/// `BLOCKED_ENVIRONMENT` via `expect`.
pub fn possible() -> io::Result<Vec<u32>> {
    let text = std::fs::read_to_string("/sys/devices/system/cpu/possible")?;
    parse_cpulist(&text).ok_or_else(|| malformed_cpulist("malformed possible cpulist"))
}

/// Require an SMP topology with at least one offline lane. Unmet
/// conditions are `BLOCKED_ENVIRONMENT` errors for the call site.
pub fn require_offline() -> io::Result<()> {
    let possible = possible()?;
    let online = std::fs::read_to_string("/sys/devices/system/cpu/online")?;
    let lanes = parse_cpulist(&online).ok_or_else(|| malformed_cpulist("malformed online cpulist"))?;
    if possible.len() < 2 {
        return Err(io::Error::other(
            "BLOCKED_ENVIRONMENT >=2 possible required",
        ));
    }
    if lanes.len() >= possible.len() {
        return Err(io::Error::other(
            "BLOCKED_ENVIRONMENT offline lane required",
        ));
    }
    Ok(())
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
#[cfg(test)]
mod tests {
    use super::parse_cpulist;

    #[test]
    fn cpulist_valid_shapes_parse() {
        assert_eq!(parse_cpulist("0"), Some(vec![0]));
        assert_eq!(parse_cpulist("0-3,8"), Some(vec![0, 1, 2, 3, 8]));
        assert_eq!(parse_cpulist("  1,4-5\n"), Some(vec![1, 4, 5]));
    }

    #[test]
    fn cpulist_malformed_refuses() {
        // S188: empty reads, truncated ranges, inverted ranges and
        // non-numeric content refuse instead of panicking.
        for malformed in ["", "0-", "3-0", "x", "0-1-2", "0,0", "65536", "0-999999"] {
            assert_eq!(parse_cpulist(malformed), None, "{malformed:?} refuses");
        }
    }
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
