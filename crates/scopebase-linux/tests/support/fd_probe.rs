// SPDX-License-Identifier: Apache-2.0
//! Single-purpose exec/retirement fixture. No unrelated FD opens before checks.
use scopebase_linux::file::{HeldFile, ProcFdResolver};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::fs::{FileExt, MetadataExt},
    },
    path::Path,
    sync::Arc,
};
fn slot_flags(fd: i32) -> std::io::Result<i32> {
    unsafe extern "C" {
        fn fcntl(fd: std::ffi::c_int, cmd: std::ffi::c_int, ...) -> std::ffi::c_int;
    }
    // F_GETFD accepts an invalid integer slot. A BorrowedFd would require it open.
    let result = unsafe { fcntl(fd, 1) };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result)
    }
}
pub fn exec_check(value: &str) {
    let v: Vec<u64> = value.split(' ').map(|s| s.parse().unwrap()).collect();
    // Neither environment parsing nor these fstats allocate another descriptor.
    let owner_result = slot_flags(v[0] as i32);
    let canary_result = slot_flags(v[1] as i32);
    assert_eq!(
        owner_result
            .expect_err("owner must close across exec")
            .raw_os_error(),
        Some(9),
        "owner must close across exec"
    );
    canary_result.unwrap();
    // The canary slot is independently known open and no concurrent work exists.
    let canary = unsafe { BorrowedFd::borrow_raw(v[1] as i32) };
    let c = rustix::fs::fstat(canary).unwrap();
    assert_eq!(
        (c.st_dev as u64, c.st_ino as u64),
        (v[2], v[3]),
        "deliberate non-CLOEXEC canary must survive"
    );
}
pub fn retirement_check(path: &Path) {
    let r = ProcFdResolver::open_self().unwrap();
    let original = File::open(path).unwrap();
    let truth = original.metadata().unwrap();
    let alias = original.try_clone().unwrap();
    let owner = Arc::new(HeldFile::from_file(original).unwrap());
    let fd = owner.as_fd().as_raw_fd();
    let twin = Arc::clone(&owner);
    std::fs::remove_file(path).unwrap();
    drop(owner);
    assert_eq!(twin.stat().unwrap().key().inode(), truth.ino());
    drop(twin);
    // This process has no other test threads; inspect the exact retired slot
    // before any further descriptor allocation, while the independent alias lives.
    let closed = slot_flags(fd);
    assert_eq!(
        closed.unwrap_err().raw_os_error(),
        Some(9),
        "original owner must release exactly its slot"
    );
    let mut bytes = [0u8; 1];
    alias.read_exact_at(&mut bytes, 0).unwrap();
    assert_eq!(&bytes, b"A");
}
#[allow(dead_code)]
fn main() {
    if let Some(value) = std::env::var_os("LX02_EXEC") {
        exec_check(value.to_str().unwrap());
    } else {
        retirement_check(Path::new(
            &std::env::var_os("LX02_RETIRE").expect("fixture mode"),
        ));
    }
}
