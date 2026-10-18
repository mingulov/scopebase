// SPDX-License-Identifier: Apache-2.0
//! Compile-only pidfd signature. The function is never invoked.
#[allow(dead_code)]
fn pidfd_api(pid: rustix::process::Pid) -> rustix::io::Result<std::os::fd::OwnedFd> {
    rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
}
#[test]
fn pidfd_signature_is_available() {
    let _signature: fn(rustix::process::Pid) -> rustix::io::Result<std::os::fd::OwnedFd> =
        pidfd_api;
}
