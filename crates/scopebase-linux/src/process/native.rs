// SPDX-License-Identifier: Apache-2.0
// NEW narrow NS_GET_NSTYPE adapter: local rustix 1.1.5 exposes the generic
// `Ioctl` trait but no safe namespace-kind helper, so this one audited unsafe
// boundary returns the kernel's direct integer result for an actual newly
// acquired namespace handle only. No public raw-FD/ioctl route reaches it.
// ABI: Linux UAPI linux/nsfs.h NSIO=0xb7, NS_GET_NSTYPE=_IO(NSIO,0x3);
// CLONE_NEWPID=0x20000000, CLONE_NEWNS=0x00020000. Scope: Linux x86_64 GNU.
use rustix::io::Errno;
use rustix::ioctl::{opcode, Ioctl, IoctlOutput, Opcode};
use std::os::fd::{AsFd, BorrowedFd};

/// Expected kernel-confirmed namespace kinds (linux/nsfs.h + sched.h ABI).
pub(crate) const CLONE_NEWPID: i32 = 0x2000_0000;
pub(crate) const CLONE_NEWNS: i32 = 0x0002_0000;

/// nsfs magic from include/uapi/linux/magic.h (`NSFS_MAGIC 0x6e736673`).
/// rustix 1.1.5 has no nsfs constant; this literal is the UAPI value only.
pub(crate) const NSFS_MAGIC: i64 = 0x6e73_6673;

/// Direct-return ioctl descriptor: NS_GET_NSTYPE returns the kind integer as
/// the syscall result, not through pointed-to output. `NoArg` is wrong (it
/// discards the return); `Getter<i32>` is wrong (nothing is pointed to).
struct NamespaceKindQuery;

unsafe impl Ioctl for NamespaceKindQuery {
    type Output = i32;
    const IS_MUTATING: bool = false;
    fn opcode(&self) -> Opcode {
        opcode::none(0xb7, 0x03)
    }
    fn as_ptr(&mut self) -> *mut core::ffi::c_void {
        core::ptr::null_mut()
    }
    unsafe fn output_from_ptr(out: IoctlOutput, _: *mut core::ffi::c_void) -> Result<i32, Errno> {
        Ok(out)
    }
}

/// Query the kernel-confirmed kind of an acquired namespace handle. No retry,
/// fallback or state mutation; a failed ioctl retains its actual errno.
pub(crate) fn namespace_kind(handle: BorrowedFd<'_>) -> Result<i32, Errno> {
    // SAFETY: NS_GET_NSTYPE takes no operand, mutates neither handle nor
    // userspace, and returns the kind as the syscall result, which
    // `output_from_ptr` forwards without dereferencing any pointer. The
    // caller passes only an actual newly acquired namespace handle.
    unsafe { rustix::ioctl::ioctl(handle.as_fd(), NamespaceKindQuery) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::{Mode, OFlags};

    fn open_own(kind: &str) -> std::os::fd::OwnedFd {
        let path = format!("/proc/self/ns/{kind}");
        rustix::fs::open(
            path.as_str(),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open own namespace handle")
    }

    #[test]
    fn pid_and_mount_handles_report_kernel_kinds() {
        let _guard = crate::FD_TABLE.lock().unwrap();
        let pid = open_own("pid");
        let mnt = open_own("mnt");
        assert_eq!(namespace_kind(pid.as_fd()).unwrap(), CLONE_NEWPID);
        assert_eq!(namespace_kind(mnt.as_fd()).unwrap(), CLONE_NEWNS);
    }

    #[test]
    fn non_namespace_fd_keeps_actual_errno() {
        let _guard = crate::FD_TABLE.lock().unwrap();
        // A regular file is not a namespace: ENOTTY, preserved, not invented.
        let file = rustix::fs::open(
            "/proc/self/status",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let error = namespace_kind(file.as_fd()).unwrap_err();
        assert_eq!(error, Errno::NOTTY);
    }
}
