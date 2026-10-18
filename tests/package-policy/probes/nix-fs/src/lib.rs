// SPDX-License-Identifier: Apache-2.0
//! Test-only comparator; signed-offset conversion is not a production adapter.
#[cfg(test)]
mod tests {

    use std::{
        fs::File,
        io::{Read, Seek, SeekFrom},
        os::unix::{ffi::OsStringExt, fs::MetadataExt},
        path::PathBuf,
    };
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "sb02-fd-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("bytes"), b"abcdefgh").unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).expect("retire owned fixture");
        }
    }
    fn assert_positional(bytes: &[u8], cursor: u64) {
        assert_eq!(bytes, b"cde", "positional bytes");
        assert_eq!(
            cursor, 5,
            "shared cursor remains at independently selected position"
        );
    }
    #[test]
    fn wrong_cursor_control() {
        let fixture = Fixture::new();
        let mut file = File::open(fixture.0.join("bytes")).unwrap();
        file.seek(SeekFrom::Start(5)).unwrap();
        let mut bytes = [0; 3];
        file.read_exact(&mut bytes).unwrap(); // Deliberately wrong cursor-relative implementation.
        let cursor = file.stream_position().unwrap();
        assert_eq!(&bytes, b"fgh");
        assert_eq!(cursor, 8); // Valid setup, named mutation executed.
        assert!(std::panic::catch_unwind(|| assert_positional(&bytes, cursor)).is_err());
    }

    use nix::{
        errno::Errno,
        fcntl::{fcntl, open, openat, FcntlArg, OFlag},
        sys::{
            stat::{fstat, Mode},
            uio::pread,
        },
    };
    use std::os::fd::{AsFd, OwnedFd};
    fn checked_offset(value: u64) -> Option<nix::libc::off_t> {
        value.try_into().ok()
    }
    #[test]
    fn positional_read_preserves_cursor() {
        let fixture = Fixture::new();
        let fd = open(
            &fixture.0.join("bytes"),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let mut file = File::from(fd);
        file.seek(SeekFrom::Start(5)).unwrap();
        let alias = file.try_clone().unwrap();
        let mut bytes = [0; 3];
        assert_eq!(
            pread(alias.as_fd(), &mut bytes, checked_offset(2).unwrap()).unwrap(),
            3
        );
        assert_positional(&bytes, file.stream_position().unwrap());
        let _: OwnedFd = file.into();
    }
    #[test]
    fn flags_raw_path_owner_and_error() {
        let fixture = Fixture::new();
        let raw = std::ffi::OsString::from_vec(vec![b'r', 0xff]);
        std::fs::write(fixture.0.join(&raw), b"raw").unwrap();
        let dir = open(
            &fixture.0,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let fd = openat(
            &dir,
            raw.as_os_str(),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        assert_ne!(
            fcntl(&fd, FcntlArg::F_GETFD).unwrap() & nix::libc::FD_CLOEXEC,
            0
        );
        assert_ne!(
            fcntl(&fd, FcntlArg::F_GETFL).unwrap() & OFlag::O_NONBLOCK.bits(),
            0
        );
        let stat = fstat(&fd).unwrap();
        let meta = std::fs::metadata(fixture.0.join(&raw)).unwrap();
        assert_eq!(stat.st_ino, meta.ino());
        assert_eq!(stat.st_dev, meta.dev());
        assert_eq!(stat.st_uid, meta.uid());
        std::os::unix::fs::symlink("bytes", fixture.0.join("link")).unwrap();
        assert_eq!(
            openat(
                &dir,
                "link",
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW,
                Mode::empty()
            )
            .unwrap_err(),
            Errno::ELOOP
        );
        assert_eq!(
            openat(&dir, "absent", OFlag::O_RDONLY, Mode::empty()).unwrap_err(),
            Errno::ENOENT
        );
    }
    #[test]
    fn checked_offset_boundaries() {
        assert_eq!(checked_offset(i64::MAX as u64), Some(i64::MAX));
        assert_eq!(checked_offset(i64::MAX as u64 + 1), None);
        assert_eq!(checked_offset(u64::MAX), None);
        let fixture = Fixture::new();
        let file = File::open(fixture.0.join("bytes")).unwrap();
        let mut bytes = [0; 1];
        assert_eq!(
            pread(&file, &mut bytes, checked_offset(7).unwrap()).unwrap(),
            1
        );
        assert_eq!(bytes, [b'h']);
        assert_eq!(
            pread(&file, &mut bytes, checked_offset(8).unwrap()).unwrap(),
            0
        );
    }
    #[test]
    fn wrapping_offset_control() {
        let input = i64::MAX as u64 + 1;
        let wrapped = Some(input as nix::libc::off_t);
        assert_eq!(wrapped, Some(i64::MIN));
        assert!(std::panic::catch_unwind(|| assert_eq!(
            wrapped, None,
            "out-of-range offset must refuse before syscall"
        ))
        .is_err());
    }
}
