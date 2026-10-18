// SPDX-License-Identifier: Apache-2.0
//! Test-only regular-file syscall API experiment; no HeldFile implementation.
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

    use rustix::{
        fs::{fcntl_getfl, fstat, fstatfs, open, openat, Mode, OFlags, PROC_SUPER_MAGIC},
        io::{fcntl_getfd, fcntl_setfd, pread, Errno, FdFlags},
    };
    use std::os::fd::{AsFd, OwnedFd};
    #[test]
    fn positional_read_preserves_cursor() {
        let fixture = Fixture::new();
        let fd = open(
            fixture.0.join("bytes"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let mut file = File::from(fd);
        file.seek(SeekFrom::Start(5)).unwrap();
        let alias = file.try_clone().unwrap();
        let mut bytes = [0; 3];
        assert_eq!(pread(alias.as_fd(), &mut bytes, 2).unwrap(), 3);
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
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let fd = openat(
            &dir,
            raw.as_os_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        assert!(fcntl_getfd(&fd).unwrap().contains(FdFlags::CLOEXEC));
        fcntl_setfd(&fd, FdFlags::empty()).unwrap();
        assert!(!fcntl_getfd(&fd).unwrap().contains(FdFlags::CLOEXEC));
        fcntl_setfd(&fd, FdFlags::CLOEXEC).unwrap();
        assert!(fcntl_getfl(&fd).unwrap().contains(OFlags::NONBLOCK));
        let stat = fstat(&fd).unwrap();
        let meta = std::fs::metadata(fixture.0.join(&raw)).unwrap();
        assert_eq!(stat.st_ino, meta.ino());
        assert_eq!(stat.st_dev, meta.dev());
        assert_eq!(stat.st_uid, meta.uid());
        let _filesystem = fstatfs(&fd).unwrap();
        let _proc_magic = PROC_SUPER_MAGIC;
        std::os::unix::fs::symlink("bytes", fixture.0.join("link")).unwrap();
        assert_eq!(
            openat(
                &dir,
                "link",
                OFlags::RDONLY | OFlags::NOFOLLOW,
                Mode::empty()
            )
            .unwrap_err(),
            Errno::LOOP
        );
        assert_eq!(
            openat(&dir, "absent", OFlags::RDONLY, Mode::empty()).unwrap_err(),
            Errno::NOENT
        );
    }
    #[test]
    fn valid_offset_boundary() {
        let fixture = Fixture::new();
        let file = File::open(fixture.0.join("bytes")).unwrap();
        let mut bytes = [0; 1];
        assert_eq!(pread(&file, &mut bytes, 7).unwrap(), 1);
        assert_eq!(bytes, [b'h']);
        assert_eq!(pread(&file, &mut bytes, 8).unwrap(), 0);
        assert_eq!(
            pread(&file, &mut bytes, u64::MAX).unwrap_err(),
            Errno::INVAL
        );
    }
}
