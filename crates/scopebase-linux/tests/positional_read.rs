// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::{
    control::OperationControl,
    error::{LimitKind, Reason, Stage},
    file::{ContentSnapshot, HeldFile, ProcFdResolver, ReadLimits, SymlinkPolicy},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn create_at_with(
        path: PathBuf,
        write: impl FnOnce(&mut File) -> std::io::Result<()>,
    ) -> std::io::Result<Self> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        let owner = Self(path);
        write(&mut file)?;
        Ok(owner)
    }
    fn new(bytes: &[u8]) -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "lx03-public-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match Self::create_at_with(path, |file| file.write_all(bytes)) {
                Ok(owner) => return owner,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("fixture creation: {e}"),
            }
        }
    }
    fn held(&self) -> HeldFile {
        HeldFile::from_file(File::open(&self.0).unwrap()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
// Exclusive directory ownership covers every rename/setup failure and both names.
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "lx03-dir-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("directory fixture: {e}"),
            }
        }
    }
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        path
    }
    fn replace_input_with(
        &self,
        bytes: &[u8],
        write: impl FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
    ) -> std::io::Result<PathBuf> {
        let source = self.0.join("input");
        let old = self.0.join("old");
        // Reserve the destination exclusively before rename may overwrite it.
        drop(OpenOptions::new().create_new(true).write(true).open(&old)?);
        fs::rename(&source, &old)?;
        let mut replacement = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(source)?;
        write(&mut replacement, bytes)?;
        Ok(old)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn with_public_readers(
    held: &Arc<HeldFile>,
    fail_first: bool,
    finished: Arc<std::sync::atomic::AtomicBool>,
    before_join: impl FnOnce(),
) -> Vec<scopebase_linux::file::FileRead> {
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..2)
            .map(|index| {
                let h = held.clone();
                let finished = finished.clone();
                scope.spawn(move || {
                    if fail_first && index == 0 {
                        panic!("injected first public reader failure");
                    }
                    let read = h
                        .read_all(limits(10), &OperationControl::unlimited())
                        .unwrap();
                    drop(h);
                    if index == 1 {
                        finished.store(true, Ordering::Release);
                    }
                    read
                })
            })
            .collect();
        before_join();
        // Collect every join before propagating any worker failure/assertion.
        let results: Vec<_> = workers.into_iter().map(|worker| worker.join()).collect();
        results.into_iter().map(|result| result.unwrap()).collect()
    })
}
fn limits(bytes: u64) -> ReadLimits {
    ReadLimits {
        max_bytes: bytes,
        max_read_calls: 100,
        max_buffer_capacity: 200_000,
    }
}
#[test]
fn shared_cursor_does_not_create_suffix_success() {
    let f = Fixture::new(b"0123456789");
    let mut input = File::open(&f.0).unwrap();
    input.seek(SeekFrom::Start(4)).unwrap();
    let mut alias = input.try_clone().unwrap();
    let held = Arc::new(HeldFile::from_file(input).unwrap());
    let mut two = [0; 2];
    alias.read_exact(&mut two).unwrap();
    assert_eq!(&two, b"45");
    let read = held
        .read_all(limits(10), &OperationControl::unlimited())
        .unwrap();
    assert_eq!(
        read.bytes(),
        b"0123456789",
        "positional reads must return literal full bytes"
    );
    assert_eq!(
        alias.stream_position().unwrap(),
        6,
        "read must preserve shared cursor"
    );
    for result in with_public_readers(
        &held,
        false,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        || {
            alias.seek(SeekFrom::Start(9)).unwrap();
        },
    ) {
        assert_eq!(result.bytes(), b"0123456789");
    }
    assert_eq!(alias.stream_position().unwrap(), 9);
}
#[test]
fn r14_caps_empty_and_huge_before_allocation() {
    for n in [0, 1, 64, 65] {
        let f = Fixture::new(&vec![0x7f; n]);
        let h = f.held();
        let result = h.read_all(
            ReadLimits {
                max_bytes: 64,
                max_buffer_capacity: 65,
                max_read_calls: 4,
            },
            &OperationControl::unlimited(),
        );
        if n <= 64 {
            let r = result.unwrap();
            assert_eq!(r.bytes(), &vec![0x7f; n]);
            assert_eq!(r.observations().before(), r.observations().after());
            assert_eq!(r.charges().read_calls(), if n == 0 { 1 } else { 2 });
        } else {
            let e = result.unwrap_err();
            assert_eq!(e.reason(), Reason::LimitExceeded(LimitKind::InputBytes));
            assert_eq!(e.charges().syscall_attempts(), 2);
            assert_eq!(e.charges().read().unwrap().requested_capacity(), 0);
        }
    }
    let empty = Fixture::new(b"");
    assert!(empty
        .held()
        .read_all(
            ReadLimits {
                max_bytes: 0,
                max_buffer_capacity: 1,
                max_read_calls: 1
            },
            &OperationControl::unlimited()
        )
        .unwrap()
        .bytes()
        .is_empty());
    let one = Fixture::new(b"x");
    assert_eq!(
        one.held()
            .read_all(limits(0), &OperationControl::unlimited())
            .unwrap_err()
            .reason(),
        Reason::LimitExceeded(LimitKind::InputBytes)
    );
    let sparse = Fixture::new(b"fixture");
    OpenOptions::new()
        .write(true)
        .open(&sparse.0)
        .unwrap()
        .set_len(1 << 40)
        .expect("real sparse fixture");
    assert_eq!(fs::metadata(&sparse.0).unwrap().len(), 1 << 40);
    let e = sparse
        .held()
        .read_all(limits(64), &OperationControl::unlimited())
        .unwrap_err();
    assert_eq!(e.stage(), Stage::ReadFile);
    assert_eq!(e.reason(), Reason::LimitExceeded(LimitKind::InputBytes));
    assert_eq!(e.charges().read().unwrap().read_calls(), 0);
}
#[test]
fn clone_keeps_one_payload_and_capacity() {
    for bytes in [b"PAYLOAD-CANARY".as_slice(), b""] {
        let f = Fixture::new(bytes);
        let held = f.held();
        let r = held
            .read_all(limits(100), &OperationControl::unlimited())
            .unwrap();
        let clone = r.clone();
        assert_eq!(
            clone.bytes().as_ptr(),
            r.bytes().as_ptr(),
            "clone shares payload allocation"
        );
        let c = r.charges();
        assert_eq!(c.requested_capacity(), bytes.len() + 1);
        assert!(c.granted_capacity() >= c.requested_capacity());
        assert_eq!(c.retained_capacity(), c.granted_capacity());
        assert_eq!(clone.charges(), c);
        drop(r);
        drop(held);
        assert_eq!(clone.bytes(), bytes);
        assert_eq!(
            clone.observations().content_snapshot(),
            ContentSnapshot::NotProven
        );
    }
}
#[test]
fn held_authority_survives_replacement_and_unlink() {
    let directory = Directory::new();
    let source = directory.write("input", b"ORIGINAL");
    let resolver = ProcFdResolver::open_self().unwrap();
    let h = HeldFile::open(&source, &resolver, SymlinkPolicy::Follow).unwrap();
    let old = directory
        .replace_input_with(b"NEW", |file, bytes| file.write_all(bytes))
        .unwrap();
    fs::remove_file(old).unwrap();
    assert_eq!(
        h.read_all(limits(16), &OperationControl::unlimited())
            .unwrap()
            .bytes(),
        b"ORIGINAL"
    );
    assert_eq!(fs::read(source).unwrap(), b"NEW");
}
#[test]
fn public_read_contract_is_private_and_bounded() {
    let f = Fixture::new(b"PAYLOAD-CANARY");
    let h = f.held();
    let token = scopebase_linux::control::CancelToken::new();
    token.cancel();
    let e = h
        .read_all(limits(100), &OperationControl::new(None, token))
        .unwrap_err();
    assert_eq!(e.reason(), Reason::Cancelled);
    assert_eq!(e.charges().read().unwrap().bytes_read(), 0);
    assert_eq!(e.charges().syscall_attempts(), 0);
    let r = h
        .read_all(limits(100), &OperationControl::unlimited())
        .unwrap();
    for s in [
        format!("{e}"),
        format!("{e:#?}"),
        format!("{r:?}"),
        format!("{:#?}", r.observations()),
        format!("{:#?}", r.charges()),
    ] {
        assert!(s.len() <= 256 && s.is_ascii());
        assert!(!s.contains("CANARY"));
    }
}

#[test]
fn fixture_setup_and_rename_failures_preserve_exclusive_paths() {
    let existing = Fixture::new(b"COLLISION-CANARY");
    let collision = Fixture::create_at_with(existing.0.clone(), |_| {
        panic!("writer must not run on collision")
    });
    assert_eq!(
        collision.err().unwrap().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(&existing.0).unwrap(), b"COLLISION-CANARY");
    let directory = Directory::new();
    let failed_path = directory.0.join("failed-write");
    let result = Fixture::create_at_with(failed_path.clone(), |file| {
        file.write_all(b"partial")?;
        Err(std::io::Error::other("injected write failure"))
    });
    assert!(result.is_err());
    assert!(
        !failed_path.exists(),
        "failed write must clean its exclusively created name"
    );
    let input = directory.write("input", b"ORIGINAL");
    let old = directory.write("old", b"SIBLING-CANARY");
    let collision = directory.replace_input_with(b"NEW", |f, b| f.write_all(b));
    assert_eq!(
        collision.unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        fs::read(&old).unwrap(),
        b"SIBLING-CANARY",
        "rename must preserve pre-existing sibling bytes"
    );
    assert_eq!(fs::read(&input).unwrap(), b"ORIGINAL");
    drop(directory);
    let directory = Directory::new();
    let root = directory.0.clone();
    directory.write("input", b"ORIGINAL");
    let failed = directory.replace_input_with(b"NEW", |f, _| {
        f.write_all(b"partial")?;
        Err(std::io::Error::other("replacement failed"))
    });
    assert!(failed.is_err());
    assert_eq!(fs::read(root.join("old")).unwrap(), b"ORIGINAL");
    drop(directory);
    assert!(
        !root.exists(),
        "directory owner must clean both renamed original and failed replacement"
    );
}
#[test]
fn public_reader_first_failure_joins_remaining_worker() {
    let f = Fixture::new(b"0123456789");
    let h = Arc::new(f.held());
    let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observe = finished.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_public_readers(&h, true, observe, || {})
    }));
    assert!(result.is_err());
    assert!(
        finished.load(Ordering::Acquire),
        "remaining worker must finish before first failure escapes"
    );
    assert_eq!(Arc::strong_count(&h), 1);
}
