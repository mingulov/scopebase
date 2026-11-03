// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::{
    control::OperationControl,
    error::{LimitKind, Reason},
    file::{ContentSnapshot, HeldFile, ReadLimits},
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
};
struct Remove(PathBuf);
impl Drop for Remove {
    fn drop(&mut self) {
        // S211: never panic in drop (see held_file.rs Fixture).
        let _ = std::fs::remove_file(&self.0);
    }
}
fn main() {
    let path = std::env::temp_dir().join(format!("lx03-adopted-{}", std::process::id()));
    let mut source = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let _remove = Remove(path);
    source.write_all(b"0123456789").unwrap();
    source.seek(SeekFrom::Start(4)).unwrap();
    let mut alias = source.try_clone().unwrap();
    let held = HeldFile::from_file(source).unwrap();
    let mut two = [0; 2];
    alias.read_exact(&mut two).unwrap();
    assert_eq!(&two, b"45");
    let limits = ReadLimits {
        max_bytes: 10,
        max_buffer_capacity: 11,
        max_read_calls: 4,
    };
    let result = held
        .read_all(limits, &OperationControl::unlimited())
        .unwrap();
    assert_eq!(result.bytes(), b"0123456789");
    assert_eq!(alias.stream_position().unwrap(), 6);
    assert_eq!(result.charges().read_calls(), 2);
    assert_eq!(result.charges().bytes_read(), 10);
    assert_eq!(
        result.observations().content_snapshot(),
        ContentSnapshot::NotProven
    );
    let e = held
        .read_all(
            ReadLimits {
                max_read_calls: 1,
                ..limits
            },
            &OperationControl::unlimited(),
        )
        .unwrap_err();
    assert_eq!(e.reason(), Reason::LimitExceeded(LimitKind::ReadCalls));
    assert_eq!(e.charges().syscall_attempts(), 3);
    let c = e.charges().read().unwrap();
    assert_eq!(
        (c.bytes_read(), c.read_calls(), c.retained_capacity()),
        (10, 1, 0)
    );
    assert_eq!(alias.stream_position().unwrap(), 6);
    let clone = result.clone();
    assert_eq!(result.bytes().as_ptr(), clone.bytes().as_ptr());
    drop(result);
    drop(held);
    drop(alias);
    assert_eq!(clone.bytes(), b"0123456789");
    let _: Option<File> = None;
}
