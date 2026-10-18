// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::{
    control::OperationControl,
    file::{HeldFile, ProcFdResolver, ReadLimits, SymlinkPolicy},
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::Arc,
};
struct Remove(PathBuf);
impl Drop for Remove {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn main() {
    let directory = (0u64..)
        .find_map(|index| {
            let path =
                std::env::temp_dir().join(format!("lx03-opened-{}-{index}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => Some(Remove(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(e) => panic!("owned client directory: {e}"),
            }
        })
        .unwrap();
    let path = directory.0.join("input");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.write_all(b"original-owned-bytes").unwrap();
    drop(file);
    let resolver = ProcFdResolver::open_self().unwrap();
    let held = Arc::new(HeldFile::open(&path, &resolver, SymlinkPolicy::Follow).unwrap());
    let key = held.stat().unwrap().key();
    fs::remove_file(&path).unwrap();
    let mut replacement = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    replacement.write_all(b"independent-replacement").unwrap();
    drop(replacement);
    assert_eq!(fs::read(&path).unwrap(), b"independent-replacement");
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let h = held.clone();
                scope.spawn(move || {
                    h.read_all(
                        ReadLimits {
                            max_bytes: 64,
                            max_buffer_capacity: 65,
                            max_read_calls: 4,
                        },
                        &OperationControl::unlimited(),
                    )
                    .unwrap()
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join())
            .collect::<Vec<_>>()
    });
    for result in results {
        let r = result.unwrap();
        assert_eq!(r.bytes(), b"original-owned-bytes");
        assert_eq!(r.observations().before().key(), key);
        assert_eq!(r.observations().before(), r.observations().after());
    }
    assert_eq!(held.stat().unwrap().key(), key);
    drop(held);
    drop(resolver);
    fs::remove_dir_all(&directory.0).unwrap();
}
