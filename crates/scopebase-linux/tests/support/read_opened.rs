// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::{
    control::OperationControl,
    file::{HeldFile, ProcFdResolver, ReadLimits, SymlinkPolicy},
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{Arc, Barrier},
};
struct Remove(PathBuf);
impl Drop for Remove {
    fn drop(&mut self) {
        fs::remove_file(&self.0).unwrap();
    }
}
fn main() {
    let path = std::env::temp_dir().join(format!("lx03-opened-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    let _remove = Remove(path.clone());
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
    let barrier = Arc::new(Barrier::new(3));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let h = held.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                b.wait();
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
    barrier.wait();
    for worker in workers {
        let r = worker.join().unwrap();
        assert_eq!(r.bytes(), b"original-owned-bytes");
        assert_eq!(r.observations().before().key(), key);
        assert_eq!(r.observations().before(), r.observations().after());
    }
    assert_eq!(held.stat().unwrap().key(), key);
    drop(held);
    drop(resolver);
}
