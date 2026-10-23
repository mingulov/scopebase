// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "linux-fixtures")]
//! F20: a failed second pipe() in `OwnedTarget::mapping` must not leak
//! the first pipe pair.
//!
//! This test lives alone in its own binary (hence its own process) on
//! purpose: it briefly exhausts the descriptor table, which would break
//! any test sharing the process. With exactly three descriptors free,
//! the fixture open (one) and the first pipe (two) succeed while the
//! second pipe fails; the pre-F20 code leaked the first pair (+2 fds),
//! the OwnedFd guards close it (fd count unchanged).
use scopebase_testkit::fixture::linux::target::OwnedTarget;
use std::fs::File;

fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("own fd dir lists")
        .count()
}

#[test]
fn second_pipe_failure_leaks_no_descriptors() {
    // Fixture the mapping target can mmap (needs >= 4096 bytes).
    let dir = std::env::temp_dir().join(format!("tt04-pipe-f20-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let fixture = dir.join("map.bin");
    std::fs::write(&fixture, vec![0xA5u8; 8192]).expect("fixture bytes");

    // Exhaust the table, then free exactly three slots.
    let mut fillers = Vec::new();
    while let Ok(filler) = File::open("/dev/null") {
        fillers.push(filler);
    }
    assert!(
        fillers.len() > 8,
        "fd exhaustion must actually bite, held {}",
        fillers.len()
    );
    let keep = fillers.len() - 3;
    fillers.truncate(keep);

    let before = fd_count();
    let err = match OwnedTarget::mapping(&fixture) {
        Ok(_) => panic!("second pipe must fail under exhaustion"),
        Err(err) => err,
    };
    let after = fd_count();
    assert_eq!(
        before, after,
        "failed mapping leaked descriptors: {before} -> {after}"
    );
    assert!(
        err.to_string().contains("pipe"),
        "unexpected failure: {err}"
    );

    drop(fillers);
    std::fs::remove_dir_all(&dir).expect("temp cleanup");
}
