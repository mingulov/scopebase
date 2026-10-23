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

/// R32: exclusively create a private temp dir; a pre-existing
/// candidate is refused, never reused (see filesystem_cells).
fn claim_temp_dir(dir: &std::path::Path) {
    match std::fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) => panic!(
            "refused: temp candidate {} already exists ({e})",
            dir.display()
        ),
    }
}

#[test]
fn second_pipe_failure_leaks_no_descriptors() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // R32 canary, folded into this test: a second #[test] in this
    // binary would share the process with fd exhaustion. A
    // preplanted symlink at the claimed path is refused, never
    // followed.
    {
        let plant = std::env::temp_dir().join(format!(
            "tt04-pipe-f20-plant-{}-{:x}",
            std::process::id(),
            nonce
        ));
        let _ = std::fs::remove_file(&plant);
        let outside = std::env::temp_dir().join(format!(
            "tt04-pipe-f20-outside-{}-{:x}",
            std::process::id(),
            nonce
        ));
        let _ = std::fs::remove_dir_all(&outside);
        claim_temp_dir(&outside);
        let canary = outside.join("canary.txt");
        std::fs::write(&canary, b"canary").expect("canary bytes");
        std::os::unix::fs::symlink(&outside, &plant).expect("plant link");
        let outcome = std::panic::catch_unwind(|| claim_temp_dir(&plant));
        assert!(
            outcome.is_err(),
            "preplanted symlink was claimed instead of refused"
        );
        assert_eq!(std::fs::read(&canary).expect("canary reads"), b"canary");
        std::fs::remove_file(&plant).expect("plant cleanup");
        std::fs::remove_dir_all(&outside).expect("outside cleanup");
    }
    // Fixture the mapping target can mmap (needs >= 4096 bytes).
    let dir =
        std::env::temp_dir().join(format!("tt04-pipe-f20-{}-{:x}", std::process::id(), nonce));
    claim_temp_dir(&dir);
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
