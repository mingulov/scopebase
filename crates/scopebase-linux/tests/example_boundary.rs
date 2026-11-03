// SPDX-License-Identifier: Apache-2.0
//! R03/R04: executable boundary tests over the path-taking examples.
//!
//! Each test skips when its example binary was not built: a filtered
//! `cargo test --test example_boundary` run does not build examples,
//! while a full `cargo test -p scopebase-linux` does. A skip therefore
//! means "not built here", never a vacuous pass of a present binary.
//!
//! S210: the skip `println!` is captured (invisible) on passing runs,
//! so filtered triage runs can pass while asserting nothing. Set
//! `EXAMPLE_BOUNDARY_STRICT=1` (CI's invocations do) to fail loudly
//! instead of skipping; pass `--nocapture` to see lax skips.
//!
//! S210b: strict fails loudly only when the example SHOULD have been
//! built — i.e. its required feature is enabled in this build. A
//! feature-gated example (`walk_root` needs `walk`, `observe_self`
//! needs `process`) in a build without that feature skips even under
//! strict: the gate never selected it, so silence is correct there.

use std::path::PathBuf;

/// Locate a built example binary, honoring `CARGO_TARGET_DIR`.
fn example(name: &str) -> Option<PathBuf> {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let root = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    let path = root.join(profile).join("examples").join(name);
    path.is_file().then_some(path)
}

fn require(name: &str) -> Option<PathBuf> {
    require_strict(name, std::env::var("EXAMPLE_BOUNDARY_STRICT").is_ok())
}

/// S210b: feature-gated examples skip (even under strict) when their
/// required feature is off in this build — cargo never builds them
/// there, so a missing binary is expected, not a hole. With the
/// feature on, strict applies exactly as S210 specifies.
fn require_gated(name: &str, feature_on: bool) -> Option<PathBuf> {
    if !feature_on {
        println!("SKIP example_boundary/{name}: required feature off in this build");
        return None;
    }
    require(name)
}

/// S210: skip-or-fail on a missing example binary. A bare `println!`
/// skip is captured (invisible) on passing runs, so filtered triage
/// runs can pass while asserting nothing; strict mode panics instead.
/// The strict bit is injected for tests; production reads
/// `EXAMPLE_BOUNDARY_STRICT` (set in CI's invocations).
fn require_strict(name: &str, strict: bool) -> Option<PathBuf> {
    match example(name) {
        Some(path) => Some(path),
        None => {
            if strict {
                panic!(
                    "example_boundary/{name}: binary not built \
                     (strict: run a full `cargo test -p scopebase-linux`)"
                );
            }
            println!(
                "SKIP example_boundary/{name}: binary not built \
                 (run a full `cargo test -p scopebase-linux`)"
            );
            None
        }
    }
}

#[test]
fn strict_skip_fails_loudly_on_missing_binary() {
    // S210: a bare `println!` skip is captured (invisible) on passing
    // runs. Strict mode panics instead of skipping, so filtered runs
    // with `EXAMPLE_BOUNDARY_STRICT` set cannot pass vacuously.
    // (Env-free: the strict bit is injected, never read here.)
    let outcome = std::panic::catch_unwind(|| require_strict("definitely-not-a-built-example", true));
    assert!(outcome.is_err(), "strict skip must fail loudly");
    assert!(
        require_strict("definitely-not-a-built-example", false).is_none(),
        "lax skip still skips"
    );
}

fn scratch(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "lx11-exb-{}-{}-{}",
        tag,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// R03: non-UTF-8 path refuses with usage (exit 2), never panics in
/// `env::args()` (old code exited 101).
#[test]
fn held_inspect_non_utf8_refuses() {
    let Some(bin) = require("held_inspect") else {
        return;
    };
    use std::os::unix::ffi::OsStringExt;
    let out = std::process::Command::new(bin)
        .arg(std::ffi::OsString::from_vec(b"/tmp/\xff".to_vec()))
        .output()
        .expect("spawn example");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not valid Unicode"), "{stderr:?}");
    assert!(stderr.contains("usage:"), "{stderr:?}");
}

/// R03/R04 control: a valid file reports its ledger on stdout.
#[test]
fn held_inspect_valid_file_reports() {
    let Some(bin) = require("held_inspect") else {
        return;
    };
    let dir = scratch("inspect");
    let file = dir.join("f.txt");
    std::fs::write(&file, b"hello").unwrap();
    let out = std::process::Command::new(bin)
        .arg(&file)
        .output()
        .expect("spawn example");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("stat"), "{stdout:?}");
    assert!(stdout.contains("bytes"), "{stdout:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// R04: a dead stdout exits 1, never panics (old `println!`
/// exited 101).
#[test]
fn held_inspect_dead_stdout_exits_1() {
    let Some(bin) = require("held_inspect") else {
        return;
    };
    let dir = scratch("inspect-full");
    let file = dir.join("f.txt");
    std::fs::write(&file, b"hello").unwrap();
    let out = std::process::Command::new(bin)
        .arg(&file)
        .stdout(std::fs::File::create("/dev/full").expect("/dev/full opens"))
        .output()
        .expect("spawn example");
    assert_eq!(out.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

/// R03: non-UTF-8 root refuses with usage (exit 2), never panics.
#[test]
fn walk_root_non_utf8_refuses() {
    let Some(bin) = require_gated("walk_root", cfg!(feature = "walk")) else {
        return;
    };
    use std::os::unix::ffi::OsStringExt;
    let out = std::process::Command::new(bin)
        .arg(std::ffi::OsString::from_vec(b"/tmp/\xff".to_vec()))
        .output()
        .expect("spawn example");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not valid Unicode"), "{stderr:?}");
    assert!(stderr.contains("usage:"), "{stderr:?}");
}

/// R03/R04 control: a valid root reports its entries on stdout.
#[test]
fn walk_root_valid_dir_reports() {
    let Some(bin) = require_gated("walk_root", cfg!(feature = "walk")) else {
        return;
    };
    let dir = scratch("walk");
    std::fs::write(dir.join("a.txt"), b"x").unwrap();
    let out = std::process::Command::new(bin)
        .arg(&dir)
        .output()
        .expect("spawn example");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("entries"), "{stdout:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// R04: a dead stdout exits 1, never panics.
#[test]
fn walk_root_dead_stdout_exits_1() {
    let Some(bin) = require_gated("walk_root", cfg!(feature = "walk")) else {
        return;
    };
    let dir = scratch("walk-full");
    std::fs::write(dir.join("a.txt"), b"x").unwrap();
    let out = std::process::Command::new(bin)
        .arg(&dir)
        .stdout(std::fs::File::create("/dev/full").expect("/dev/full opens"))
        .output()
        .expect("spawn example");
    assert_eq!(out.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

/// R04 control: the self-observation example reports its ledger.
#[test]
fn observe_self_reports() {
    let Some(bin) = require_gated("observe_self", cfg!(feature = "process")) else {
        return;
    };
    let out = std::process::Command::new(bin)
        .output()
        .expect("spawn example");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("birth"), "{stdout:?}");
}

/// R04: the self-observation example exits 1 on a dead stdout.
#[test]
fn observe_self_dead_stdout_exits_1() {
    let Some(bin) = require_gated("observe_self", cfg!(feature = "process")) else {
        return;
    };
    let out = std::process::Command::new(bin)
        .stdout(std::fs::File::create("/dev/full").expect("/dev/full opens"))
        .output()
        .expect("spawn example");
    assert_eq!(out.status.code(), Some(1));
}
