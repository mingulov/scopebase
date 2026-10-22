// SPDX-License-Identifier: Apache-2.0
//! Explicitly selected tests require the shipped single-thread fixture binary.
#[path = "support/mount_custody.rs"]
mod mount_custody;
fn run(case: &str, nested: bool) {
    let binary = std::env::var_os("SCOPEBASE_BP02_FIXTURE")
        .expect("BLOCKED_ENVIRONMENT explicit fixture binary required");
    let mut cmd = if nested {
        let mut c = std::process::Command::new("unshare");
        c.args(["--mount", "--pid", "--fork", "--mount-proc"]);
        c.arg(binary);
        c
    } else {
        std::process::Command::new(binary)
    };
    cmd.args([case, "--owned-namespace"]);
    let outcome = mount_custody::run(
        cmd,
        !matches!(case, "fork" | "nested"),
        &std::env::temp_dir(),
    );
    outcome.emit(case);
    // Reap, check the exact PID/root identity, attempt cleanup and emit both
    // primary/cleanup outcomes before any success/PASS assertion can panic.
    assert!(
        outcome.custody_resolved(),
        "UNRESOLVED owned fixture custody for {case}"
    );
    let out = outcome.output.as_ref().expect("fixture child not reaped");
    assert!(
        out.status.success(),
        "{case}: {} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("PASS"));
    assert!(
        !outcome.root_required || outcome.owned_temp_removed,
        "source case did not prove owned-root removal"
    );
}
#[test]
#[ignore = "N6 requires explicitly admitted private mount namespaces"]
fn n6_source_authenticity() {
    for case in [
        "full-root",
        "fake",
        "online-leaf",
        "symlink-leaf",
        "symlink-root",
        "subtree",
        "full-root",
    ] {
        run(case, false);
    }
}
#[test]
#[ignore = "N7 requires explicitly owned source substitution"]
fn n7_continuity() {
    run("replace-root", false);
    run("full-root", false);
}
#[test]
#[ignore = "N8 requires single-thread owned PID/mount namespace fixture"]
fn n8_fork_context() {
    run("fork", false);
    run("nested", true);
}

#[test]
fn cleanup_control_child() {
    use std::os::unix::fs::MetadataExt;
    let Ok(mode) = std::env::var("SCOPEBASE_BP02_CLEANUP_CONTROL") else {
        return;
    };
    println!();
    if mode == "rootless" {
        println!("PASS rootless control");
        return;
    }
    if mode == "absent" {
        panic!("BP02_BEFORE_ROOT_CONTROL");
    }
    let root = std::env::temp_dir().join(format!("scopebase-bp02-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    if mode != "missing" {
        println!("OWNED_TEMP_ROOT={}", root.display());
        let metadata = std::fs::symlink_metadata(&root).unwrap();
        if mode == "malformed" {
            println!("OWNED_TEMP_ROOT_ID=not-an-identity");
        } else {
            println!(
                "OWNED_TEMP_ROOT_ID={}:{}",
                metadata.dev(),
                metadata.ino() + u64::from(mode == "mismatch")
            );
        }
        if mode == "duplicate" {
            mount_custody::report_root(&root).unwrap();
        }
    }
    println!("BP02_AFTER_ROOT_VALID_SETUP");
    if mode == "fail" {
        panic!("BP02_AFTER_ROOT_PRIMARY_CHILD_FAILURE");
    }
    println!("PASS owned cleanup control");
}

fn cleanup_control(
    mode: &str,
    root_required: bool,
) -> (mount_custody::ChildOutcome, std::path::PathBuf) {
    use std::os::unix::fs::DirBuilderExt;
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let directory = std::env::temp_dir().join(format!(
        "bp02-custody-control-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "cleanup_control_child", "--nocapture"])
        .env("SCOPEBASE_BP02_CLEANUP_CONTROL", mode)
        .env("TMPDIR", &directory);
    (
        mount_custody::run(command, root_required, &directory),
        directory,
    )
}

#[test]
fn failed_child_root_cleanup_and_positive_twin() {
    for mode in ["fail", "positive"] {
        let (outcome, directory) = cleanup_control(mode, true);
        assert!(outcome.child_reaped);
        assert!(outcome.owned_temp_removed, "BP02_FAILED_CHILD_ROOT_CLEANUP");
        assert_eq!(outcome.cleanup_status, "PASS");
        assert!(!outcome.expected_root.as_ref().unwrap().exists());
        assert_eq!(outcome.child_success(), mode == "positive");
        if mode == "fail" {
            assert!(
                String::from_utf8_lossy(&outcome.output.as_ref().unwrap().stderr)
                    .contains("BP02_AFTER_ROOT_PRIMARY_CHILD_FAILURE")
            );
        }
        std::fs::remove_dir(&directory).unwrap();
    }
}

#[test]
fn root_protocol_mismatch_missing_duplicate_and_malformed_are_unresolved() {
    for mode in ["mismatch", "missing", "duplicate", "malformed"] {
        let (outcome, directory) = cleanup_control(mode, true);
        assert!(outcome.child_reaped);
        assert_eq!(outcome.cleanup_status, "UNRESOLVED", "{mode}");
        assert!(!outcome.owned_temp_removed && !outcome.custody_resolved());
        assert!(outcome.expected_root.as_ref().unwrap().is_dir());
        // This base was created by this test, not selected from a report.
        std::fs::remove_dir_all(&directory).unwrap();
    }
}

#[test]
fn absent_root_and_rootless_child_are_distinct() {
    for (mode, required, expected) in [
        ("absent", true, "ABSENT"),
        ("rootless", false, "NOT_REQUIRED"),
    ] {
        let (outcome, directory) = cleanup_control(mode, required);
        assert!(outcome.child_reaped && outcome.custody_resolved());
        assert_eq!(outcome.cleanup_status, expected);
        assert!(!outcome.owned_temp_removed);
        std::fs::remove_dir(&directory).unwrap();
    }
}
