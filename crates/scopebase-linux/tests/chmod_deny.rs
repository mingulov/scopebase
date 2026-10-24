// SPDX-License-Identifier: Apache-2.0
//! S60: real fchmod-denial probes for fixture construction. Each
//! parent spawns this binary as its own child (the `held_file.rs`
//! self-reexec pattern — a seccomp filter is irreversible, so the
//! denial must live in a fresh process). The child denies ONLY the
//! fchmod syscall, drives one construction path, and reports; the
//! parent asserts the error AND the absence of residue.
//!
//! No libc import: the syscall number below is a plain integer
//! literal inferred at the call site. x86_64 fchmod is UAPI 91
//! (`arch/x86/entry/syscalls/syscall_64.tbl`); a wrong number fails
//! loud — the child's construction would succeed and its assertion
//! fire. Non-x86_64 children report setup (skip).
use scopebase_linux::conformance::FixtureRoot;
use scopebase_testkit::fixture::linux::seccomp::{install_deny_one, DenyAction};

/// Install the fchmod-only denial. Returns false when the platform
/// cannot (non-x86_64, or seccomp refused): the child reports setup.
fn deny_fchmod() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // UAPI-stable number, verified loud on mismatch (see above).
        install_deny_one(91, DenyAction::Eperm).is_ok()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

fn temp_parent(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "s60-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    // Exclusive parent (require_exclusive_parent): 0700&~umask can
    // only narrow, so this qualifies under every umask.
    std::fs::create_dir(&dir).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// Run the child probe for `mode` against `parent`; returns its
/// stdout line. A `setup=...` line means the platform cannot deny
/// (skip); anything else must be `verdict=err ...`.
fn child_line(mode: &str, parent: &std::path::Path) -> String {
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new(exe)
        .args(["--exact", "s60_probe_child", "--nocapture"])
        .env("S60_PROBE", format!("{mode}:{}", parent.display()))
        .output()
        .expect("probe child runs");
    assert!(
        out.status.success(),
        "probe child failed: status={} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|line| {
            if line.starts_with("verdict=") || line.starts_with("setup=") {
                Some(line.to_owned())
            } else {
                None
            }
        })
        .expect("probe child reports one line")
}

/// S60: `FixtureRoot::create` under denied fchmod refuses and strands
/// nothing — the root has no owner yet, so rollback must remove it.
#[test]
fn s60_create_chmod_denial_leaves_no_root() {
    let parent = temp_parent("create");
    let line = child_line("root", &parent);
    if line.starts_with("setup=") {
        let _ = std::fs::remove_dir_all(&parent);
        return;
    }
    assert!(
        line.starts_with("verdict=err"),
        "denied fchmod must refuse creation, got: {line}"
    );
    assert!(
        !parent.join("s60root").exists(),
        "denied fchmod stranded its root"
    );
    let _ = std::fs::remove_dir_all(&parent);
}

/// S60: `subdir` under denied fchmod refuses and leaves no leaf.
#[test]
fn s60_subdir_chmod_denial_leaves_no_leaf() {
    let parent = temp_parent("subdir");
    let line = child_line("subdir", &parent);
    if line.starts_with("setup=") {
        let _ = std::fs::remove_dir_all(&parent);
        return;
    }
    assert!(
        line.starts_with("verdict=err"),
        "denied fchmod must refuse subdir, got: {line}"
    );
    assert!(
        !parent.join("s60root").join("leaf").exists(),
        "denied fchmod stranded its leaf"
    );
    let _ = std::fs::remove_dir_all(&parent);
}

/// S60: nested `subdir` under denied fchmod refuses with the
/// pre-created intermediate still present but empty (no leaf).
#[test]
fn s60_nested_chmod_denial_leaves_no_leaf() {
    let parent = temp_parent("nested");
    let line = child_line("nested", &parent);
    if line.starts_with("setup=") {
        let _ = std::fs::remove_dir_all(&parent);
        return;
    }
    assert!(
        line.starts_with("verdict=err"),
        "denied fchmod must refuse nested subdir, got: {line}"
    );
    let mid = parent.join("s60root").join("mid");
    assert!(mid.is_dir(), "pre-created intermediate must survive");
    assert!(
        !mid.join("leaf").exists(),
        "denied fchmod stranded its nested leaf"
    );
    let _ = std::fs::remove_dir_all(&parent);
}

/// S60: `open_child_dir`'s fresh intermediate under denied fchmod
/// refuses and leaves no intermediate behind.
#[test]
fn s60_intermediate_chmod_denial_leaves_no_dir() {
    let parent = temp_parent("intermediate");
    let line = child_line("intermediate", &parent);
    if line.starts_with("setup=") {
        let _ = std::fs::remove_dir_all(&parent);
        return;
    }
    assert!(
        line.starts_with("verdict=err"),
        "denied fchmod must refuse intermediate creation, got: {line}"
    );
    assert!(
        !parent.join("s60root").join("newmid").exists(),
        "denied fchmod stranded its intermediate"
    );
    let _ = std::fs::remove_dir_all(&parent);
}

/// Child entry: deny fchmod, drive one construction, report one line.
/// Returns immediately in the parent (no `S60_PROBE` in env).
#[test]
fn s60_probe_child() {
    let spec = match std::env::var("S60_PROBE") {
        Ok(spec) => spec,
        Err(_) => return,
    };
    let (mode, parent) = spec.split_once(':').expect("mode:parent spec");
    let parent = std::path::Path::new(parent);
    // Pre-creation runs BEFORE the filter: only the step under test
    // sees the denial.
    let root = match mode {
        "root" => None,
        "subdir" | "intermediate" => {
            Some(FixtureRoot::create(parent, "s60root").expect("pre-create root"))
        }
        "nested" => {
            let root = FixtureRoot::create(parent, "s60root").expect("pre-create root");
            root.subdir("mid").expect("pre-create intermediate");
            Some(root)
        }
        _ => {
            println!("setup=unknown-mode");
            return;
        }
    };
    if !deny_fchmod() {
        println!("setup=seccomp-or-arch-unsupported");
        return;
    }
    let result = match mode {
        "root" => FixtureRoot::create(parent, "s60root").map(|_| ()),
        "subdir" => root.unwrap().subdir("leaf").map(|_| ()),
        "nested" => root.unwrap().subdir("mid/leaf").map(|_| ()),
        "intermediate" => root.unwrap().subdir("newmid/leaf").map(|_| ()),
        _ => unreachable!("mode admitted above"),
    };
    match result {
        Ok(()) => {
            // Loud failure: the denial did not bite (wrong syscall
            // number, or the chmod path was bypassed).
            println!("verdict=UNEXPECTED-OK");
            std::process::exit(1);
        }
        Err(error) => {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied,
                "denial must surface as EPERM"
            );
            let text = error.to_string();
            assert!(
                text.contains("chmod"),
                "error must name the chmod stage, got: {text}"
            );
            println!("verdict=err {text}");
        }
    }
}
