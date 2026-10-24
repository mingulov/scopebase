// SPDX-License-Identifier: Apache-2.0
//! Held-file inspector binary: smoke scenarios plus three useful modes over
//! real files (`inspect PATH`, `maps`, `walk ROOT`).
//! NEW (LX11): reference-only; no donor lines copied.
//!
//! F04: every failure below is a message plus an exit code, never a panic:
//! missing operands are usage errors (exit 2), setup/IO failures exit 1.
//! R03: argv enters via [`scopebase_testkit::cli::argv_strings`]: non-UTF-8
//! bytes refuse with usage, never panic in `env::args()`. R04: all output
//! is fallible (`put_line`/`err_line`); a dead stdout exits 1, a dead
//! stderr keeps the already-determined code. R34: smoke validates its
//! predicted paths before creating anything and always retires its root.
use linux_heldfile_reference::adapter::{run_scenario, script_value, HeldfileReferenceAdapter};
use scopebase_linux::conformance::FixtureRoot;
use scopebase_testkit::cli;
use scopebase_testkit::ConformanceAdapter;

const USAGE: &str = "usage: linux-heldfile-reference [inspect PATH | maps | walk ROOT]";

/// Report a failed stdout write; always exits 1 however stderr fares.
fn output_failed() -> i32 {
    cli::err_line("output write failed");
    1
}

fn smoke_name() -> String {
    format!("lx11-heldfile-smoke-{}", std::process::id())
}

/// S14: private smoke staging. Created before validation; the
/// `Drop` guard removes it on every exit path (empty-only — residue
/// fails visibly instead of hiding), so even a refused run strands
/// nothing. R34's validate-then-create still holds: the staging dir
/// is the only pre-validation creation, and the guard retires it.
struct Staging {
    path: Option<std::path::PathBuf>,
}

impl Staging {
    fn create(tag: &str) -> Option<Self> {
        // Exclusive create, skipping stale names from crashed runs
        // (same pid reused) — never removing anything.
        for n in 0..1024u32 {
            let dir = std::env::temp_dir().join(format!(
                "scopebase-staging-{tag}-{}-{n}",
                std::process::id()
            ));
            // S60: restrictive creation mode — the pre-chmod window is
            // 0700&~umask, never 0777&~umask.
            let created = {
                use std::os::unix::fs::DirBuilderExt as _;
                std::fs::DirBuilder::new().mode(0o700).create(&dir)
            };
            match created {
                Ok(()) => {
                    return Self::finish(dir, |dir| {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return None,
            }
        }
        None
    }

    /// S60: the guard arms BEFORE the fallible permission step, so a
    /// denied chmod removes the fresh directory instead of stranding
    /// it. The step is injected for tests; production passes the real
    /// `set_permissions`.
    fn finish(
        dir: std::path::PathBuf,
        chmod: impl FnOnce(&std::path::Path) -> std::io::Result<()>,
    ) -> Option<Self> {
        let staging = Self { path: Some(dir) };
        chmod(staging.path()).ok()?;
        Some(staging)
    }

    fn path(&self) -> &std::path::Path {
        self.path.as_ref().expect("staging held")
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            // Best-effort: `Drop` cannot report. Empty-only, so a
            // failure leaves visible residue rather than hiding it.
            let _ = std::fs::remove_dir(&path);
        }
    }
}

/// R34: predicted smoke layout, validated BEFORE anything is created.
/// The `;` refusal must strand nothing, so every interpolated string
/// is checked while the filesystem is still untouched.
///
/// S35: paths enter strictly. A lossy conversion would map a native
/// path beneath a non-UTF-8 directory onto a DIFFERENT (replacement
/// character) name — selecting another file for the open/read/walk
/// probes — so unrepresentable paths refuse here, before any
/// resource is created. A literal U+FFFD in a valid-Unicode path is
/// a real name and passes through byte-identical; only
/// unrepresentable bytes refuse.
fn smoke_paths(staging: &std::path::Path) -> Result<(String, String), &'static str> {
    let root = staging.join(smoke_name());
    let file = root
        .join("a.txt")
        .to_str()
        .ok_or("smoke paths are not valid Unicode")?
        .to_owned();
    let root_path = root
        .to_str()
        .ok_or("smoke paths are not valid Unicode")?
        .to_owned();
    let (Some(file), Some(root_path)) = (script_value(&file), script_value(&root_path)) else {
        return Err("smoke paths contain ';'");
    };
    Ok((file.to_owned(), root_path.to_owned()))
}

/// R34: populate a freshly created smoke root. Split from creation so
/// a partial failure can be retired by the caller (and faulted in tests
/// by pre-planting `sub` as a file, which refuses the nested write).
fn write_smoke_files(root: &FixtureRoot) -> Result<(), String> {
    root.write_file("a.txt", b"hello world")
        .map_err(|e| format!("smoke file: {e}"))?;
    root.write_file("sub/b.txt", b"second")
        .map_err(|e| format!("smoke nested: {e}"))?;
    Ok(())
}

fn main() {
    let code = match cli::argv_strings() {
        Some(argv) => run(&argv),
        None => {
            cli::err_line("argv is not valid Unicode");
            cli::err_line(USAGE);
            2
        }
    };
    std::process::exit(code);
}

fn run(args: &[String]) -> i32 {
    match args.get(1).map(String::as_str) {
        None => smoke(),
        Some("inspect") => {
            let Some(path) = args.get(2) else {
                cli::err_line("usage: inspect PATH");
                return 2;
            };
            let Some(path) = script_value(path) else {
                cli::err_line("inspect refuses paths containing ';'");
                return 2;
            };
            let script = format!("case=ok;path={path};");
            match run_scenario("open", script.as_bytes(), None) {
                Some(body) => {
                    if !cli::put_line(&body) {
                        return output_failed();
                    }
                    0
                }
                None => {
                    cli::err_line("inspect refused");
                    1
                }
            }
        }
        Some("maps") => {
            let raw = match std::fs::read("/proc/self/maps") {
                Ok(raw) => raw,
                Err(error) => {
                    cli::err_line(&format!("cannot read own maps: {error}"));
                    return 1;
                }
            };
            match run_scenario("parse-maps", b"case=live;", Some(&raw)) {
                Some(body) => {
                    if !cli::put_line(&body) {
                        return output_failed();
                    }
                    0
                }
                None => {
                    cli::err_line("maps refused");
                    1
                }
            }
        }
        Some("walk") => {
            let Some(root) = args.get(2) else {
                cli::err_line("usage: walk ROOT");
                return 2;
            };
            let Some(root) = script_value(root) else {
                cli::err_line("walk refuses roots containing ';'");
                return 2;
            };
            let script = format!("case=ok;root={root};");
            match run_scenario("walk", script.as_bytes(), None) {
                Some(body) => {
                    if !cli::put_line(&body) {
                        return output_failed();
                    }
                    0
                }
                None => {
                    cli::err_line("walk refused");
                    1
                }
            }
        }
        Some(other) => {
            cli::err_line(&format!("unknown mode {other}"));
            1
        }
    }
}

fn smoke() -> i32 {
    let adapter = match HeldfileReferenceAdapter::new() {
        Ok(adapter) => adapter,
        Err(error) => {
            cli::err_line(&format!("adapter builds: {error}"));
            return 1;
        }
    };
    let subject = adapter.subject();
    if !cli::put_line(&format!(
        "subject: {} {} consumer={}",
        subject.package_name(),
        subject.package_version(),
        subject.consumer().name()
    )) {
        return output_failed();
    }
    // S14: private staging first; its guard retires it on every
    // exit path below. R34: validate-then-create. The staging dir
    // is the only thing existing yet, and the guard owns it, so a
    // refusal here still strands nothing by construction.
    let Some(staging) = Staging::create("heldfile-smoke") else {
        cli::err_line("smoke staging failed");
        return 1;
    };
    let (file, root_path) = match smoke_paths(staging.path()) {
        Ok(paths) => paths,
        Err(message) => {
            cli::err_line(message);
            return 1;
        }
    };
    let root = match FixtureRoot::create(staging.path(), &smoke_name()) {
        Ok(root) => root,
        Err(error) => {
            cli::err_line(&format!("smoke root: {error}"));
            return 1;
        }
    };
    // R34: a partial setup retires what it created before reporting.
    if let Err(error) = write_smoke_files(&root) {
        let _ = root.close();
        cli::err_line(&error);
        return 1;
    }
    let mut failed = false;
    let mut lines = Vec::new();
    for (op, script, body, expected) in [
        (
            "open",
            format!("case=ok;path={file};"),
            None,
            "stat=len:11;",
        ),
        (
            "read",
            format!("case=ok;path={file};"),
            None,
            "bytes=11;calls=2;",
        ),
        (
            "walk",
            format!("case=ok;root={root_path};"),
            None,
            "entries=a.txt,sub,sub/b.txt;done=true;",
        ),
    ] {
        match run_scenario(op, script.as_bytes(), body) {
            Some(got) => {
                if got != expected {
                    failed = true;
                }
                lines.push(format!("{op}: {got}"));
            }
            None => {
                failed = true;
                lines.push(format!("{op}: refused"));
            }
        }
    }
    // R34: the root retires before any scenario output, so a dead
    // stdout cannot strand the tree (print-after-close).
    if let Err(error) = root.close() {
        cli::err_line(&format!("smoke cleanup: {error}"));
        return 1;
    }
    for line in &lines {
        if !cli::put_line(line) {
            return output_failed();
        }
    }
    i32::from(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    // F04: invalid input is a usage error, never a panic.
    #[test]
    fn missing_operands_are_usage_errors() {
        assert_eq!(run(&argv(&["inspect-bin", "inspect"])), 2);
        assert_eq!(run(&argv(&["inspect-bin", "walk"])), 2);
        assert_eq!(run(&argv(&["inspect-bin", "bogus"])), 1);
    }

    // F28: delimiter-bearing values refuse before interpolation.
    #[test]
    fn semicolon_values_are_refused() {
        assert_eq!(run(&argv(&["inspect-bin", "inspect", "/tmp/a;b"])), 2);
        assert_eq!(run(&argv(&["inspect-bin", "walk", "/tmp/x;y"])), 2);
        assert_eq!(script_value("plain/path"), Some("plain/path"));
        assert_eq!(script_value("semi;colon"), None);
    }

    // R34: a partial smoke setup is an error the caller can retire:
    // pre-planting `sub` as a file refuses the nested write, and the
    // root still closes cleanly afterwards (no residue).
    #[test]
    fn partial_smoke_setup_retires_cleanly() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "lx11-r34-partial-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        // S14: the partial root stages under a private parent.
        let staging = Staging::create("r34-partial").expect("staging");
        let path = staging.path().join(&name);
        let root = FixtureRoot::create(staging.path(), &name).expect("create partial root");
        root.write_file("sub", b"blocker")
            .expect("plant blocker file");
        let err = write_smoke_files(&root).unwrap_err();
        assert!(err.contains("smoke nested"), "nested write refused: {err}");
        root.close().expect("close retires the partial tree");
        assert!(!path.exists(), "partial setup left residue");
    }

    // S35: unrepresentable smoke paths refuse with their own message;
    // a literal U+FFFD name is valid Unicode and passes through
    // byte-identical — the helper never confuses invalid bytes with
    // the replacement character. Pure prediction: nothing created.
    #[test]
    fn smoke_paths_refuse_non_utf8() {
        use std::os::unix::ffi::OsStringExt;
        let bad = std::path::PathBuf::from(std::ffi::OsString::from_vec(
            b"/tmp/with-\xff-byte".to_vec(),
        ));
        assert_eq!(
            smoke_paths(&bad).unwrap_err(),
            "smoke paths are not valid Unicode"
        );
        let semi = std::path::Path::new("/tmp/with;semi");
        assert_eq!(smoke_paths(semi).unwrap_err(), "smoke paths contain ';'");
        let doppel = std::path::Path::new("/tmp/with-\u{FFFD}-char");
        let (file, root_path) = smoke_paths(doppel).expect("replacement char is representable");
        assert!(
            file.contains("\u{FFFD}") && file.ends_with("a.txt"),
            "doppelganger name passes through exactly: {file}"
        );
        assert!(
            root_path.contains("\u{FFFD}"),
            "doppelganger root passes through exactly: {root_path}"
        );
        assert!(!doppel.exists(), "prediction created nothing");
    }

    /// S60: a denied permission step removes the fresh directory —
    /// the guard was armed before the fallible chmod, not after.
    #[test]
    fn s60_failed_chmod_leaves_no_residue() {
        let dir = std::env::temp_dir().join(format!(
            "s60-staging-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let out = Staging::finish(dir.clone(), |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected chmod denial",
            ))
        });
        assert!(out.is_none(), "denied chmod must refuse staging");
        assert!(
            !dir.exists(),
            "denied chmod stranded the staging dir: {}",
            dir.display()
        );
    }

    /// S60: the accepted path still guards (drop retires the dir).
    #[test]
    fn s60_ok_chmod_keeps_guarded_dir() {
        let dir = std::env::temp_dir().join(format!(
            "s60-staging-ok-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let staging = Staging::finish(dir.clone(), |_| Ok(())).expect("ok chmod keeps staging");
        assert!(dir.exists(), "accepted staging must hold its dir");
        drop(staging);
        assert!(!dir.exists(), "guard drop must retire the dir");
    }
}
