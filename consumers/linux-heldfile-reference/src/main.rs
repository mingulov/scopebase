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

/// R34: predicted smoke layout, validated BEFORE anything is created.
/// The `;` refusal must strand nothing, so every interpolated string
/// is checked while the filesystem is still untouched.
fn smoke_paths() -> Option<(String, String)> {
    let root = std::env::temp_dir().join(smoke_name());
    let file = root.join("a.txt").to_string_lossy().into_owned();
    let root_path = root.to_string_lossy().into_owned();
    let (Some(file), Some(root_path)) = (script_value(&file), script_value(&root_path)) else {
        return None;
    };
    Some((file.to_owned(), root_path.to_owned()))
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
    // R34: validate-then-create. Nothing exists yet, so a refusal
    // here strands nothing by construction.
    let Some((file, root_path)) = smoke_paths() else {
        cli::err_line("smoke paths contain ';'");
        return 1;
    };
    let root = match FixtureRoot::create(&std::env::temp_dir(), &smoke_name()) {
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
        let path = std::env::temp_dir().join(&name);
        let _ = std::fs::remove_dir_all(&path);
        let root = FixtureRoot::create(&std::env::temp_dir(), &name).expect("create partial root");
        root.write_file("sub", b"blocker")
            .expect("plant blocker file");
        let err = write_smoke_files(&root).unwrap_err();
        assert!(err.contains("smoke nested"), "nested write refused: {err}");
        root.close().expect("close retires the partial tree");
        assert!(!path.exists(), "partial setup left residue");
    }
}
