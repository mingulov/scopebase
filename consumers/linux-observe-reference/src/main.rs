// SPDX-License-Identifier: Apache-2.0
//! Owned-workload observer binary: smoke scenarios, a useful `observe PID`
//! mode, and the hidden `child SECS` sleep mode the adapter spawns as its
//! hermetic owned workload (no /bin dependency).
//! NEW (LX11): reference-only; no donor lines copied.
//!
//! F04: every failure below is a message plus an exit code, never a panic:
//! missing/invalid operands are usage errors (exit 2), setup/IO failures exit 1.
//! R03: argv enters via [`scopebase_testkit::cli::argv_strings`]: non-UTF-8
//! bytes refuse with usage, never panic in `env::args()`. R04: all output
//! is fallible (`put_line`/`err_line`); a dead stdout exits 1, a dead
//! stderr keeps the already-determined code. R34: smoke validates its
//! predicted paths before creating anything and always retires its root.
use linux_observe_reference::adapter::{run_scenario, script_value, ObserveReferenceAdapter};
use scopebase_linux::conformance::FixtureRoot;
use scopebase_testkit::cli;
use scopebase_testkit::ConformanceAdapter;

const USAGE: &str = "usage: linux-observe-reference [observe PID | child SECS]";

/// Report a failed stdout write; always exits 1 however stderr fares.
fn output_failed() -> i32 {
    cli::err_line("output write failed");
    1
}

fn smoke_name() -> String {
    format!("lx11-observe-smoke-{}", std::process::id())
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
            match std::fs::create_dir(&dir) {
                Ok(()) => {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok()?;
                    return Some(Self { path: Some(dir) });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return None,
            }
        }
        None
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

/// R34: every string smoke interpolates, resolved and validated BEFORE
/// anything is created. The own-binary lookup also happens here so a
/// `;` refusal (or a current_exe failure) strands nothing.
///
/// S35: paths enter strictly. A lossy conversion would map a native
/// path beneath a non-UTF-8 directory onto a DIFFERENT (replacement
/// character) name — selecting another file for the mapping probe or
/// another executable for the spawn probe — so unrepresentable paths
/// refuse here, before any resource is created or child executed. A
/// literal U+FFFD in a valid-Unicode path is a real name and passes
/// through byte-identical; only unrepresentable bytes refuse.
fn smoke_paths(staging: &std::path::Path) -> Result<(String, String), &'static str> {
    let exe = std::env::current_exe().map_err(|_| "smoke cannot locate its binary")?;
    let empty = staging.join(smoke_name()).join("empty.bin");
    let empty = empty.to_str().ok_or("smoke paths are not valid Unicode")?;
    let exe = exe.to_str().ok_or("smoke paths are not valid Unicode")?;
    let (Some(exe), Some(empty)) = (script_value(exe), script_value(empty)) else {
        return Err("smoke paths contain ';'");
    };
    Ok((exe.to_owned(), empty.to_owned()))
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
        Some("child") => {
            let Some(raw) = args.get(2) else {
                cli::err_line("usage: child SECS");
                return 2;
            };
            let secs: u64 = match raw.parse() {
                Ok(secs) => secs,
                Err(_) => {
                    cli::err_line("usage: child SECS (unsigned seconds)");
                    return 2;
                }
            };
            std::thread::sleep(std::time::Duration::from_secs(secs));
            0
        }
        Some("observe") => {
            let Some(pid) = args.get(2) else {
                cli::err_line("usage: observe PID");
                return 2;
            };
            let Some(pid) = script_value(pid) else {
                cli::err_line("observe refuses PIDs containing ';'");
                return 2;
            };
            let script = format!("case=pid;pid={pid};");
            match run_scenario("acquire", script.as_bytes(), None) {
                Some(body) => {
                    if !cli::put_line(&body) {
                        return output_failed();
                    }
                    0
                }
                None => {
                    cli::err_line("observe refused");
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
    let adapter = match ObserveReferenceAdapter::new() {
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
    let Some(staging) = Staging::create("observe-smoke") else {
        cli::err_line("smoke staging failed");
        return 1;
    };
    let (exe, empty) = match smoke_paths(staging.path()) {
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
    // R34: the single setup write retires the root on failure.
    if let Err(error) = root.write_file("empty.bin", b"") {
        let _ = root.close();
        cli::err_line(&format!("smoke file: {error}"));
        return 1;
    }
    let mut failed = false;
    let mut lines = Vec::new();
    for (op, script, expected) in [
        (
            "acquire-self",
            "case=self;".to_string(),
            "birth=AliveSameBirth;self_zombie=false;starttime_match=true;",
        ),
        (
            "spawn-observe",
            format!("case=child;child={exe};"),
            "birth=AliveSameBirth;child_maps=true;starttime_match=true;reaped=true;gone=true;",
        ),
        (
            "mapping",
            format!("case=empty;path={empty};"),
            "verdict=inconclusive:EmptyFile;",
        ),
    ] {
        match run_scenario(op, script.as_bytes(), None) {
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
    fn invalid_operands_are_usage_errors() {
        assert_eq!(run(&argv(&["observe-bin", "child"])), 2);
        assert_eq!(run(&argv(&["observe-bin", "child", "not-a-number"])), 2);
        assert_eq!(run(&argv(&["observe-bin", "observe"])), 2);
        assert_eq!(run(&argv(&["observe-bin", "bogus"])), 1);
    }

    // F28: delimiter-bearing values refuse before interpolation.
    #[test]
    fn semicolon_values_are_refused() {
        assert_eq!(run(&argv(&["observe-bin", "observe", "1;2"])), 2);
        assert_eq!(script_value("fine"), Some("fine"));
        assert_eq!(script_value("a;b"), None);
    }

    // R34: smoke-path prediction resolves the real binary and the
    // predicted tree without creating anything (pure prediction:
    // nothing to strand). Hostile-TMPDIR refusal is covered by the
    // subprocess leftover test, which owns TMPDIR safely.
    #[test]
    fn smoke_paths_predict_without_creating() {
        // S14: prediction takes the staging path but creates
        // nothing — the probe dir below never exists.
        let probe =
            std::env::temp_dir().join(format!("scopebase-probe-observe-{}", std::process::id()));
        let (exe, empty) = smoke_paths(&probe).expect("clean layout predicts");
        // In unit tests this resolves the test executable, in production
        // the product binary; both carry the crate name either way.
        assert!(exe.contains("observe"), "own binary: {exe}");
        assert!(
            std::path::Path::new(&exe).exists(),
            "resolved binary is real"
        );
        assert!(empty.ends_with("empty.bin"), "predicted file: {empty}");
        assert!(
            !std::path::Path::new(&empty).exists(),
            "prediction created nothing"
        );
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
        let (_, empty) = smoke_paths(doppel).expect("replacement char is representable");
        assert!(
            empty.contains("\u{FFFD}") && empty.ends_with("empty.bin"),
            "doppelganger name passes through exactly: {empty}"
        );
        assert!(!doppel.exists(), "prediction created nothing");
    }
}
