// SPDX-License-Identifier: Apache-2.0
//! Held-file inspector binary: smoke scenarios plus three useful modes over
//! real files (`inspect PATH`, `maps`, `walk ROOT`).
//! NEW (LX11): reference-only; no donor lines copied.
//!
//! F04: every failure below is a message plus an exit code, never a panic:
//! missing operands are usage errors (exit 2), setup/IO failures exit 1.
use linux_heldfile_reference::adapter::{run_scenario, script_value, HeldfileReferenceAdapter};
use scopebase_linux::conformance::FixtureRoot;
use scopebase_testkit::ConformanceAdapter;

fn smoke_root() -> Result<FixtureRoot, String> {
    let name = format!("lx11-heldfile-smoke-{}", std::process::id());
    let root =
        FixtureRoot::create(&std::env::temp_dir(), &name).map_err(|e| format!("smoke root: {e}"))?;
    root.write_file("a.txt", b"hello world")
        .map_err(|e| format!("smoke file: {e}"))?;
    root.write_file("sub/b.txt", b"second")
        .map_err(|e| format!("smoke nested: {e}"))?;
    Ok(root)
}

fn main() {
    std::process::exit(run(&std::env::args().collect::<Vec<_>>()));
}

fn run(args: &[String]) -> i32 {
    match args.get(1).map(String::as_str) {
        None => smoke(),
        Some("inspect") => {
            let Some(path) = args.get(2) else {
                eprintln!("usage: inspect PATH");
                return 2;
            };
            let Some(path) = script_value(path) else {
                eprintln!("inspect refuses paths containing ';'");
                return 2;
            };
            let script = format!("case=ok;path={path};");
            match run_scenario("open", script.as_bytes(), None) {
                Some(body) => {
                    println!("{body}");
                    0
                }
                None => {
                    eprintln!("inspect refused");
                    1
                }
            }
        }
        Some("maps") => {
            let raw = match std::fs::read("/proc/self/maps") {
                Ok(raw) => raw,
                Err(error) => {
                    eprintln!("cannot read own maps: {error}");
                    return 1;
                }
            };
            match run_scenario("parse-maps", b"case=live;", Some(&raw)) {
                Some(body) => {
                    println!("{body}");
                    0
                }
                None => {
                    eprintln!("maps refused");
                    1
                }
            }
        }
        Some("walk") => {
            let Some(root) = args.get(2) else {
                eprintln!("usage: walk ROOT");
                return 2;
            };
            let Some(root) = script_value(root) else {
                eprintln!("walk refuses roots containing ';'");
                return 2;
            };
            let script = format!("case=ok;root={root};");
            match run_scenario("walk", script.as_bytes(), None) {
                Some(body) => {
                    println!("{body}");
                    0
                }
                None => {
                    eprintln!("walk refused");
                    1
                }
            }
        }
        Some(other) => {
            eprintln!("unknown mode {other}");
            1
        }
    }
}

fn smoke() -> i32 {
    let adapter = match HeldfileReferenceAdapter::new() {
        Ok(adapter) => adapter,
        Err(error) => {
            eprintln!("adapter builds: {error}");
            return 1;
        }
    };
    let subject = adapter.subject();
    println!(
        "subject: {} {} consumer={}",
        subject.package_name(),
        subject.package_version(),
        subject.consumer().name()
    );
    let root = match smoke_root() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("{error}");
            return 1;
        }
    };
    let file = root.path().join("a.txt");
    let file = file.to_string_lossy().into_owned();
    let root_path = root.path().to_string_lossy().into_owned();
    let (Some(file), Some(root_path)) = (script_value(&file), script_value(&root_path)) else {
        eprintln!("smoke paths contain ';'");
        return 1;
    };
    let mut failed = false;
    for (op, script, body, expected) in [
        ("open", format!("case=ok;path={file};"), None, "stat=len:11;"),
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
                println!("{op}: {got}");
                if got != expected {
                    failed = true;
                }
            }
            None => {
                println!("{op}: refused");
                failed = true;
            }
        }
    }
    if let Err(error) = root.close() {
        eprintln!("smoke cleanup: {error}");
        return 1;
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
}
