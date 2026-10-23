// SPDX-License-Identifier: Apache-2.0
//! Owned-workload observer binary: smoke scenarios, a useful `observe PID`
//! mode, and the hidden `child SECS` sleep mode the adapter spawns as its
//! hermetic owned workload (no /bin dependency).
//! NEW (LX11): reference-only; no donor lines copied.
//!
//! F04: every failure below is a message plus an exit code, never a panic:
//! missing/invalid operands are usage errors (exit 2), setup/IO failures exit 1.
use linux_observe_reference::adapter::{run_scenario, script_value, ObserveReferenceAdapter};
use scopebase_linux::conformance::FixtureRoot;
use scopebase_testkit::ConformanceAdapter;

fn main() {
    std::process::exit(run(&std::env::args().collect::<Vec<_>>()));
}

fn run(args: &[String]) -> i32 {
    match args.get(1).map(String::as_str) {
        None => smoke(),
        Some("child") => {
            let Some(raw) = args.get(2) else {
                eprintln!("usage: child SECS");
                return 2;
            };
            let secs: u64 = match raw.parse() {
                Ok(secs) => secs,
                Err(_) => {
                    eprintln!("usage: child SECS (unsigned seconds)");
                    return 2;
                }
            };
            std::thread::sleep(std::time::Duration::from_secs(secs));
            0
        }
        Some("observe") => {
            let Some(pid) = args.get(2) else {
                eprintln!("usage: observe PID");
                return 2;
            };
            let Some(pid) = script_value(pid) else {
                eprintln!("observe refuses PIDs containing ';'");
                return 2;
            };
            let script = format!("case=pid;pid={pid};");
            match run_scenario("acquire", script.as_bytes(), None) {
                Some(body) => {
                    println!("{body}");
                    0
                }
                None => {
                    eprintln!("observe refused");
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
    let adapter = match ObserveReferenceAdapter::new() {
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
    let name = format!("lx11-observe-smoke-{}", std::process::id());
    let root = match FixtureRoot::create(&std::env::temp_dir(), &name) {
        Ok(root) => root,
        Err(error) => {
            eprintln!("smoke root: {error}");
            return 1;
        }
    };
    let empty = match root.write_file("empty.bin", b"") {
        Ok(path) => path.to_string_lossy().into_owned(),
        Err(error) => {
            eprintln!("smoke file: {error}");
            return 1;
        }
    };
    let exe = match std::env::current_exe() {
        Ok(exe) => exe.to_string_lossy().into_owned(),
        Err(error) => {
            eprintln!("own binary: {error}");
            return 1;
        }
    };
    let (Some(exe), Some(empty)) = (script_value(&exe), script_value(&empty)) else {
        eprintln!("smoke paths contain ';'");
        return 1;
    };
    let mut failed = false;
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
}
