// SPDX-License-Identifier: Apache-2.0
//! Held-file inspector binary: smoke scenarios plus three useful modes over
//! real files (`inspect PATH`, `maps`, `walk ROOT`).
//! NEW (LX11): reference-only; no donor lines copied.
use linux_heldfile_reference::adapter::{run_scenario, HeldfileReferenceAdapter};
use scopebase_linux::conformance::FixtureRoot;
use scopebase_testkit::ConformanceAdapter;

fn smoke_root() -> FixtureRoot {
    let name = format!("lx11-heldfile-smoke-{}", std::process::id());
    let root = FixtureRoot::create(&std::env::temp_dir(), &name).expect("smoke root");
    root.write_file("a.txt", b"hello world")
        .expect("smoke file");
    root.write_file("sub/b.txt", b"second")
        .expect("smoke nested");
    root
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        None => smoke(),
        Some("inspect") => {
            let path = args.get(2).expect("usage: inspect PATH");
            let script = format!("case=ok;path={path};");
            match run_scenario("open", script.as_bytes(), None) {
                Some(body) => println!("{body}"),
                None => {
                    eprintln!("inspect refused");
                    std::process::exit(1);
                }
            }
        }
        Some("maps") => {
            let raw = std::fs::read("/proc/self/maps").expect("read own maps");
            match run_scenario("parse-maps", b"case=live;", Some(&raw)) {
                Some(body) => println!("{body}"),
                None => {
                    eprintln!("maps refused");
                    std::process::exit(1);
                }
            }
        }
        Some("walk") => {
            let root = args.get(2).expect("usage: walk ROOT");
            let script = format!("case=ok;root={root};");
            match run_scenario("walk", script.as_bytes(), None) {
                Some(body) => println!("{body}"),
                None => {
                    eprintln!("walk refused");
                    std::process::exit(1);
                }
            }
        }
        Some(other) => {
            eprintln!("unknown mode {other}");
            std::process::exit(1);
        }
    }
}

fn smoke() {
    let adapter = HeldfileReferenceAdapter::new().expect("adapter builds");
    let subject = adapter.subject();
    println!(
        "subject: {} {} consumer={}",
        subject.package_name(),
        subject.package_version(),
        subject.consumer().name()
    );
    let root = smoke_root();
    let file = root.path().join("a.txt");
    let file = file.to_string_lossy().into_owned();
    let root_path = root.path().to_string_lossy().into_owned();
    let mut failed = false;
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
    root.close().expect("smoke cleanup");
    if failed {
        std::process::exit(1);
    }
}
