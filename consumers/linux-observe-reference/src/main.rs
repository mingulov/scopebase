// SPDX-License-Identifier: Apache-2.0
//! Owned-workload observer binary: smoke scenarios, a useful `observe PID`
//! mode, and the hidden `child SECS` sleep mode the adapter spawns as its
//! hermetic owned workload (no /bin dependency).
//! NEW (LX11): reference-only; no donor lines copied.
use linux_observe_reference::adapter::{run_scenario, ObserveReferenceAdapter};
use scopebase_linux::conformance::FixtureRoot;
use scopebase_testkit::ConformanceAdapter;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        None => smoke(),
        Some("child") => {
            let secs: u64 = args
                .get(2)
                .expect("usage: child SECS")
                .parse()
                .expect("secs");
            std::thread::sleep(std::time::Duration::from_secs(secs));
        }
        Some("observe") => {
            let pid = args.get(2).expect("usage: observe PID");
            let script = format!("case=pid;pid={pid};");
            match run_scenario("acquire", script.as_bytes(), None) {
                Some(body) => println!("{body}"),
                None => {
                    eprintln!("observe refused");
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
    let adapter = ObserveReferenceAdapter::new().expect("adapter builds");
    let subject = adapter.subject();
    println!(
        "subject: {} {} consumer={}",
        subject.package_name(),
        subject.package_version(),
        subject.consumer().name()
    );
    let name = format!("lx11-observe-smoke-{}", std::process::id());
    let root = FixtureRoot::create(&std::env::temp_dir(), &name).expect("smoke root");
    let empty = root.write_file("empty.bin", b"").expect("smoke file");
    let empty = empty.to_string_lossy().into_owned();
    let exe = std::env::current_exe().expect("own binary");
    let exe = exe.to_string_lossy().into_owned();
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
    root.close().expect("smoke cleanup");
    if failed {
        std::process::exit(1);
    }
}
