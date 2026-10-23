// SPDX-License-Identifier: Apache-2.0
//! KryProbe-shaped reference consumer binary: prints its subject binding
//! and runs two smoke scenarios through the product-shaped reducer.
//! NEW (CP11): reference-only; no donor lines copied.
use capture_kryprobe_reference::adapter::{run_scenario, KryprobeReferenceAdapter};
use scopebase_testkit::ConformanceAdapter;

fn main() {
    let adapter = KryprobeReferenceAdapter::new().expect("adapter builds");
    let subject = adapter.subject();
    println!(
        "subject: {} {} consumer={}",
        subject.package_name(),
        subject.package_version(),
        subject.consumer().name()
    );
    let mut failed = false;
    for (op, case, expected) in [
        ("fold", "ok", "total=10;owner=7;"),
        (
            "holder",
            "agree",
            "report_rev1=true;export_rev1=true;report_value=7;export_value=7;agree=true;",
        ),
    ] {
        match run_scenario(op, case) {
            Some(Ok(body)) => {
                println!("{op}/{case}: {body}");
                if body != expected {
                    failed = true;
                }
            }
            other => {
                println!("{op}/{case}: unexpected {other:?}");
                failed = true;
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
}
