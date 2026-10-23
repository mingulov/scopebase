// SPDX-License-Identifier: Apache-2.0
//! MemVeil-shaped reference consumer binary: prints its subject binding
//! and runs two smoke scenarios through the product-shaped reducer.
//! NEW (CP11): reference-only; no donor lines copied.
use capture_memveil_reference::adapter::{run_scenario, MemveilReferenceAdapter};
use scopebase_testkit::ConformanceAdapter;

fn main() {
    let adapter = MemveilReferenceAdapter::new().expect("adapter builds");
    let subject = adapter.subject();
    println!(
        "subject: {} {} consumer={}",
        subject.package_name(),
        subject.package_version(),
        subject.consumer().name()
    );
    let mut failed = false;
    for (op, case, expected) in [
        ("facts", "ok", "match=true;generation=1;"),
        (
            "views",
            "partial-then-final",
            "first=consumed-loss+query-partial;second=consumed-loss;",
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
