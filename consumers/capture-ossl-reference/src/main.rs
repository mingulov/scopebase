// SPDX-License-Identifier: Apache-2.0
//! OSSL-shaped reference consumer binary: prints its subject binding
//! and runs two smoke scenarios through the product-shaped reducer.
//! NEW (CP11): reference-only; no donor lines copied.
use capture_ossl_reference::adapter::{run_scenario, OsslReferenceAdapter};
use scopebase_testkit::ConformanceAdapter;

fn main() {
    let adapter = OsslReferenceAdapter::new().expect("adapter builds");
    let subject = adapter.subject();
    println!(
        "subject: {} {} consumer={}",
        subject.package_name(),
        subject.package_version(),
        subject.consumer().name()
    );
    let mut failed = false;
    for (op, case, expected) in [
        ("bounds", "shared", "lower=0;upper=10;"),
        (
            "neutral",
            "ok",
            "counters=1;losses=1;signals=1;claims=1;partitions=1;corrections=1;",
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
