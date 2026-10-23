// SPDX-License-Identifier: Apache-2.0
//! TT07 downstream consumer binary: runs the delivery profile through the
//! packaged operator library with this crate's own adapter.
//!
//! NEW (TT07): no donor lines copied.
//!
//! Usage: `conformance-client --fixture-root PATH --output PATH
//! [--template PATH]`; `--fixture-root` may be omitted when
//! `CONFORMANCE_FIXTURE_ROOT` is set.

use conformance_client::{fixture_root, RenamedAdapter};
use scopebase_conformance::delivery;
use std::path::PathBuf;

fn usage() -> ! {
    eprintln!(
        "usage: conformance-client [--fixture-root PATH] --output PATH [--template PATH]"
    );
    std::process::exit(2);
}

fn flag_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == name {
            return iter.next().map(String::as_str);
        }
    }
    None
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let root = flag_value(&argv, "--fixture-root")
        .map(PathBuf::from)
        .unwrap_or_else(fixture_root);
    let output = flag_value(&argv, "--output").unwrap_or_else(|| usage());
    let template = flag_value(&argv, "--template").map(PathBuf::from);
    let mut adapter = RenamedAdapter::new().unwrap_or_else(|e| {
        eprintln!("conformance-client: {e}");
        std::process::exit(3);
    });
    let oracle = delivery::DeliveryOracle::new().unwrap_or_else(|e| {
        eprintln!("conformance-client: {e}");
        std::process::exit(3);
    });
    match delivery::run_delivery(delivery::RunRequest {
        catalog_path: root.join("catalog.json"),
        profile: delivery::DELIVERY_PROFILE.into(),
        fixture_root: root,
        manifest_path: None,
        template_path: template,
        output_dir: PathBuf::from(output),
        mapping_policy: "no-new-target-mappings".into(),
        adapter: &mut adapter,
        oracle: &oracle,
    }) {
        Ok(outcome) => {
            println!(
                "qualification={:?} run_id={} receipt={}",
                outcome.qualification,
                outcome.run_id,
                outcome.receipt_path.display()
            );
            std::process::exit(delivery::exit_for_qualification(outcome.qualification));
        }
        Err(error) => {
            eprintln!("conformance-client: {error}");
            std::process::exit(error.exit_code());
        }
    }
}
