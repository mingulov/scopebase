// SPDX-License-Identifier: Apache-2.0
//! `scopebase-conformance`: installed operator command (TT07).
//!
//! NEW (TT07): no donor lines copied. Thin argv entry point over
//! [`scopebase_conformance::commands`]; all paths are explicit and no
//! repo-relative defaults exist.

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    std::process::exit(scopebase_conformance::commands::run_argv(&argv));
}
