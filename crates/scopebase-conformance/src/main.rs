// SPDX-License-Identifier: Apache-2.0
//! `scopebase-conformance`: installed operator command (TT07).
//!
//! NEW (TT07): no donor lines copied. Thin argv entry point over
//! [`scopebase_conformance::commands`]; all paths are explicit and no
//! repo-relative defaults exist.
//!
//! R03: argv enters via `cli::argv_strings`: non-UTF-8 bytes print the
//! reason plus usage and exit 2, never panic in `env::args()`.

fn main() {
    let code = match scopebase_testkit::cli::argv_strings() {
        Some(argv) => scopebase_conformance::commands::run_argv(&argv),
        None => {
            // Reason first, then the same usage an empty argv gets.
            scopebase_testkit::cli::err_line("scopebase-conformance: argv is not valid Unicode");
            scopebase_conformance::commands::run_argv(&[])
        }
    };
    std::process::exit(code);
}
