// SPDX-License-Identifier: Apache-2.0
//! TT07 CLI dispatch: `scopebase-conformance` subcommands and stable exits.
//!
//! NEW (TT07): no donor lines copied.
//!
//! Pure argv-to-exit dispatch over explicit paths; no repo-relative defaults.
//! All commands accept only explicit `--flag value` options (plus `--help`).

use crate::error::{OperatorError, OperatorErrorKind, EXIT_OK};
pub use crate::error::exit_for_kind;
use scopebase_testkit::cli;
use std::path::PathBuf;

const USAGE: &str = "usage:
\tscopebase-conformance describe --catalog PATH
\tscopebase-conformance plan --catalog PATH --profile ID --fixture-root PATH [--mapping-policy POLICY]
\tscopebase-conformance run --catalog PATH --profile ID --fixture-root PATH --output PATH [--fixture-manifest PATH] [--contract-template PATH] [--mapping-policy POLICY]
\tscopebase-conformance verify-receipt PATH [--catalog PATH]
\tscopebase-conformance cleanup --run PATH [--expect-run-id ID]
exits: 0 success, 1 verdict failure, 2 usage, 3 incomplete, 64 broken package";

/// Dispatch argv (including argv[0]) and return the process exit code.
pub fn run_argv(argv: &[String]) -> i32 {
    match dispatch(argv) {
        Ok(()) => EXIT_OK,
        Err(error) => {
            // R04: the code is already determined; a dead stderr
            // cannot change it and must not panic for a second report.
            cli::err_line(&format!("scopebase-conformance: {error}"));
            error.exit_code()
        }
    }
}

/// R04: serialize one report (serialization failure is an engine
/// error, never an unwrap) and emit it (stream failure is
/// `OutputFailed`, never a `println!` panic).
fn render<T: serde::Serialize>(value: &T) -> Result<String, OperatorError> {
    serde_json::to_string_pretty(value).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::Engine,
            format!("report serialization failed: {e}"),
        )
    })
}

fn emit(report: &str) -> Result<(), OperatorError> {
    if cli::put_line(report) {
        Ok(())
    } else {
        Err(OperatorError::new(
            OperatorErrorKind::OutputFailed,
            "cannot write report to stdout",
        ))
    }
}

fn dispatch(argv: &[String]) -> Result<(), OperatorError> {
    let usage = || OperatorError::new(OperatorErrorKind::Usage, USAGE);
    if argv.len() < 2 {
        cli::err_line(USAGE);
        return Err(usage());
    }
    if argv[1] == "--help" || argv[1] == "-h" || argv[1] == "help" {
        return emit(USAGE);
    }
    match argv[1].as_str() {
        "describe" => {
            let catalog = required(&argv[2..], "--catalog")?;
            reject_unknown(
                &argv[2..],
                &["--catalog"],
                &["describe --catalog PATH"],
            )?;
            let bytes = std::fs::read(catalog).map_err(|e| {
                OperatorError::new(
                    OperatorErrorKind::MissingInput,
                    format!("cannot read catalog {catalog}: {e}"),
                )
            })?;
            let description = crate::describe::describe(&bytes)?;
            emit(&render(&description)?)
        }
        "plan" => {
            let catalog = required(&argv[2..], "--catalog")?;
            let profile = required(&argv[2..], "--profile")?;
            let fixture_root = required(&argv[2..], "--fixture-root")?;
            let policy = optional(&argv[2..], "--mapping-policy", "no-new-target-mappings");
            reject_unknown(
                &argv[2..],
                &["--catalog", "--profile", "--fixture-root", "--mapping-policy"],
                &["plan --catalog PATH --profile ID --fixture-root PATH"],
            )?;
            let bytes = std::fs::read(catalog).map_err(|e| {
                OperatorError::new(
                    OperatorErrorKind::MissingInput,
                    format!("cannot read catalog {catalog}: {e}"),
                )
            })?;
            let doc = crate::plan::plan(&bytes, profile, PathBuf::from(fixture_root).as_path(), policy)?;
            emit(&render(&doc)?)
        }
        "run" => {
            let catalog = required(&argv[2..], "--catalog")?;
            let profile = required(&argv[2..], "--profile")?;
            let fixture_root = required(&argv[2..], "--fixture-root")?;
            let output = required(&argv[2..], "--output")?;
            let manifest = flag_value(&argv[2..], "--fixture-manifest").map(PathBuf::from);
            let template = flag_value(&argv[2..], "--contract-template").map(PathBuf::from);
            let policy = optional(&argv[2..], "--mapping-policy", "no-new-target-mappings");
            reject_unknown(
                &argv[2..],
                &[
                    "--catalog",
                    "--profile",
                    "--fixture-root",
                    "--output",
                    "--fixture-manifest",
                    "--contract-template",
                    "--mapping-policy",
                ],
                &["run --catalog PATH --profile ID --fixture-root PATH --output PATH"],
            )?;
            let mut adapter = crate::delivery::DeliveryAdapter::new()?;
            let oracle = crate::delivery::DeliveryOracle::new()?;
            let outcome = crate::delivery::run_delivery(crate::delivery::RunRequest {
                catalog_path: PathBuf::from(catalog),
                profile: profile.to_string(),
                fixture_root: PathBuf::from(fixture_root),
                manifest_path: manifest,
                template_path: template,
                output_dir: PathBuf::from(output),
                mapping_policy: policy.to_string(),
                adapter: &mut adapter,
                oracle: &oracle,
            })?;
            emit(&render(&serde_json::json!({
                "qualification": format!("{:?}", outcome.qualification).to_lowercase(),
                "run_id": outcome.run_id,
                "receipt": outcome.receipt_path.to_string_lossy(),
            }))?)?;
            let code = crate::delivery::exit_for_qualification(outcome.qualification);
            if code == EXIT_OK {
                Ok(())
            } else {
                Err(OperatorError::new(
                    if code == crate::error::EXIT_INCOMPLETE {
                        OperatorErrorKind::ClosureIncomplete
                    } else {
                        OperatorErrorKind::Engine
                    },
                    format!("run ended {:?}", outcome.qualification),
                ))
            }
        }
        "verify-receipt" => {
            let rest = &argv[2..];
            let target = rest
                .iter()
                .find(|a| !a.starts_with("--"))
                .ok_or_else(usage)?;
            let catalog = flag_value(rest, "--catalog");
            reject_unknown(rest, &["--catalog"], &["verify-receipt PATH [--catalog PATH]"])?;
            let report = match catalog {
                Some(path) => {
                    let bytes = std::fs::read(path).map_err(|e| {
                        OperatorError::new(
                            OperatorErrorKind::MissingInput,
                            format!("cannot read catalog {path}: {e}"),
                        )
                    })?;
                    crate::receipt::verify_receipt_with_catalog(
                        PathBuf::from(target).as_path(),
                        &bytes,
                    )?
                }
                None => crate::receipt::verify_receipt(PathBuf::from(target).as_path())?,
            };
            emit(&render(&serde_json::json!({
                "schema": report.schema,
                "run_id": report.run_id,
                "profile": report.profile,
                "qualification": format!("{:?}", report.qualification).to_lowercase(),
                "runtime_authority": report.runtime_authority,
            }))?)
        }
        "cleanup" => {
            let run = required(&argv[2..], "--run")?;
            let expected = flag_value(&argv[2..], "--expect-run-id");
            reject_unknown(&argv[2..], &["--run", "--expect-run-id"], &["cleanup --run PATH"])?;
            let report = crate::cleanup::cleanup_run(
                PathBuf::from(run).as_path(),
                expected.map(str::to_string).as_deref(),
            )?;
            emit(&render(&serde_json::json!({
                "removed_run_id": report.run_id,
                "profile": report.profile,
            }))?)
        }
        _ => {
            cli::err_line(USAGE);
            Err(usage())
        }
    }
}

fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str, OperatorError> {
    flag_value(args, name).ok_or_else(|| {
        OperatorError::new(
            OperatorErrorKind::Usage,
            format!("missing required {name}"),
        )
    })
}

fn flag_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == name {
            // F33: a following option is not a value (values starting
            // with `--` use the `--flag=value` form). The arity error is
            // reported by reject_unknown; lookup yields nothing here so a
            // missing value can never be misread as the next flag.
            return iter
                .next()
                .filter(|next| !next.starts_with("--"))
                .map(String::as_str);
        }
        if let Some(value) = arg.strip_prefix(&format!("{name}=")) {
            return Some(value);
        }
    }
    None
}

fn optional<'a>(args: &'a [String], name: &str, default: &'a str) -> &'a str {
    flag_value(args, name).unwrap_or(default)
}

fn reject_unknown(args: &[String], known: &[&str], forms: &[&str]) -> Result<(), OperatorError> {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg.starts_with("--") {
            let name = arg.split('=').next().unwrap_or(arg);
            if !known.contains(&name) {
                return Err(OperatorError::new(
                    OperatorErrorKind::Usage,
                    format!("unknown option {name}; expected {}", forms.join(" | ")),
                ));
            }
            // F33: space-form options require a non-option value. A
            // missing value or a following option is a usage error, never
            // a silent default.
            if !arg.contains('=') {
                match iter.peek() {
                    Some(next) if !next.starts_with("--") => {
                        iter.next();
                    }
                    _ => {
                        return Err(OperatorError::new(
                            OperatorErrorKind::Usage,
                            format!(
                                "option {name} needs a value; expected {}",
                                forms.join(" | ")
                            ),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
