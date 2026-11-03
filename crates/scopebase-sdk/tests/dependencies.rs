// SPDX-License-Identifier: Apache-2.0
//! SDK01 dependency check: the default SDK build depends on the pure
//! `scopebase-capture` API, the `--no-default-features` build is pure std,
//! and neither build admits a BPF/native/Mojo build input. Verified through
//! `cargo tree` in both feature modes. The tree is scoped to normal edges:
//! dev-dependencies (integration-test-only, e.g. the SDK03 testkit consumer
//! adapter) never ship in either build and are checked separately.

use std::process::Command;

const BANNED: [&str; 9] = [
    "aya", "libbpf", "mojo", "bpf", "rustix", "libc", "cc", "cmake", "bindgen",
];

fn tree(extra_args: &[&str]) -> String {
    tree_edges(extra_args, "normal")
}

fn tree_edges(extra_args: &[&str], edges: &str) -> String {
    let cargo = option_env!("CARGO").unwrap_or("cargo");
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let mut args = vec![
        "tree",
        "--offline",
        "--manifest-path",
        manifest,
        "-p",
        "scopebase-sdk",
        "--prefix",
        "none",
        "--edges",
        edges,
    ];
    args.extend(extra_args.iter().copied());
    let output = Command::new(cargo)
        .args(&args)
        .output()
        .expect("cargo tree runs offline");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Banned-substring scan over package names only: the local checkout path
/// itself may contain them, so strip any " (path)" suffix first.
/// Returns the first banned name found, if any.
fn banned_input_in(tree: &str) -> Option<&'static str> {
    let names: String = tree
        .lines()
        .map(|line| line.split(" (").next().unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n");
    let lowered = names.to_lowercase();
    BANNED.into_iter().find(|banned| lowered.contains(banned))
}

fn assert_no_banned_inputs(tree: &str) {
    if let Some(banned) = banned_input_in(tree) {
        panic!("dependency tree mentions banned build input {banned}: {tree}");
    }
}

#[test]
fn no_default_tree_is_pure_std_without_banned_inputs() {
    let output = tree(&["--no-default-features"]);
    // Zero dependencies means the tree is exactly the one package line;
    // cargo appends the workspace path in parentheses after the version.
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "no-default SDK build must stay dependency-free; unexpected tree: {output}"
    );
    assert!(
        lines[0].starts_with("scopebase-sdk v0.1.0"),
        "unexpected tree root: {output}"
    );
    assert_no_banned_inputs(&output);
}

#[test]
fn default_tree_depends_on_capture_without_banned_inputs() {
    let output = tree(&[]);
    let lines: Vec<&str> = output.lines().collect();
    assert!(
        !lines.is_empty() && lines[0].starts_with("scopebase-sdk v0.1.0"),
        "unexpected tree root: {output}"
    );
    // The SDK depends by default on scopebase-capture's pure API (SDK plan
    // "Default dependency is capture"; SDK design package boundary).
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("scopebase-capture v0.1.0")),
        "default SDK tree must contain scopebase-capture: {output}"
    );
    assert_no_banned_inputs(&output);
}

#[test]
fn build_tree_has_no_banned_inputs() {
    // S176: the banned list targets build-time tools (cc, cmake,
    // bindgen), so build edges must be scanned too — normal/dev-only
    // queries miss a `[build-dependencies]` addition.
    let output = tree_edges(&[], "normal,build");
    assert_no_banned_inputs(&output);
    let build_only = tree_edges(&[], "build");
    assert_no_banned_inputs(&build_only);
}

#[test]
fn banned_scanner_flags_synthetic_tree_lines() {
    // S176 negative control: the scanner must flag a banned name in a
    // synthetic tree line and stay quiet on clean lines.
    assert_eq!(
        banned_input_in("scopebase-sdk v0.1.0\ncc v1.2.3"),
        Some("cc")
    );
    assert_eq!(
        banned_input_in("scopebase-sdk v0.1.0 (/some/cc-path/checkout)"),
        None,
        "checkout paths are stripped before scanning"
    );
    assert_eq!(
        banned_input_in("scopebase-sdk v0.1.0\nscopebase-capture v0.1.0"),
        None
    );
}

#[test]
fn dev_tree_has_testkit_without_banned_inputs() {
    // Integration-test-only edges: the SDK03 consumer adapter uses the
    // testkit's subject/observation types. These never ship in the build,
    // and must not drag a BPF/native/Mojo input into SDK tests either.
    let output = tree_edges(&[], "dev");
    let lines: Vec<&str> = output.lines().collect();
    assert!(
        !lines.is_empty() && lines[0].starts_with("scopebase-sdk v0.1.0"),
        "unexpected tree root: {output}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("scopebase-testkit v0.1.0")),
        "dev tree must contain scopebase-testkit: {output}"
    );
    assert_no_banned_inputs(&output);
}
