// SPDX-License-Identifier: Apache-2.0
//! SDK01 dependency check: the default SDK build depends on the pure
//! `scopebase-capture` API, the `--no-default-features` build is pure std,
//! and neither build admits a BPF/native/Mojo build input. Verified through
//! `cargo tree` in both feature modes.

use std::process::Command;

const BANNED: [&str; 9] = [
    "aya", "libbpf", "mojo", "bpf", "rustix", "libc", "cc", "cmake", "bindgen",
];

fn tree(extra_args: &[&str]) -> String {
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
fn assert_no_banned_inputs(tree: &str) {
    let names: String = tree
        .lines()
        .map(|line| line.split(" (").next().unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in BANNED {
        assert!(
            !names.to_lowercase().contains(banned),
            "dependency tree mentions banned build input {banned}: {tree}"
        );
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
