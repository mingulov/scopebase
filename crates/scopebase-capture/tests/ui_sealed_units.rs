// SPDX-License-Identifier: Apache-2.0
//! S170: the nine pre-CP05 sealed-unit UI fixtures are compiled by this
//! harness — six must fail with their labeled error, three must pass.
//! (The finding's tenth name, `counter_units_match.rs`, never existed.)

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

/// (file, must_pass, expected error code when failing).
const FIXTURES: &[(&str, bool, &str)] = &[
    ("sealed_unit.rs", false, "E0277"),
    ("count_units_do_not_mix.rs", false, "E0308"),
    ("count_units_match.rs", true, ""),
    ("counter_units_do_not_mix.rs", false, "E0308"),
    ("cp03_units_match.rs", true, ""),
    ("cp04_units_match.rs", true, ""),
    ("private_capture_id.rs", false, "E0423"),
    ("provenance_units_do_not_mix.rs", false, "E0308"),
    ("signal_is_not_event_loss.rs", false, "E0308"),
];

fn workspace_target() -> PathBuf {
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(dir);
    }
    Path::new(MANIFEST_DIR).join("../../target")
}

/// X2: newest mtime under `src_dir` (bounded walk); the subject
/// rlib must be at least this new, mirroring cargo's own
/// freshness rule.
fn newest_src_mtime(src_dir: &Path) -> std::io::Result<std::time::SystemTime> {
    const CAP: usize = 65536;
    let mut newest = SystemTime::UNIX_EPOCH;
    let mut stack = vec![src_dir.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            seen += 1;
            if seen > CAP {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::QuotaExceeded,
                    format!("src walk exceeded {CAP} entries"),
                ));
            }
            let entry = entry?;
            let meta = std::fs::symlink_metadata(entry.path())?;
            if meta.is_dir() {
                stack.push(entry.path());
            } else if let Ok(mtime) = meta.modified() {
                newest = newest.max(mtime);
            }
        }
    }
    Ok(newest)
}

/// X2: the harness's own subject-feature set, mirrored from the
/// crate's cargo features. `default` is normalized out by the
/// matcher: it enables nothing in this crate, so default/on and
/// default/off builds of the same meaningful features are
/// equivalent subjects. Extend this when the crate gains a feature
/// the fixtures can observe — an unlisted feature refuses loudly
/// instead of testing a mismatched build.
fn own_features() -> Vec<&'static str> {
    let mut feats = Vec::new();
    if cfg!(feature = "json") {
        feats.push("json");
    }
    feats
}

/// X2/Y5: read the feature list cargo recorded for the `libscopebase_capture-<hash>`
/// build. Cargo stores it as an escaped-JSON string
/// (`"features":"[\"default\", \"json\"]"`). Strict at both layers:
/// only valid JSON escapes, the value followed by `,` or `}`, and a
/// plain `["name", ...]` inner list (no nested escapes, at most 64
/// names of 64 bytes); anything else yields `None` so the caller
/// refuses rather than guesses. The REST of the fingerprint object
/// is not validated — only the extracted value's local shape.
fn fingerprint_features(deps_dir: &Path, hash: &str) -> Option<Vec<String>> {
    let path = deps_dir
        .parent()?
        .join(".fingerprint")
        .join(format!("scopebase-capture-{hash}"))
        .join("lib-scopebase_capture.json");
    let text = std::fs::read_to_string(path).ok()?;
    if text.len() > 1_048_576 {
        return None;
    }
    let key = text.find("\"features\"")?;
    let after_key = text[key + "\"features\"".len()..].strip_prefix(':')?;
    let quoted = after_key.trim_start().strip_prefix('"')?;
    // Y5: strict JSON string unescape — only the seven short escapes
    // plus `\uXXXX` with four hex digits; anything else refuses.
    let mut inner = String::new();
    let mut chars = quoted.chars();
    let mut closed = false;
    while let Some(c) = chars.next() {
        if inner.len() > 4096 {
            return None;
        }
        if c == '\\' {
            match chars.next()? {
                '"' => inner.push('"'),
                '\\' => inner.push('\\'),
                '/' => inner.push('/'),
                'b' => inner.push('\u{0008}'),
                'f' => inner.push('\u{000C}'),
                'n' => inner.push('\n'),
                'r' => inner.push('\r'),
                't' => inner.push('\t'),
                'u' => {
                    let mut hex = String::new();
                    for _ in 0..4 {
                        let h = chars.next()?;
                        if !h.is_ascii_hexdigit() {
                            return None;
                        }
                        hex.push(h);
                    }
                    inner.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                _ => return None,
            }
        } else if c == '"' {
            closed = true;
            break;
        } else if (c as u32) < 0x20 {
            return None;
        } else {
            inner.push(c);
        }
    }
    if !closed {
        return None;
    }
    // The value must be followed by `,` or `}` — trailing garbage
    // means the enclosing JSON is not what we parsed.
    match chars.as_str().trim_start().chars().next()? {
        ',' | '}' => {}
        _ => return None,
    }
    // Inner shape: `["default", "json"]`.
    let list = inner.trim().strip_prefix('[')?.strip_suffix(']')?;
    if list.trim().is_empty() {
        return Some(Vec::new());
    }
    let mut feats = Vec::new();
    for item in list.split(',') {
        if feats.len() >= 64 {
            return None;
        }
        let item = item.trim().strip_prefix('"')?.strip_suffix('"')?;
        if item.is_empty() || item.len() > 64 || item.contains('\\') || item.contains('"') {
            return None;
        }
        feats.push(item.to_string());
    }
    Some(feats)
}

/// Z2: verify the candidate rlib was built from THIS checkout by
/// its EMBEDDED absolute source paths (both profiles carry them —
/// 169 hits in debug, 37 in release). Dep-info cannot serve: cargo
/// records workspace-relative paths, so a same-layout foreign
/// checkout emits identical dep text. For each `/src/<name>.rs`
/// path extracted from the rlib bytes: canonicalize-under-
/// `manifest_dir` verifies; a `scopebase-capture*`-segmented path
/// anywhere else is a foreign shadow and vetoes; anything else
/// (registry sources, build artifacts) is ignored. At least one
/// verified path is required — a pathless (stripped, remapped)
/// rlib fails closed.
///
/// Threat boundary: defeats accidental cross-checkout reuse
/// (shared `CARGO_TARGET_DIR`, stale hashes, same-layout twins)
/// — not a saboteur with write access to the target dir, who
/// could plant a crafted rlib outright.
fn rlib_origin_ok(rlib: &Path, manifest_dir: &Path) -> bool {
    const CAP: u64 = 128 * 1024 * 1024;
    let bytes = match std::fs::read(rlib) {
        Ok(b) if b.len() as u64 <= CAP => b,
        _ => return false,
    };
    let manifest_canon = match std::fs::canonicalize(manifest_dir) {
        Ok(p) => p,
        Err(_) => return false,
    };
    fn is_path_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'+')
    }
    fn is_name_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_')
    }
    let mut verified = 0usize;
    let mut i = 0usize;
    while i + 5 <= bytes.len() {
        if &bytes[i..i + 5] != b"/src/" {
            i += 1;
            continue;
        }
        let mut s = i;
        while s > 0 && is_path_byte(bytes[s - 1]) {
            if i - s > 4096 {
                break;
            }
            s -= 1;
        }
        let mut e = i + 5;
        while e < bytes.len() && is_name_byte(bytes[e]) {
            if e - (i + 5) > 128 {
                break;
            }
            e += 1;
        }
        let at = i;
        i = e.max(i + 1);
        let Ok(cand) = std::str::from_utf8(&bytes[s..e]) else {
            continue;
        };
        if !cand.starts_with('/') || !cand.ends_with(".rs") {
            continue;
        }
        // Strict file-name shape: `/src/<alnum_…>.rs`, non-empty stem.
        let after_src = &cand[at - s + 5..];
        if after_src.len() <= 3
            || !after_src[..after_src.len() - 3]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        match std::fs::canonicalize(cand) {
            Ok(p) if p.starts_with(&manifest_canon) => verified += 1,
            _ => {
                if cand.rsplit('/').take(4).any(|seg| seg.starts_with("scopebase-capture")) {
                    return false;
                }
            }
        }
    }
    verified >= 1
}

/// X2/Z2: select the subject rlib bound to this test build: the
/// deps dir binds profile/target, the mtime floor refuses stale
/// candidates loudly, embedded-path origin verification rejects
/// cross-checkout artifacts (including same-layout twins), and
/// among surviving candidates only an exact feature match wins.
/// Same-feature survivors pick newest mtime (cargo's latest
/// verified build of these sources); exact mtime ties fail closed
/// — never lexicographic order, never a silent fallback to
/// another build.
fn select_subject_rlib(
    deps_dir: &Path,
    src_dir: &Path,
    want: &[&str],
    manifest_dir: &Path,
) -> Result<PathBuf, String> {
    let floor = newest_src_mtime(src_dir).map_err(|e| format!("src mtime unreadable: {e}"))?;
    let entries =
        std::fs::read_dir(deps_dir).map_err(|e| format!("deps unreadable {}: {e}", deps_dir.display()))?;
    let mut fresh: Vec<(SystemTime, PathBuf, String)> = Vec::new();
    let mut stale = 0usize;
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let hash = name
            .strip_prefix("libscopebase_capture-")
            .and_then(|s| s.strip_suffix(".rlib"));
        let Some(hash) = hash else { continue };
        let hash = hash.to_string();
        match std::fs::metadata(&path).and_then(|m| m.modified()) {
            Ok(mtime) if mtime >= floor => fresh.push((mtime, path, hash)),
            _ => stale += 1,
        }
    }
    if fresh.is_empty() {
        return Err(format!(
            "stale subject: {stale} libscopebase_capture rlib(s) under {} all predate the subject sources; rebuild",
            deps_dir.display()
        ));
    }
    // Exact feature match among fresh candidates (`default`
    // normalized out — see `own_features`). An unreadable
    // fingerprint never matches: refuse rather than guess. Z2: a
    // feature match must also prove embedded origin — a newer
    // same-feature rlib from another checkout sharing the target
    // dir loses to an older own-checkout build.
    let mut want: Vec<&str> = want.to_vec();
    want.sort_unstable();
    let mut found: Vec<String> = Vec::new();
    let mut foreign: Vec<String> = Vec::new();
    let mut matching: Vec<(SystemTime, PathBuf, String)> = Vec::new();
    for (mtime, path, hash) in &fresh {
        let Some(mut feats) = fingerprint_features(deps_dir, hash) else {
            found.push(format!("{hash}=<?>"));
            continue;
        };
        feats.retain(|f| f != "default");
        feats.sort();
        found.push(format!("{hash}={feats:?}"));
        if !feats.iter().map(String::as_str).eq(want.iter().copied()) {
            continue;
        }
        if !rlib_origin_ok(path, manifest_dir) {
            foreign.push(hash.clone());
            continue;
        }
        matching.push((*mtime, path.clone(), hash.clone()));
    }
    matching.sort();
    if let Some((when, hit, _)) = matching.pop() {
        // Y2: exact mtime ties fail closed — no pathname
        // tie-break between indistinguishable builds.
        if let Some((tied, tied_path, _)) = matching.pop() {
            if tied == when {
                return Err(format!(
                    "stale subject: ambiguous subject rlibs with equal mtime: {} and {}; rebuild to disambiguate",
                    hit.display(),
                    tied_path.display(),
                ));
            }
        }
        return Ok(hit);
    }
    if !foreign.is_empty() {
        return Err(format!(
            "stale subject: {} fresh feature-matching rlib(s) under {} have foreign or unverifiable embedded origin ({}); expected sources under {}",
            foreign.len(),
            deps_dir.display(),
            foreign.join(","),
            manifest_dir.display(),
        ));
    }
    Err(format!(
        "stale subject: no exact feature match for {want:?} among fresh rlibs under {}; found {}; extend own_features() if the crate gained a feature",
        deps_dir.display(),
        found.join(","),
    ))
}

fn subject_rlib() -> PathBuf {
    // X2: the deps dir holding the running test binary binds the
    // profile, target triple, and target dir to THIS build — no
    // debug-before-release guess, no workspace-layout assumption.
    let manifest_dir = Path::new(MANIFEST_DIR);
    let src_dir = manifest_dir.join("src");
    let want = own_features();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(deps) = exe.parent() {
            if deps.file_name().is_some_and(|n| n == "deps") {
                match select_subject_rlib(deps, &src_dir, &want, manifest_dir) {
                    Ok(hit) => return hit,
                    Err(e) => panic!("{e}"),
                }
            }
        }
    }
    for profile in ["debug", "release"] {
        let deps = workspace_target().join(profile).join("deps");
        if let Ok(hit) = select_subject_rlib(&deps, &src_dir, &want, manifest_dir) {
            return hit;
        }
    }
    panic!("libscopebase_capture rlib not found under {}", workspace_target().display());
}

#[test]
fn sealed_unit_fixtures_hold() {
    let rlib = subject_rlib();
    let deps = rlib.parent().unwrap().to_path_buf();
    let out_dir = std::env::temp_dir().join(format!("s170-ui-{}", std::process::id()));
    std::fs::create_dir_all(&out_dir).unwrap();
    for (file, must_pass, code) in FIXTURES {
        let source = Path::new(MANIFEST_DIR).join("tests/ui").join(file);
        assert!(source.is_file(), "fixture present: {file}");
        let output = out_dir.join(file.replace(".rs", ""));
        let output = Command::new("rustc")
            .args([
                "--edition=2021",
                "--crate-type=bin",
                "-L",
                deps.to_str().unwrap(),
                "--extern",
                &format!("scopebase_capture={}", rlib.display()),
                "-o",
                output.to_str().unwrap(),
            ])
            .arg(&source)
            .output()
            .unwrap_or_else(|e| panic!("rustc {file}: {e}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        if *must_pass {
            assert!(output.status.success(), "{file} must compile: {stderr}");
        } else {
            assert!(!output.status.success(), "{file} must fail to compile");
            assert!(
                stderr.contains(&format!("[{code}]")),
                "{file} must fail with {code}: {stderr}"
            );
        }
    }
    std::fs::remove_dir_all(&out_dir).unwrap();
}

#[cfg(test)]
mod x2_tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "s170-x2-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("deps")).unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        // The scratch root plays the package dir (origin boundary)
        // in these tests.
        dir
    }

    fn plant(path: &Path, age: Duration) {
        std::fs::write(path, b"x").unwrap();
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(SystemTime::now() - age).unwrap();
    }

    /// Plant a cargo-shaped fingerprint for a fake `libscopebase_capture-<hash>.rlib`.
    fn plant_fingerprint(root: &Path, hash: &str, features: &str) {
        let dir = root.join(".fingerprint").join(format!("scopebase-capture-{hash}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("lib-scopebase_capture.json"),
            format!("{{\"rustc\":1,\"features\":{features:?},\"target\":2}}"),
        )
        .unwrap();
    }

    /// Plant a fake rlib whose bytes embed `origin` as an
    /// absolute `/src/lib.rs` source path (mirrors the real
    /// embedded paths both profiles carry), with `age` mtime.
    fn plant_rlib(path: &Path, age: Duration, origin: &Path) {
        let body = format!("\0RUSTC\0{}/src/lib.rs\0", origin.display());
        std::fs::write(path, body.as_bytes()).unwrap();
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(SystemTime::now() - age).unwrap();
    }

    /// X2: lexicographic order must not select the subject — the
    /// stale `zzz` rlib loses to the fresh `aaa` one.
    #[test]
    fn selects_fresh_over_lexicographic_last() {
        let root = scratch("fresh");
        plant(&root.join("src/lib.rs"), Duration::from_secs(60));
        plant_rlib(
            &root.join("deps/libscopebase_capture-aaa.rlib"),
            Duration::from_secs(30),
            &root,
        );
        plant_rlib(
            &root.join("deps/libscopebase_capture-zzz.rlib"),
            Duration::from_secs(3600),
            &root,
        );
        plant_fingerprint(&root, "aaa", "[\"default\"]");
        plant_fingerprint(&root, "zzz", "[\"default\"]");
        let hit = select_subject_rlib(&root.join("deps"), &root.join("src"), &[], &root).unwrap();
        assert!(
            hit.file_name().unwrap().to_str().unwrap().contains("aaa"),
            "stale lexicographic-last rlib selected: {}",
            hit.display()
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// X2: when every candidate predates the subject sources, refuse
    /// loudly instead of testing a stale library.
    #[test]
    fn refuses_all_stale_candidates() {
        let root = scratch("stale");
        plant(&root.join("src/lib.rs"), Duration::from_secs(60));
        plant_rlib(
            &root.join("deps/libscopebase_capture-aaa.rlib"),
            Duration::from_secs(3600),
            &root,
        );
        plant_fingerprint(&root, "aaa", "[\"default\"]");
        let err = select_subject_rlib(&root.join("deps"), &root.join("src"), &[], &root).unwrap_err();
        assert!(
            err.contains("stale"),
            "staleness must be loud: {err}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// X2: the profile/target binding assumes the test binary runs
    /// from a cargo `deps` dir — pin that so a layout change fails
    /// loudly instead of silently falling back to a guessed path.
    #[test]
    fn test_binary_runs_from_cargo_deps_dir() {
        let exe = std::env::current_exe().unwrap();
        assert_eq!(
            exe.parent().unwrap().file_name().unwrap(),
            "deps",
            "binding assumption broken: {exe:?}"
        );
    }

    /// X2: exact feature binding beats newer-mtime — the fresh
    /// `zzz` rlib carries `json` but the harness wants the plain
    /// build, so the older `aaa` wins.
    #[test]
    fn selects_exact_feature_build_over_newer_mismatch() {
        let root = scratch("feat");
        plant(&root.join("src/lib.rs"), Duration::from_secs(3600));
        plant_rlib(
            &root.join("deps/libscopebase_capture-aaa.rlib"),
            Duration::from_secs(60),
            &root,
        );
        plant_rlib(
            &root.join("deps/libscopebase_capture-zzz.rlib"),
            Duration::from_secs(10),
            &root,
        );
        plant_fingerprint(&root, "aaa", "[\"default\"]");
        plant_fingerprint(&root, "zzz", "[\"default\", \"json\"]");
        let hit = select_subject_rlib(&root.join("deps"), &root.join("src"), &[], &root).unwrap();
        assert!(
            hit.file_name().unwrap().to_str().unwrap().contains("aaa"),
            "wrong-feature rlib selected: {}",
            hit.display()
        );
        let hit = select_subject_rlib(&root.join("deps"), &root.join("src"), &["json"], &root).unwrap();
        assert!(
            hit.file_name().unwrap().to_str().unwrap().contains("zzz"),
            "json build not selected: {}",
            hit.display()
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// X2: no exact feature match refuses loudly instead of testing
    /// an arbitrary cached feature build.
    #[test]
    fn refuses_without_exact_feature_match() {
        let root = scratch("nomatch");
        plant(&root.join("src/lib.rs"), Duration::from_secs(3600));
        plant_rlib(
            &root.join("deps/libscopebase_capture-aaa.rlib"),
            Duration::from_secs(10),
            &root,
        );
        plant_fingerprint(&root, "aaa", "[\"default\"]");
        let err = select_subject_rlib(&root.join("deps"), &root.join("src"), &["json"], &root).unwrap_err();
        assert!(err.contains("no exact feature match"), "must be loud: {err}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// X2: the fingerprint reader handles cargo's real shape —
    /// `features` as an escaped-JSON string among other keys.
    #[test]
    fn reads_cargo_shaped_fingerprint_features() {
        let root = scratch("parse");
        let dir = root.join(".fingerprint").join("scopebase-capture-aaa");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("lib-scopebase_capture.json"),
            "{\"rustc\":1625334936438085654,\"features\":\"[\\\"default\\\", \\\"json\\\"]\",\"target\":1}",
        )
        .unwrap();
        assert_eq!(
            fingerprint_features(&root.join("deps"), "aaa"),
            Some(vec!["default".to_string(), "json".to_string()])
        );
        assert_eq!(fingerprint_features(&root.join("deps"), "missing"), None);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// X2: end-to-end — the rlib `subject_rlib()` binds for THIS
    /// test invocation carries exactly the harness's own feature
    /// set. Runs in every profile/feature combo CI exercises.
    #[test]
    fn subject_binding_matches_own_features() {
        let hit = subject_rlib();
        let name = hit.file_name().unwrap().to_str().unwrap();
        let hash = name
            .strip_prefix("libscopebase_capture-")
            .unwrap()
            .strip_suffix(".rlib")
            .unwrap();
        let mut feats =
            fingerprint_features(hit.parent().unwrap(), hash).expect("bound rlib fingerprinted");
        feats.retain(|f| f != "default");
        feats.sort();
        let mut want: Vec<String> = own_features().iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(feats, want, "bound subject feature mismatch: {hit:?}");
        assert!(
            rlib_origin_ok(&hit, Path::new(MANIFEST_DIR)),
            "bound subject built from foreign sources: {hit:?}"
        );
    }

    /// Y5: malformed fingerprints refuse — invalid escapes,
    /// trailing garbage, truncation, and non-string values all
    /// yield `None` instead of a guessed feature set.
    #[test]
    fn rejects_malformed_fingerprint_json() {
        let root = scratch("malformed");
        let dir = root.join(".fingerprint").join("scopebase-capture-aaa");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("lib-scopebase_capture.json");
        for bad in [
            "{\"features\":\"[\\\"a\\x\\\"]\"}",   // invalid escape
            "{\"features\":\"[\\\"a\\\"]\"zzz}",   // trailing garbage
            "{\"features\":\"[\\\"a\\\"",          // truncated
            "{\"features\":[\"a\"]}",              // non-string value
            "{\"features\":\"[\\\"a\\\",]}",       // trailing comma
            "{\"other\":1}",                       // missing key
        ] {
            std::fs::write(&file, bad).unwrap();
            assert_eq!(
                fingerprint_features(&root.join("deps"), "aaa"),
                None,
                "accepted malformed: {bad}"
            );
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Z2: a newer same-feature rlib whose embedded source paths
    /// point at ANOTHER checkout root loses to the older
    /// own-checkout build — newer-mtime never crosses origins.
    /// Two scratch roots with identical relative layouts; the
    /// foreign root's files EXIST, so only the embedded origin
    /// distinguishes them.
    #[test]
    fn rejects_foreign_checkout_rlib() {
        let root = scratch("foreign");
        let other = scratch("foreign-other");
        plant(&root.join("src/lib.rs"), Duration::from_secs(3600));
        plant(&other.join("src/lib.rs"), Duration::from_secs(3600));
        plant_rlib(
            &root.join("deps/libscopebase_capture-aaa.rlib"),
            Duration::from_secs(60),
            &root,
        );
        plant_rlib(
            &root.join("deps/libscopebase_capture-zzz.rlib"),
            Duration::from_secs(10),
            &other,
        );
        plant_fingerprint(&root, "aaa", "[\"default\"]");
        plant_fingerprint(&root, "zzz", "[\"default\"]");
        let hit = select_subject_rlib(&root.join("deps"), &root.join("src"), &[], &root).unwrap();
        assert!(
            hit.file_name().unwrap().to_str().unwrap().contains("aaa"),
            "foreign-checkout rlib selected: {}",
            hit.display()
        );
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&other).unwrap();
    }

    /// Z2: a same-layout foreign path (existing files under a
    /// different root) rejects even when it is the ONLY candidate.
    #[test]
    fn rejects_same_layout_foreign_origin() {
        let root = scratch("shadow");
        let other = scratch("shadow-other");
        plant(&root.join("src/lib.rs"), Duration::from_secs(3600));
        plant(&other.join("src/lib.rs"), Duration::from_secs(3600));
        plant_rlib(
            &root.join("deps/libscopebase_capture-aaa.rlib"),
            Duration::from_secs(10),
            &other,
        );
        plant_fingerprint(&root, "aaa", "[\"default\"]");
        let err = select_subject_rlib(&root.join("deps"), &root.join("src"), &[], &root).unwrap_err();
        assert!(err.contains("origin"), "must be loud: {err}");
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&other).unwrap();
    }

    /// Z2: an rlib mixing own-checkout paths with a foreign
    /// scopebase-capture shadow path rejects — one shadow anywhere
    /// vetoes, even beside verified own paths. (Merely unknown
    /// outside paths, e.g. registry sources, are ignored — only
    /// same-crate shadows veto.)
    #[test]
    fn rejects_mixed_origin_rlib() {
        let root = scratch("mixed");
        plant(&root.join("src/lib.rs"), Duration::from_secs(3600));
        let body = format!(
            "\0{}/src/lib.rs\0garbage\0/elsewhere/crates/scopebase-capture/src/evil.rs\0",
            root.display(),
        );
        let rlib = root.join("deps/libscopebase_capture-aaa.rlib");
        std::fs::write(&rlib, body.as_bytes()).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&rlib)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(10))
            .unwrap();
        plant_fingerprint(&root, "aaa", "[\"default\"]");
        let err = select_subject_rlib(&root.join("deps"), &root.join("src"), &[], &root).unwrap_err();
        assert!(err.contains("origin"), "must be loud: {err}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Z2: an rlib with no extractable subject-source paths (empty
    /// of origin evidence, e.g. stripped) fails closed instead of
    /// matching by features alone.
    #[test]
    fn rejects_rlib_without_origin_evidence() {
        let root = scratch("noevidence");
        plant(&root.join("src/lib.rs"), Duration::from_secs(3600));
        // Byte-plain rlib: no embedded source paths at all.
        plant(
            &root.join("deps/libscopebase_capture-aaa.rlib"),
            Duration::from_secs(10),
        );
        plant_fingerprint(&root, "aaa", "[\"default\"]");
        let err = select_subject_rlib(&root.join("deps"), &root.join("src"), &[], &root).unwrap_err();
        assert!(err.contains("origin"), "must be loud: {err}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Y2: two origin-verified same-feature candidates with exactly
    /// equal mtimes fail closed instead of tie-breaking by pathname.
    #[test]
    fn refuses_exact_mtime_ties() {
        let root = scratch("tie");
        plant(&root.join("src/lib.rs"), Duration::from_secs(3600));
        let stamp = SystemTime::now() - Duration::from_secs(60);
        for hash in ["aaa", "zzz"] {
            let path = root.join(format!("deps/libscopebase_capture-{hash}.rlib"));
            let body = format!("\0RUSTC\0{}/src/lib.rs\0", root.display());
            std::fs::write(&path, body.as_bytes()).unwrap();
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(stamp)
                .unwrap();
            plant_fingerprint(&root, hash, "[\"default\"]");
        }
        let err = select_subject_rlib(&root.join("deps"), &root.join("src"), &[], &root).unwrap_err();
        assert!(err.contains("ambiguous"), "must be loud: {err}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// X2: non-rlib neighbors are ignored; an empty deps dir refuses.
    #[test]
    fn ignores_non_rlib_neighbors() {
        let root = scratch("neighbors");
        plant(&root.join("src/lib.rs"), Duration::from_secs(60));
        plant(
            &root.join("deps/libscopebase_capture-zzz.rmeta"),
            Duration::from_secs(10),
        );
        plant_rlib(
            &root.join("deps/libscopebase_capture-aaa.rlib"),
            Duration::from_secs(30),
            &root,
        );
        plant_fingerprint(&root, "aaa", "[\"default\"]");
        let hit = select_subject_rlib(&root.join("deps"), &root.join("src"), &[], &root).unwrap();
        assert!(hit.extension().unwrap() == "rlib");
        std::fs::remove_file(root.join("deps/libscopebase_capture-aaa.rlib")).unwrap();
        select_subject_rlib(&root.join("deps"), &root.join("src"), &[], &root).unwrap_err();
        std::fs::remove_dir_all(&root).unwrap();
    }
}
