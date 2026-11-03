// SPDX-License-Identifier: Apache-2.0
//! Shipped structural boundary checks. Python 3.11+ is a developer-test prerequisite.
use std::fs::{self, DirBuilder};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn check(manifest: &Path) -> (i32, String) {
    let helper = Path::new(MANIFEST_DIR).join("tests/support/check_package_boundary.py");
    let mut child = Command::new("python3")
        .arg("-I")
        .arg(helper)
        .arg(manifest)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("required Python 3.11+ must be available");
    let mut stderr = Vec::new();
    let read_result = child
        .stderr
        .take()
        .unwrap()
        .take(4097)
        .read_to_end(&mut stderr);
    if read_result.is_err() || stderr.len() > 4096 {
        let _ = child.kill();
        let status = child.wait().expect("reap helper after output refusal");
        panic!("boundary helper output exceeded bound or could not be read: {status}");
    }
    let status = child.wait().expect("reap boundary helper");
    (
        status.code().expect("helper must exit normally"),
        String::from_utf8(stderr).unwrap(),
    )
}

fn valid_manifest() -> PathBuf {
    Path::new(MANIFEST_DIR).join("Cargo.toml")
}
fn source_manifest() -> String {
    // Cargo normalizes Cargo.toml; mutation twins use the shipped original syntax.
    let original = Path::new(MANIFEST_DIR).join("Cargo.toml.orig");
    fs::read_to_string(if original.exists() {
        original
    } else {
        valid_manifest()
    })
    .unwrap()
}
fn valid_twin() {
    assert_eq!(check(&valid_manifest()), (0, String::new()));
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        for _ in 0..32 {
            let serial = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "scopebase-capture-boundary-{}-{serial}",
                std::process::id()
            ));
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create private test directory: {error}"),
            }
        }
        panic!("could not reserve a fresh test directory");
    }
    fn manifest(&self, contents: &str) -> PathBuf {
        let path = self.0.join("Cargo.toml");
        use std::io::Write;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap()
            .write_all(contents.as_bytes())
            .unwrap();
        path
    }
    fn finish(self) {
        fs::remove_dir_all(&self.0).expect("retire owned boundary fixture");
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn refused(contents: &str, reason: &str) {
    valid_twin();
    let scratch = Scratch::new();
    let manifest = scratch.manifest(contents);
    assert_eq!(
        check(&manifest),
        (1, format!("PACKAGE_BOUNDARY:{reason}\n"))
    );
    scratch.finish();
    valid_twin();
}

#[test]
fn package_has_no_platform_or_codegen_dependency() {
    valid_twin();
}

#[test]
fn forbidden_dependency_is_refused_before_resolution() {
    let original = source_manifest();
    refused(
        &(original + "\n[target.'cfg(any())'.dependencies]\naya = '=0.14.0'\n"),
        "DEPENDENCIES",
    );
}

#[test]
fn ordinary_forbidden_dependency_is_refused() {
    let original = source_manifest();
    // An independent forbidden production edge, added without resolving or compiling it.
    refused(
        &original.replace("[dependencies]", "[dependencies]\naya = '=0.14.0'"),
        "DEPENDENCIES",
    );
}

#[test]
fn unexpected_build_script_is_refused() {
    valid_twin();
    let scratch = Scratch::new();
    let original = source_manifest();
    let manifest = scratch.manifest(&original);
    fs::write(
        scratch.0.join("build.rs"),
        "fn main() { panic!(\"must not execute\"); }\n",
    )
    .unwrap();
    assert_eq!(
        check(&manifest),
        (1, "PACKAGE_BOUNDARY:BUILD_INPUT\n".into())
    );
    scratch.finish();
    valid_twin();
}

#[test]
fn malformed_toml_is_an_input_failure() {
    valid_twin();
    let scratch = Scratch::new();
    let manifest = scratch.manifest("[package\n");
    assert_eq!(check(&manifest), (2, "PACKAGE_BOUNDARY:INPUT\n".into()));
    scratch.finish();
}

#[test]
fn oversized_manifest_is_an_input_failure() {
    valid_twin();
    let scratch = Scratch::new();
    let manifest = scratch.manifest(&"#".repeat(65_537));
    assert_eq!(check(&manifest), (2, "PACKAGE_BOUNDARY:INPUT\n".into()));
    scratch.finish();
}

#[test]
fn features_and_exact_dependency_options_are_checked() {
    let original = source_manifest();
    refused(
        &original.replace("default = []", "default = [\"json\"]"),
        "FEATURES",
    );
    refused(&original.replace("=1.0.229", "=1.0.228"), "DEPENDENCIES");
    refused(
        &original.replace("optional = true", "optional = false"),
        "DEPENDENCIES",
    );
    refused(
        &original.replace("features = [\"std\"]", "features = [\"std\", \"derive\"]"),
        "DEPENDENCIES",
    );
}

#[test]
fn build_inputs_and_source_overrides_are_refused() {
    let original = source_manifest();
    refused(
        &original.replace("build = false", "build = \"custom.rs\""),
        "BUILD_INPUT",
    );
    refused(
        &(original.clone() + "\n[build-dependencies]\ncc = '1'\n"),
        "BUILD_INPUT",
    );
    refused(
        &(original.clone() + "\n[dev-dependencies]\nlibc = '0.2'\n"),
        "DEPENDENCIES",
    );
    refused(
        &(original.clone() + "\n[patch.crates-io]\nserde = { path = '../serde' }\n"),
        "OVERRIDE",
    );
    refused(&(original + "\n[workspace]\n"), "OVERRIDE");
}

#[test]
fn package_metadata_is_frozen() {
    let original = source_manifest();
    refused(
        &original.replace("rust-version = \"1.88.0\"", "rust-version = \"1.98.1\""),
        "PACKAGE_METADATA",
    );
    refused(
        &original.replace("publish = false", "publish = true"),
        "PACKAGE_METADATA",
    );
}

fn dependency_table_alias_is_refused(canonical: &str, alias: &str, reason: &str) {
    let original = source_manifest();
    // The same forbidden edge must refuse under both Cargo table spellings.
    // These fixtures are parsed only; no dependency is resolved or compiled.
    refused(&(original.clone() + canonical), reason);
    refused(&(original + alias), reason);
}

#[test]
fn top_level_build_dependency_alias_is_refused() {
    dependency_table_alias_is_refused(
        "\n[build-dependencies]\ncc = '1'\n",
        "\n[build_dependencies]\ncc = '1'\n",
        "BUILD_INPUT",
    );
}

#[test]
fn top_level_dev_dependency_alias_is_refused() {
    dependency_table_alias_is_refused(
        "\n[dev-dependencies]\nlibc = '0.2'\n",
        "\n[dev_dependencies]\nlibc = '0.2'\n",
        "DEPENDENCIES",
    );
}

#[test]
fn inactive_target_build_dependency_alias_is_refused() {
    dependency_table_alias_is_refused(
        "\n[target.'cfg(any())'.build-dependencies]\ncc = '1'\n",
        "\n[target.'cfg(any())'.build_dependencies]\ncc = '1'\n",
        "BUILD_INPUT",
    );
}

#[test]
fn inactive_target_dev_dependency_alias_is_refused() {
    dependency_table_alias_is_refused(
        "\n[target.'cfg(any())'.dev-dependencies]\nlibc = '0.2'\n",
        "\n[target.'cfg(any())'.dev_dependencies]\nlibc = '0.2'\n",
        "DEPENDENCIES",
    );
}

// X3: the S170 sealed-units harness must ship in the packaged crate
// alongside the nine UI fixtures it executes — otherwise the
// delivered package carries fixtures without their runner. Parsed
// with tomllib (same developer-python prerequisite as the boundary
// helper), not substring matching.
#[test]
fn sealed_units_harness_ships_in_package() {
    let manifest = Path::new(MANIFEST_DIR).join("Cargo.toml");
    let probe = Command::new("python3")
        .arg("-I")
        .arg("-c")
        .arg(
            "import sys,tomllib;include=tomllib.load(open(sys.argv[1],'rb'))['package']['include'];print('tests/ui_sealed_units.rs' in include)",
        )
        .arg(&manifest)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("required Python 3.11+ must be available");
    assert!(probe.status.success(), "tomllib include probe failed");
    assert_eq!(
        String::from_utf8(probe.stdout).unwrap(),
        "True\n",
        "tests/ui_sealed_units.rs missing from package include"
    );
}
