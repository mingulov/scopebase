// SPDX-License-Identifier: Apache-2.0
//! BP10 shared adapter-test helpers: repo fixture loading, `HeldFile`
//! authority construction and native-vector suite drivers.
//!
//! Every adapter test runs the same two native contract vectors
//! (`fixtures/bpf/native/configure.json` and `output-spans.json`) plus
//! its backend manifest (`tools/bpf-compat/profiles/<loader>-adapter.json`).
//! Loader-specific fakes live in each test file; only the drivers are shared.
use scopebase_bpf::adapters::{
    parse_configure_vector, parse_output_vector, AdapterViolation, LoaderId, NativeState,
    OutputLedger,
};
use scopebase_bpf::Limits;
use scopebase_linux::file::HeldFile;

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

pub fn limits() -> Limits {
    Limits {
        input_bytes: 1 << 20,
        retained_bytes: 1 << 20,
        work_steps: 1 << 20,
        sites: 64,
        live_links: 64,
        pending_retirements: 64,
    }
}

pub fn repo_bytes(relative: &str) -> Vec<u8> {
    std::fs::read(format!("{MANIFEST_DIR}/../../{relative}"))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

/// Temp pathname that removes its file on drop, so adapter tests
/// never leak temp files even on assertion failure.
pub struct TempPath(std::path::PathBuf);

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Create `path` with `contents`, refusing when the target already
/// exists (S187): `create_new` fails `AlreadyExists` on a pre-created
/// file or planted symlink instead of truncating through it.
pub fn create_temp_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(contents)
}

/// Create a temp regular file and adopt it as a `HeldFile` (LX02
/// `from_file`). The adapter must use the held FD only; it never sees
/// this pathname.
pub fn temp_held(contents: &[u8]) -> (TempPath, HeldFile) {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "bp10-adapter-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    create_temp_file(&path, contents).unwrap();
    let held = HeldFile::from_file(std::fs::File::open(&path).unwrap()).unwrap();
    (TempPath(path), held)
}

/// Drive every `configure.json` case through a fresh [`NativeState`]:
/// applied cases must land exactly on `final`; refused cases must name
/// the expected rule and leave the state bit-identical to `initial`.
pub fn run_configure_suite() {
    let bytes = repo_bytes("fixtures/bpf/native/configure.json");
    let vector = parse_configure_vector(&bytes, &limits()).unwrap();
    assert!(!vector.cases().is_empty(), "vector must not be empty");
    for case in vector.cases() {
        let mut state = NativeState::new(*case.initial());
        if case.loaded() {
            state.mark_loaded();
        }
        if case.poisoned() {
            state.poison();
        }
        let outcome = state.configure(case.attempt());
        match case.expect_applied() {
            true => {
                assert!(
                    outcome.is_ok(),
                    "case {}: expected applied, got {:?}",
                    case.name(),
                    outcome.err().map(|v| (v.rule(), v.kind()))
                );
                assert_eq!(
                    state.config(),
                    case.final_config(),
                    "case {}: applied state must equal final",
                    case.name()
                );
            }
            false => {
                let violation: AdapterViolation = outcome
                    .err()
                    .unwrap_or_else(|| panic!("case {}: expected refusal", case.name()));
                assert_eq!(
                    violation.rule(),
                    case.expect_rule().unwrap(),
                    "case {}: rule mismatch",
                    case.name()
                );
                assert!(
                    !violation.location().is_empty(),
                    "case {}: violation must carry a location",
                    case.name()
                );
                assert_eq!(
                    state.config(),
                    case.initial(),
                    "case {}: refused configure must leave state unchanged",
                    case.name()
                );
            }
        }
    }
}

/// Drive every `output-spans.json` case: admitted ledgers keep every
/// sentinel byte-identical across the lookup; refused ledgers name the
/// expected rule.
pub fn run_output_suite() {
    let bytes = repo_bytes("fixtures/bpf/native/output-spans.json");
    let vector = parse_output_vector(&bytes, &limits()).unwrap();
    assert!(!vector.cases().is_empty(), "vector must not be empty");
    for case in vector.cases() {
        match OutputLedger::admit(case.spans()) {
            Ok(ledger) => {
                let found = ledger.lookup(case.lookup()).is_some();
                assert_eq!(
                    found,
                    case.expect_hit().unwrap(),
                    "case {}: hit/miss mismatch",
                    case.name()
                );
                let after: Vec<[u8; 8]> = case
                    .spans()
                    .iter()
                    .map(|span| ledger.sentinel(span.id).unwrap())
                    .collect();
                let before: Vec<[u8; 8]> = case.spans().iter().map(|span| span.sentinel).collect();
                assert_eq!(
                    before,
                    after,
                    "case {}: lookup must not mutate sentinels",
                    case.name()
                );
                let expected: Vec<[u8; 8]> = case.expected_sentinels().to_vec();
                assert_eq!(
                    after,
                    expected,
                    "case {}: sentinels must equal the vector",
                    case.name()
                );
            }
            Err(violation) => {
                assert_eq!(
                    violation.rule(),
                    case.expect_rule().unwrap(),
                    "case {}: rule mismatch",
                    case.name()
                );
            }
        }
    }
}

/// Assert the shipped backend manifest names this loader and exactly the
/// versions the adapter admits.
pub fn check_manifest(loader: LoaderId, admitted: &[&str]) {
    let bytes = repo_bytes(&format!(
        "tools/bpf-compat/profiles/{}-adapter.json",
        loader.as_str()
    ));
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["kind"], "bp10_loader_manifest");
    assert_eq!(value["loader"], loader.as_str());
    let versions: Vec<&str> = value["admitted_versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(versions, admitted, "manifest/admitted version drift");
}
