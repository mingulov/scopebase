// SPDX-License-Identifier: Apache-2.0
//! TC02: executor/scope/custody API over the admitted compiler closure.
//!
//! Donor slices (p11scope-ws w000 @ 6f97aa47, frozen tree; whole
//! user-authored files): `llvm-bpf-toolchain-experiment.md` (lines 1-216),
//! `llvm-bpf-atomic-load-report.md` (lines 1-140),
//! `evidence/llvm-toolchain-review-20260922/kernel-oracle/prepare.py`
//! (lines 1-139), `run.py` (lines 1-91). ADAPT of explicit tool paths,
//! CPU admission, argv-array spawn, wall-clock budgets, hash-pinned-before-use,
//! exclusive leases and returncode-gated admission; no upstream lines copied.
//! Grant: OWNER-2026-10-23.
//!
//! The scripted backend below models parent-exit/descendant-writing states;
//! the real descendant and positive mixed Cargo-to-linker guest tests are
//! TC07/TC08 gates after TT05. No host Cargo runs here as a substitute.
use scopebase_bpf::{ErrorKind, Limits, OperationError, Stage};
use scopebase_testkit::toolchain::{
    compile_fixture, run_pinned, BuildExit, BuildRequest, BuildScopeBackend, CompileOutcome,
    CompilerClosure, CompilerExecutor, DirectScope, ExecutorBudget, ExecutorLimits, ExecutorUsage,
    NestedBounds, RoleBinding, RoleSelection, ScopePoll, ScopeStart, SelectedClosure,
};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn limits() -> Limits {
    Limits {
        input_bytes: 1 << 20,
        retained_bytes: 1 << 20,
        work_steps: 1 << 20,
        sites: 64,
        live_links: 64,
        pending_retirements: 64,
    }
}

fn generous_limits() -> ExecutorLimits {
    ExecutorLimits {
        max_jobs: 16,
        max_reserved_output_bytes: 1 << 30,
        max_retained_diagnostic_bytes: 1 << 30,
    }
}

/// Unique scratch dir per test; removed on drop. Declare first so it outlives
/// every executor and ticket that borrows paths beneath it.
struct TempDir {
    path: PathBuf,
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// S229/R32: process-start nonce so a rerun under a recycled PID never
/// collides with crash residue (which would otherwise refuse below).
static START_NONCE: std::sync::OnceLock<u128> = std::sync::OnceLock::new();

fn start_nonce() -> u128 {
    *START_NONCE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    })
}

/// S229/R32: exclusively create a private temp dir. A pre-existing
/// candidate (preplanted symlink, stale residue) is refused loudly:
/// silently reusing it would let a planted link redirect build writes
/// outside the temp tree.
fn claim_temp_dir(dir: &std::path::Path) {
    match std::fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) => panic!(
            "refused: temp candidate {} already exists ({e})",
            dir.display()
        ),
    }
}

impl TempDir {
    fn named(tag: &str) -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "tc02exec-{}-{tag}-{id}-{:x}",
            std::process::id(),
            start_nonce()
        ));
        claim_temp_dir(&path);
        Self { path }
    }

    fn join(&self, name: impl AsRef<str>) -> PathBuf {
        self.path.join(name.as_ref())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn repo_file(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(relative)
}

fn fake_tool(name: &str) -> PathBuf {
    repo_file(&format!("fixtures/bpf/toolchain/fake-tools/{name}"))
}

fn sha_hex_of(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap();
    Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn pin_json(id: &str, role: &str, version: &str, path: &Path) -> String {
    format!(
        r#"{{
      "id": "{id}",
      "role": "{role}",
      "name": "{id}",
      "version": "{version}",
      "version_detail": "test pin {id}",
      "sha256": "{}",
      "origin": "preserved-binary",
      "origin_ref": "tc02exec test",
      "used_for": "executor/scope tests"
    }}"#,
        sha_hex_of(path)
    )
}

fn manifest_of(pins: &[String]) -> CompilerClosure {
    let doc = format!(
        r#"{{
  "schema_version": 1,
  "kind": "tc02_compiler_closure",
  "tools": [{}]
}}"#,
        pins.join(",")
    );
    CompilerClosure::from_json(doc.as_bytes(), &limits()).unwrap()
}

fn binding(pin: &str, path: &Path, version_output: &[u8]) -> RoleBinding {
    RoleBinding {
        pin: pin.to_owned(),
        path: path.to_path_buf(),
        version_output: version_output.to_vec(),
    }
}

/// Fake loaded-LLVM library bytes: a real file with real bytes and a real
/// hash, standing in for the shared object the donor reports distinguish
/// from Rust's embedded LLVM and Clang's LLVM.
fn fake_lib_llvm(dir: &TempDir, name: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, b"fake-libLLVM-so.23.1").unwrap();
    path
}

fn request_in(source: &Path, output: &Path) -> BuildRequest {
    BuildRequest::new(
        source.to_path_buf(),
        output.to_path_buf(),
        "bpfel-unknown-none".to_owned(),
        Instant::now() + Duration::from_secs(30),
        1 << 20,
        1 << 20,
    )
}

fn short_request_in(source: &Path, output: &Path, timeout_ms: u64) -> BuildRequest {
    BuildRequest::new(
        source.to_path_buf(),
        output.to_path_buf(),
        "bpfel-unknown-none".to_owned(),
        Instant::now() + Duration::from_millis(timeout_ms),
        1 << 20,
        1 << 20,
    )
}

fn make_source(dir: &TempDir) -> PathBuf {
    let source = dir.join("src");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("input.ll"), b"; fake LLVM IR\n").unwrap();
    source
}

// ---------------------------------------------------------------------------
// Scripted scope backend: TC02's whole-guest ownership contract as a model.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct ScriptedJob;

#[derive(Debug, Clone, Copy)]
enum ScriptStart {
    Started,
    NoEffect(ErrorKind, Stage),
    Uncertain(ErrorKind, Stage),
}

enum ScriptPoll {
    Running,
    Settled {
        exit: BuildExit,
        objects: Vec<PathBuf>,
        diagnostic: Vec<u8>,
    },
    Unresolved(ErrorKind, Stage),
}

/// Model backend with shared call counters and shared script queues, so the
/// test can advance the script after the backend moved into the executor.
/// Queues drain in order; an empty `starts` queue means `Started`, an empty
/// `polls` queue means `Running`. `request_stop` reports the next queued
/// poll, like a real cooperative stop.
struct Scripted {
    starts: Rc<RefCell<VecDeque<ScriptStart>>>,
    polls: Rc<RefCell<VecDeque<ScriptPoll>>>,
    start_calls: Rc<Cell<u32>>,
    poll_calls: Rc<Cell<u32>>,
    stop_calls: Rc<Cell<u32>>,
    seen_env: Rc<RefCell<Vec<BTreeMap<OsString, OsString>>>>,
    /// When set, `start` writes these bytes to `output_root/obj.o`, modelling
    /// a tool that produced an object.
    write_object: Option<Vec<u8>>,
    /// When set, `start` chmods the output root to this mode after writing,
    /// modelling unresolved root cleanup.
    sabotage_root_mode: Option<u32>,
}

impl Scripted {
    fn new() -> Self {
        Self {
            starts: Rc::new(RefCell::new(VecDeque::new())),
            polls: Rc::new(RefCell::new(VecDeque::new())),
            start_calls: Rc::new(Cell::new(0)),
            poll_calls: Rc::new(Cell::new(0)),
            stop_calls: Rc::new(Cell::new(0)),
            seen_env: Rc::new(RefCell::new(Vec::new())),
            write_object: None,
            sabotage_root_mode: None,
        }
    }

    fn bump(cell: &Rc<Cell<u32>>) {
        cell.set(cell.get() + 1);
    }

    fn script_error(kind: ErrorKind, stage: Stage) -> OperationError {
        OperationError::new(kind, stage, None, None)
    }

    fn next_poll(&mut self, _job: &mut ScriptedJob) -> ScopePoll {
        match self
            .polls
            .borrow_mut()
            .pop_front()
            .unwrap_or(ScriptPoll::Running)
        {
            ScriptPoll::Running => ScopePoll::Running,
            ScriptPoll::Settled {
                exit,
                objects,
                diagnostic,
            } => ScopePoll::Settled {
                exit,
                objects,
                diagnostic,
            },
            ScriptPoll::Unresolved(kind, stage) => {
                ScopePoll::Unresolved(Self::script_error(kind, stage))
            }
        }
    }
}

// SAFETY: the script makes no authority claim beyond its queue: `Settled`
// is scripted test data, and the job retains no native resource.
unsafe impl BuildScopeBackend for Scripted {
    type Job = ScriptedJob;

    fn start(&mut self, _tools: &SelectedClosure, request: &BuildRequest) -> ScopeStart<Self::Job> {
        Self::bump(&self.start_calls);
        self.seen_env.borrow_mut().push(request.environment.clone());
        if let Some(bytes) = &self.write_object {
            std::fs::write(request.output_root.join("obj.o"), bytes).unwrap();
        }
        if let Some(mode) = self.sabotage_root_mode {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&request.output_root, std::fs::Permissions::from_mode(mode))
                .unwrap();
        }
        let start = self
            .starts
            .borrow_mut()
            .pop_front()
            .unwrap_or(ScriptStart::Started);
        match start {
            ScriptStart::Started => ScopeStart::Started(ScriptedJob),
            ScriptStart::NoEffect(kind, stage) => {
                ScopeStart::NoEffect(Self::script_error(kind, stage))
            }
            ScriptStart::Uncertain(kind, stage) => ScopeStart::Uncertain {
                custody: ScriptedJob,
                cause: Self::script_error(kind, stage),
            },
        }
    }

    fn poll(&mut self, job: &mut Self::Job) -> ScopePoll {
        Self::bump(&self.poll_calls);
        self.next_poll(job)
    }

    fn request_stop(&mut self, job: &mut Self::Job) -> ScopePoll {
        Self::bump(&self.stop_calls);
        self.next_poll(job)
    }
}

// ---------------------------------------------------------------------------
// Role-structured selection over the admitted pin manifest.
// ---------------------------------------------------------------------------

/// Manifest with one backend, one frontend, one linker, one runner, one rust
/// and one cargo pin, all hashed from real fake-tool bytes.
fn rich_manifest(dir: &TempDir) -> (CompilerClosure, PathBuf) {
    let lib = fake_lib_llvm(dir, "libLLVM.so");
    let manifest = manifest_of(&[
        pin_json("test-llc", "backend", "23.1.2", &fake_tool("record-build")),
        pin_json("test-clang", "frontend", "18.1.8", &fake_tool("silent-ok")),
        pin_json("test-linker", "linker", "0.11.1", &fake_tool("fake-linker")),
        pin_json("test-runner", "runner", "1.0.0", &fake_tool("exit-code")),
        pin_json("test-rustc", "rust", "1.90.0", &fake_tool("exit-code")),
        pin_json("test-cargo", "cargo", "1.90.0", &fake_tool("silent-ok")),
        pin_json("test-libllvm", "backend", "23.1.2", &lib),
    ]);
    (manifest, lib)
}

fn llc_selection(lib: &Path) -> RoleSelection {
    RoleSelection {
        llc: Some(binding(
            "test-llc",
            &fake_tool("record-build"),
            b"fake llc 23.1.2",
        )),
        loaded_llvm: Some(binding("test-libllvm", lib, b"fake libLLVM 23.1.2")),
        ..RoleSelection::none()
    }
}

#[test]
fn select_binds_manifest_pins_to_roles() {
    let dir = TempDir::named("select");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let llc = tools.llc().unwrap();
    assert_eq!(llc.executable, fake_tool("record-build"));
    assert_eq!(&llc.sha256, manifest.find("test-llc").unwrap().sha256());
    assert_eq!(llc.version_output, b"fake llc 23.1.2");
    assert_eq!(
        &tools.loaded_llvm().sha256,
        manifest.find("test-libllvm").unwrap().sha256()
    );
    assert!(tools.cargo().is_none());
    assert!(tools.rustc().is_none());
    assert!(tools.rust_sysroot().is_none());
    assert!(tools.clang().is_none());
    assert!(tools.linker().is_none());
    assert_eq!(
        tools.role_pin(scopebase_testkit::toolchain::ToolRole::Llc),
        Some("test-llc")
    );
    assert_eq!(tools.manifest().len(), manifest.len());
}

#[test]
fn select_requires_loaded_llvm() {
    let dir = TempDir::named("select-llvm");
    let (manifest, lib) = rich_manifest(&dir);
    let mut selection = llc_selection(&lib);
    selection.loaded_llvm = None;
    let error = SelectedClosure::select(&manifest, &selection).unwrap_err();
    assert_eq!(
        (error.kind(), error.stage()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
}

#[test]
fn select_refuses_unknown_pin() {
    let dir = TempDir::named("select-unknown");
    let (manifest, lib) = rich_manifest(&dir);
    let mut selection = llc_selection(&lib);
    selection.llc = Some(binding("no-such-pin", &fake_tool("record-build"), b"v"));
    let error = SelectedClosure::select(&manifest, &selection).unwrap_err();
    assert_eq!(
        (error.kind(), error.stage()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
}

#[test]
fn select_refuses_role_mismatch() {
    let dir = TempDir::named("select-role");
    let (manifest, lib) = rich_manifest(&dir);
    // A runner pin is not a backend: binding it as llc refuses.
    let mut selection = llc_selection(&lib);
    selection.llc = Some(binding("test-runner", &fake_tool("exit-code"), b"v"));
    let error = SelectedClosure::select(&manifest, &selection).unwrap_err();
    assert_eq!(
        (error.kind(), error.stage()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
}

#[test]
fn select_refuses_empty_version_output() {
    let dir = TempDir::named("select-version");
    let (manifest, lib) = rich_manifest(&dir);
    let mut selection = llc_selection(&lib);
    selection.llc = Some(binding("test-llc", &fake_tool("record-build"), b""));
    let error = SelectedClosure::select(&manifest, &selection).unwrap_err();
    assert_eq!(
        (error.kind(), error.stage()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
}

#[test]
fn select_accepts_any_pin_for_loaded_llvm() {
    // loaded_llvm records which LLVM got loaded; it is identity, not a role.
    let dir = TempDir::named("select-llvm-any");
    let (manifest, lib) = rich_manifest(&dir);
    let mut selection = llc_selection(&lib);
    selection.loaded_llvm = Some(binding("test-linker", &fake_tool("fake-linker"), b"v"));
    let tools = SelectedClosure::select(&manifest, &selection).unwrap();
    assert_eq!(tools.loaded_llvm().executable, fake_tool("fake-linker"));
}

#[test]
fn shipped_manifest_selects_structurally_then_tool_missing() {
    // Reconciliation: the shipped generic manifest binds roles without
    // touching the filesystem, and execution honestly reports that the
    // recorded donor binaries are absent from this host.
    let dir = TempDir::named("shipped");
    let bytes = std::fs::read(repo_file("tools/bpf-compat/compiler-closure.json")).unwrap();
    let manifest = CompilerClosure::from_json(&bytes, &limits()).unwrap();
    let selection = RoleSelection {
        llc: Some(binding(
            "llvm-23.1.2-pristine-llc",
            Path::new("/nonexistent/llc"),
            b"llc 23.1.2",
        )),
        loaded_llvm: Some(binding(
            "llvm-23.1.2-pristine-llc",
            Path::new("/nonexistent/libLLVM.so.23.1"),
            b"libLLVM 23.1.2",
        )),
        ..RoleSelection::none()
    };
    let tools = SelectedClosure::select(&manifest, &selection).unwrap();
    let backend = Scripted::new();
    let starts = Rc::clone(&backend.start_calls);
    let mut executor = CompilerExecutor::new(backend, generous_limits()).unwrap();
    let source = make_source(&dir);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &request_in(&source, &dir.join("out")),
    );
    match outcome {
        CompileOutcome::ToolMissing { name } => assert_eq!(name, "llc"),
        other => panic!("expected ToolMissing, got {other:?}"),
    }
    assert_eq!(starts.get(), 0, "missing tools refuse before spawn");
    assert_eq!(
        executor.usage(),
        ExecutorUsage {
            jobs: 0,
            reserved_output_bytes: 0,
            retained_diagnostic_bytes: 0
        }
    );
    assert!(
        !dir.join("out").exists(),
        "no root is reserved for a missing tool"
    );
}

// ---------------------------------------------------------------------------
// compile_fixture admission: request, environment, pair, capacity.
// ---------------------------------------------------------------------------

fn scripted_pair() -> (Scripted, Rc<Cell<u32>>) {
    let backend = Scripted::new();
    let starts = Rc::clone(&backend.start_calls);
    (backend, starts)
}

fn new_executor(backend: Scripted) -> CompilerExecutor<Scripted> {
    CompilerExecutor::new(backend, generous_limits()).unwrap()
}

fn assert_rejected<S: BuildScopeBackend>(
    outcome: CompileOutcome<S>,
    kind: ErrorKind,
    stage: Stage,
) {
    match outcome {
        CompileOutcome::Rejected(error) => assert_eq!((error.kind(), error.stage()), (kind, stage)),
        other => panic!("expected Rejected({kind:?}/{stage:?}), got {other:?}"),
    }
}

#[test]
fn env_rustc_refuses_before_spawn() {
    let dir = TempDir::named("env-rustc");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let (backend, starts) = scripted_pair();
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let mut request = request_in(&source, &dir.join("out"));
    request
        .environment
        .insert(OsString::from("RUSTC"), OsString::from("rustc"));
    let outcome = compile_fixture(&mut executor, &tools, &request);
    assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
    assert_eq!(starts.get(), 0);
    assert_eq!(executor.usage().jobs, 0);
}

#[test]
fn env_cargo_target_cpu_keys_refuse() {
    let dir = TempDir::named("env-keys");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    for key in ["CARGO", "TARGET", "CPU"] {
        let (backend, starts) = scripted_pair();
        let mut executor = new_executor(backend);
        let source = make_source(&dir);
        let mut request = request_in(&source, &dir.join("out"));
        request
            .environment
            .insert(OsString::from(key), OsString::from("x"));
        let outcome = compile_fixture(&mut executor, &tools, &request);
        assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
        assert_eq!(starts.get(), 0, "key {key} must refuse before spawn");
    }
}

#[test]
fn env_proxy_and_offline_override_refuse() {
    let dir = TempDir::named("env-net");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    for (key, value) in [
        ("http_proxy", "http://proxy.invalid:8080"),
        ("HTTPS_PROXY", "https://proxy.invalid:8080"),
        ("CARGO_NET_OFFLINE", "false"),
    ] {
        let (backend, starts) = scripted_pair();
        let mut executor = new_executor(backend);
        let source = make_source(&dir);
        let mut request = request_in(&source, &dir.join("out"));
        request
            .environment
            .insert(OsString::from(key), OsString::from(value));
        let outcome = compile_fixture(&mut executor, &tools, &request);
        assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
        assert_eq!(
            starts.get(),
            0,
            "network env {key} must refuse before spawn"
        );
    }
}

#[test]
fn request_nul_and_empty_fields_refuse_without_spawn() {
    let dir = TempDir::named("req-shape");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let source = make_source(&dir);
    let mut bad = Vec::new();
    let mut with_nul_out = request_in(&source, &dir.join("out"));
    with_nul_out.output_root = PathBuf::from(OsString::from_vec(vec![0x61, 0x00]));
    bad.push(with_nul_out);
    let mut with_nul_target = request_in(&source, &dir.join("out"));
    with_nul_target.target = "bpf\0el".to_owned();
    bad.push(with_nul_target);
    let mut with_nul_feature = request_in(&source, &dir.join("out"));
    with_nul_feature.features = vec!["ok".to_owned(), "a\0b".to_owned()];
    bad.push(with_nul_feature);
    let mut with_nul_env = request_in(&source, &dir.join("out"));
    with_nul_env
        .environment
        .insert(OsString::from("A"), OsString::from_vec(vec![0x00]));
    bad.push(with_nul_env);
    let mut with_bad_key = request_in(&source, &dir.join("out"));
    with_bad_key
        .environment
        .insert(OsString::from("A=B"), OsString::from("c"));
    bad.push(with_bad_key);
    let mut with_empty_target = request_in(&source, &dir.join("out"));
    with_empty_target.target = String::new();
    bad.push(with_empty_target);
    let mut with_empty_out = request_in(&source, &dir.join("out"));
    with_empty_out.output_root = PathBuf::new();
    bad.push(with_empty_out);
    for (index, request) in bad.into_iter().enumerate() {
        let (backend, starts) = scripted_pair();
        let mut executor = new_executor(backend);
        let outcome = compile_fixture(&mut executor, &tools, &request);
        assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
        assert_eq!(
            starts.get(),
            0,
            "bad request {index} must refuse before spawn"
        );
    }
}

#[test]
fn benign_env_passes_through_verbatim() {
    let dir = TempDir::named("env-ok");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let backend = Scripted::new();
    let seen = Rc::clone(&backend.seen_env);
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let mut request = short_request_in(&source, &dir.join("out"), 200);
    request
        .environment
        .insert(OsString::from("FOO"), OsString::from("bar"));
    let outcome = compile_fixture(&mut executor, &tools, &request);
    assert!(
        matches!(outcome, CompileOutcome::TimedOut { .. }),
        "scripted backend runs: {outcome:?}"
    );
    assert_eq!(seen.borrow().len(), 1);
    assert_eq!(
        seen.borrow()[0].get(OsString::from("FOO").as_os_str()),
        Some(&OsString::from("bar"))
    );
    if let CompileOutcome::TimedOut { job } = outcome {
        drop(job);
    }
}

/// Cargo/rustc/sysroot triple selection. `rustc_under_sysroot` controls
/// whether the rustc path sits under the sysroot; `with_rustlib` controls
/// whether `lib/rustlib` exists beneath it.
fn pair_selection(
    dir: &TempDir,
    cargo_version: &str,
    rustc_version: &str,
    rustc_under_sysroot: bool,
    with_rustlib: bool,
) -> (CompilerClosure, RoleSelection, PathBuf) {
    let sysroot = dir.join("sysroot");
    std::fs::create_dir_all(sysroot.join("bin")).unwrap();
    if with_rustlib {
        std::fs::create_dir_all(sysroot.join("lib/rustlib")).unwrap();
    }
    let rustc_path = if rustc_under_sysroot {
        sysroot.join("bin/rustc")
    } else {
        dir.join("rustc")
    };
    std::fs::copy(fake_tool("exit-code"), &rustc_path).unwrap();
    let lib = fake_lib_llvm(dir, "libLLVM.so");
    let manifest = manifest_of(&[
        pin_json(
            "pair-cargo",
            "cargo",
            cargo_version,
            &fake_tool("silent-ok"),
        ),
        pin_json("pair-rustc", "rust", rustc_version, &rustc_path),
        pin_json("pair-libllvm", "backend", "23.1.2", &lib),
        pin_json("pair-llc", "backend", "23.1.2", &fake_tool("record-build")),
    ]);
    let selection = RoleSelection {
        cargo: Some(binding(
            "pair-cargo",
            &fake_tool("silent-ok"),
            b"cargo 1.90.0",
        )),
        rustc: Some(binding("pair-rustc", &rustc_path, b"rustc 1.90.0")),
        rust_sysroot: Some(sysroot.clone()),
        loaded_llvm: Some(binding("pair-libllvm", &lib, b"libLLVM")),
        ..RoleSelection::none()
    };
    (manifest, selection, sysroot)
}

#[test]
fn pair_partial_selections_refuse() {
    let dir = TempDir::named("pair-partial");
    let (manifest, selection, _) = pair_selection(&dir, "1.90.0", "1.90.0", true, true);
    // Cargo alone, rustc alone, sysroot alone, and every two-part mix refuse:
    // a selected pair is all three or nothing.
    let mut cases = Vec::new();
    let mut cargo_only = RoleSelection::none();
    cargo_only.cargo = selection.cargo.clone();
    cargo_only.loaded_llvm = selection.loaded_llvm.clone();
    cases.push(cargo_only);
    let mut rustc_only = RoleSelection::none();
    rustc_only.rustc = selection.rustc.clone();
    rustc_only.loaded_llvm = selection.loaded_llvm.clone();
    cases.push(rustc_only);
    let mut sysroot_only = RoleSelection::none();
    sysroot_only.rust_sysroot = selection.rust_sysroot.clone();
    sysroot_only.loaded_llvm = selection.loaded_llvm.clone();
    cases.push(sysroot_only);
    let mut cargo_rustc = RoleSelection::none();
    cargo_rustc.cargo = selection.cargo.clone();
    cargo_rustc.rustc = selection.rustc.clone();
    cargo_rustc.loaded_llvm = selection.loaded_llvm.clone();
    cases.push(cargo_rustc);
    let mut cargo_sysroot = RoleSelection::none();
    cargo_sysroot.cargo = selection.cargo.clone();
    cargo_sysroot.rust_sysroot = selection.rust_sysroot.clone();
    cargo_sysroot.loaded_llvm = selection.loaded_llvm.clone();
    cases.push(cargo_sysroot);
    let mut rustc_sysroot = RoleSelection::none();
    rustc_sysroot.rustc = selection.rustc.clone();
    rustc_sysroot.rust_sysroot = selection.rust_sysroot.clone();
    rustc_sysroot.loaded_llvm = selection.loaded_llvm.clone();
    cases.push(rustc_sysroot);
    for (index, case) in cases.into_iter().enumerate() {
        let tools = SelectedClosure::select(&manifest, &case).unwrap();
        let (backend, starts) = scripted_pair();
        let mut executor = new_executor(backend);
        let source = make_source(&dir);
        let outcome = compile_fixture(
            &mut executor,
            &tools,
            &request_in(&source, &dir.join("out")),
        );
        assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
        assert_eq!(
            starts.get(),
            0,
            "partial pair {index} must refuse before spawn"
        );
    }
}

#[test]
fn pair_version_mismatch_refuses() {
    let dir = TempDir::named("pair-version");
    let (manifest, selection, _) = pair_selection(&dir, "1.90.0", "1.91.0", true, true);
    let tools = SelectedClosure::select(&manifest, &selection).unwrap();
    let (backend, starts) = scripted_pair();
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &request_in(&source, &dir.join("out")),
    );
    assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
    assert_eq!(starts.get(), 0);
}

#[test]
fn pair_rustc_outside_sysroot_refuses() {
    let dir = TempDir::named("pair-outside");
    let (manifest, selection, _) = pair_selection(&dir, "1.90.0", "1.90.0", false, true);
    let tools = SelectedClosure::select(&manifest, &selection).unwrap();
    let (backend, starts) = scripted_pair();
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &request_in(&source, &dir.join("out")),
    );
    assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
    assert_eq!(starts.get(), 0);
}

#[test]
fn pair_sysroot_without_rustlib_refuses() {
    let dir = TempDir::named("pair-rustlib");
    let (manifest, selection, _) = pair_selection(&dir, "1.90.0", "1.90.0", true, false);
    let tools = SelectedClosure::select(&manifest, &selection).unwrap();
    let (backend, starts) = scripted_pair();
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &request_in(&source, &dir.join("out")),
    );
    assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
    assert_eq!(starts.get(), 0);
}

#[test]
fn pair_verified_triple_admits() {
    let dir = TempDir::named("pair-ok");
    let (manifest, selection, _) = pair_selection(&dir, "1.90.0", "1.90.0", true, true);
    let tools = SelectedClosure::select(&manifest, &selection).unwrap();
    let mut backend = Scripted::new();
    backend.write_object = Some(b"obj".to_vec());
    backend.polls.borrow_mut().push_back(ScriptPoll::Settled {
        exit: BuildExit::Exited(0),
        objects: vec![dir.join("out").join("obj.o")],
        diagnostic: Vec::new(),
    });
    let starts = Rc::clone(&backend.start_calls);
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &request_in(&source, &dir.join("out")),
    );
    assert!(
        matches!(outcome, CompileOutcome::Emitted { .. }),
        "verified pair admits: {outcome:?}"
    );
    assert_eq!(starts.get(), 1);
    if let CompileOutcome::Emitted { output } = outcome {
        output.release(&mut executor).unwrap();
    }
    assert!(matches!(
        executor.close(),
        scopebase_testkit::toolchain::ExecutorClose::Closed
    ));
}

// ---------------------------------------------------------------------------
// Persistent custody: saturation, orphaned tickets, reconciliation, leases.
// ---------------------------------------------------------------------------

fn two_slot_limits() -> ExecutorLimits {
    ExecutorLimits {
        max_jobs: 2,
        max_reserved_output_bytes: 1 << 30,
        max_retained_diagnostic_bytes: 1 << 30,
    }
}

#[test]
fn two_dropped_timeouts_saturate_third_refuses_before_spawn() {
    let dir = TempDir::named("saturate");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let backend = Scripted::new(); // empty queues: start ok, poll runs forever
    let starts = Rc::clone(&backend.start_calls);
    let mut executor = CompilerExecutor::new(backend, two_slot_limits()).unwrap();
    let source = make_source(&dir);
    for index in 0..2 {
        let outcome = compile_fixture(
            &mut executor,
            &tools,
            &short_request_in(&source, &dir.join(format!("out{index}")), 100),
        );
        assert!(
            matches!(outcome, CompileOutcome::TimedOut { .. }),
            "job {index} must time out"
        );
        if let CompileOutcome::TimedOut { job } = outcome {
            drop(job); // orphaned: reservations stay
        }
    }
    assert_eq!(starts.get(), 2);
    assert_eq!(executor.usage().jobs, 2);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &short_request_in(&source, &dir.join("out2"), 100),
    );
    assert_rejected(outcome, ErrorKind::LimitExceeded, Stage::Admission);
    assert_eq!(starts.get(), 2, "saturated executor refuses before spawn");
    assert!(!dir.join("out2").exists(), "refused call reserves no root");
}

#[test]
fn reconcile_releases_exactly_the_recovered_reservation() {
    let dir = TempDir::named("reconcile");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let backend = Scripted::new(); // default script: start ok, poll runs
    let polls = Rc::clone(&backend.polls);
    let mut executor = CompilerExecutor::new(backend, two_slot_limits()).unwrap();
    let source = make_source(&dir);
    for index in 0..2 {
        let outcome = compile_fixture(
            &mut executor,
            &tools,
            &short_request_in(&source, &dir.join(format!("out{index}")), 100),
        );
        assert!(matches!(outcome, CompileOutcome::TimedOut { .. }));
        drop(outcome); // orphan both jobs; reservations stay
    }
    assert_eq!(executor.usage().jobs, 2);
    // Confirmed writer retirement for one orphan only.
    polls.borrow_mut().push_back(ScriptPoll::Settled {
        exit: BuildExit::Exited(0),
        objects: Vec::new(),
        diagnostic: Vec::new(),
    });
    let report = executor.reconcile(ExecutorBudget {
        max_scope_calls: 10,
    });
    assert_eq!(
        (report.settled_jobs, report.pending_jobs, report.failed_jobs),
        (1, 1, 0)
    );
    assert_eq!(
        executor.usage().jobs,
        1,
        "exactly the settled orphan releases"
    );
    assert_eq!(report.usage.jobs, 1);
    // The second orphan retires; everything releases and the executor closes.
    polls.borrow_mut().push_back(ScriptPoll::Settled {
        exit: BuildExit::Signaled(9),
        objects: Vec::new(),
        diagnostic: b"killed".to_vec(),
    });
    let report = executor.reconcile(ExecutorBudget {
        max_scope_calls: 10,
    });
    assert_eq!(
        (report.settled_jobs, report.pending_jobs, report.failed_jobs),
        (1, 0, 0)
    );
    assert_eq!(
        executor.usage(),
        ExecutorUsage {
            jobs: 0,
            reserved_output_bytes: 0,
            retained_diagnostic_bytes: 0
        }
    );
    assert!(!dir.join("out0").exists() && !dir.join("out1").exists());
    assert!(matches!(
        executor.close(),
        scopebase_testkit::toolchain::ExecutorClose::Closed
    ));
}

#[test]
fn dropped_job_reconcile_recovers_and_closes() {
    let dir = TempDir::named("orphan");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let backend = Scripted::new();
    let polls = Rc::clone(&backend.polls);
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &short_request_in(&source, &dir.join("out"), 100),
    );
    assert!(matches!(outcome, CompileOutcome::TimedOut { .. }));
    if let CompileOutcome::TimedOut { job } = outcome {
        drop(job);
    }
    assert_eq!(executor.usage().jobs, 1);
    assert!(dir.join("out").exists());
    // Orphan still running: reconcile reports pending, releases nothing.
    let report = executor.reconcile(ExecutorBudget {
        max_scope_calls: 10,
    });
    assert_eq!(
        (report.settled_jobs, report.pending_jobs, report.failed_jobs),
        (0, 1, 0)
    );
    assert_eq!(executor.usage().jobs, 1);
    let mut executor = match executor.close() {
        scopebase_testkit::toolchain::ExecutorClose::Unresolved(executor) => executor,
        scopebase_testkit::toolchain::ExecutorClose::Closed => {
            panic!("live orphan must block close")
        }
    };
    // The scope settles; reconcile reaps it and the executor closes.
    polls.borrow_mut().push_back(ScriptPoll::Settled {
        exit: BuildExit::Exited(0),
        objects: Vec::new(),
        diagnostic: Vec::new(),
    });
    let report = executor.reconcile(ExecutorBudget {
        max_scope_calls: 10,
    });
    assert_eq!(
        (report.settled_jobs, report.pending_jobs, report.failed_jobs),
        (1, 0, 0)
    );
    assert_eq!(executor.usage().jobs, 0);
    assert!(!dir.join("out").exists());
    assert!(matches!(
        executor.close(),
        scopebase_testkit::toolchain::ExecutorClose::Closed
    ));
}

#[test]
fn usage_accounts_live_charges_exactly() {
    let dir = TempDir::named("usage");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let backend = Scripted::new();
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let mut request = short_request_in(&source, &dir.join("out"), 100);
    request.max_output_bytes = 1000;
    request.max_artifact_bytes = 2000;
    let outcome = compile_fixture(&mut executor, &tools, &request);
    assert!(matches!(outcome, CompileOutcome::TimedOut { .. }));
    assert_eq!(
        executor.usage(),
        ExecutorUsage {
            jobs: 1,
            reserved_output_bytes: 2000,
            retained_diagnostic_bytes: 1000
        }
    );
    drop(outcome);
}

#[test]
fn artifact_and_diagnostic_reservations_refuse() {
    let dir = TempDir::named("reserve");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let source = make_source(&dir);
    for (limits, label) in [
        (
            ExecutorLimits {
                max_jobs: 16,
                max_reserved_output_bytes: 1999,
                max_retained_diagnostic_bytes: 1 << 30,
            },
            "artifact",
        ),
        (
            ExecutorLimits {
                max_jobs: 16,
                max_reserved_output_bytes: 1 << 30,
                max_retained_diagnostic_bytes: 999,
            },
            "diagnostic",
        ),
        (
            ExecutorLimits {
                max_jobs: 0,
                max_reserved_output_bytes: 1 << 30,
                max_retained_diagnostic_bytes: 1 << 30,
            },
            "jobs",
        ),
    ] {
        let (backend, starts) = scripted_pair();
        let mut executor = CompilerExecutor::new(backend, limits).unwrap();
        let mut request = request_in(&source, &dir.join("out"));
        request.max_output_bytes = 1000;
        request.max_artifact_bytes = 2000;
        let outcome = compile_fixture(&mut executor, &tools, &request);
        assert_rejected(outcome, ErrorKind::LimitExceeded, Stage::Admission);
        assert_eq!(
            starts.get(),
            0,
            "{label} over-reservation must refuse before spawn"
        );
    }
}

#[test]
fn shared_output_root_refuses() {
    let dir = TempDir::named("shared-root");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let (backend, starts) = scripted_pair();
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let first = compile_fixture(
        &mut executor,
        &tools,
        &short_request_in(&source, &dir.join("out"), 150),
    );
    // Keep the first job alive (timed out or running) while the second tries.
    let held = match first {
        CompileOutcome::TimedOut { job } => Some(job),
        other => panic!("expected TimedOut, got {other:?}"),
    };
    let second = compile_fixture(
        &mut executor,
        &tools,
        &short_request_in(&source, &dir.join("out"), 100),
    );
    assert_rejected(second, ErrorKind::InvalidInput, Stage::Admission);
    assert_eq!(starts.get(), 1, "shared root refuses before spawn");
    drop(held);
}

#[test]
fn alias_output_root_refuses() {
    let dir = TempDir::named("alias-root");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let backend = Scripted::new();
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let first = compile_fixture(
        &mut executor,
        &tools,
        &short_request_in(&source, &dir.join("out"), 150),
    );
    let held = match first {
        CompileOutcome::TimedOut { job } => job,
        other => panic!("expected TimedOut, got {other:?}"),
    };
    // A symlink naming the same root is the same root.
    std::os::unix::fs::symlink(dir.join("out"), dir.join("alias")).unwrap();
    let second = compile_fixture(
        &mut executor,
        &tools,
        &short_request_in(&source, &dir.join("alias"), 100),
    );
    assert_rejected(second, ErrorKind::InvalidInput, Stage::Admission);
    drop(held);
}

#[test]
fn nested_output_root_refuses() {
    let dir = TempDir::named("nested-root");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let backend = Scripted::new();
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let first = compile_fixture(
        &mut executor,
        &tools,
        &short_request_in(&source, &dir.join("out"), 150),
    );
    let held = match first {
        CompileOutcome::TimedOut { job } => job,
        other => panic!("expected TimedOut, got {other:?}"),
    };
    // A path beneath a reserved root cannot become a second root.
    std::fs::create_dir_all(dir.join("out/nest")).unwrap();
    let second = compile_fixture(
        &mut executor,
        &tools,
        &short_request_in(&source, &dir.join("out/nest/inner"), 100),
    );
    assert_rejected(second, ErrorKind::InvalidInput, Stage::Admission);
    drop(held);
}

#[test]
fn root_reusable_after_explicit_release() {
    let dir = TempDir::named("reuse");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let mut backend = Scripted::new();
    backend.write_object = Some(b"obj".to_vec());
    for _ in 0..2 {
        backend.polls.borrow_mut().push_back(ScriptPoll::Settled {
            exit: BuildExit::Exited(0),
            objects: vec![dir.join("out").join("obj.o")],
            diagnostic: Vec::new(),
        });
    }
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    for round in 0..2 {
        let outcome = compile_fixture(
            &mut executor,
            &tools,
            &request_in(&source, &dir.join("out")),
        );
        match outcome {
            CompileOutcome::Emitted { output } => output.release(&mut executor).unwrap(),
            other => panic!("round {round}: expected Emitted, got {other:?}"),
        }
    }
    assert!(matches!(
        executor.close(),
        scopebase_testkit::toolchain::ExecutorClose::Closed
    ));
}

#[test]
fn wrong_executor_job_fails_without_native_action() {
    let dir = TempDir::named("wrong-exec");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let source = make_source(&dir);
    let mut home = new_executor(Scripted::new());
    let outcome = compile_fixture(
        &mut home,
        &tools,
        &short_request_in(&source, &dir.join("out"), 100),
    );
    let job = match outcome {
        CompileOutcome::TimedOut { job } => job,
        other => panic!("expected TimedOut, got {other:?}"),
    };
    let foreign = Scripted::new();
    let (f_start, f_poll, f_stop) = (
        Rc::clone(&foreign.start_calls),
        Rc::clone(&foreign.poll_calls),
        Rc::clone(&foreign.stop_calls),
    );
    let mut away = new_executor(foreign);
    let outcome = job.reconcile(&mut away, Instant::now() + Duration::from_secs(5));
    match outcome {
        CompileOutcome::Unresolved { job, error } => {
            assert_eq!(
                (error.kind(), error.stage()),
                (ErrorKind::InvalidInput, Stage::Admission)
            );
            // Custody survived: the home executor still owns the job.
            let back = job.reconcile(&mut home, Instant::now() + Duration::from_millis(50));
            assert!(
                matches!(back, CompileOutcome::TimedOut { .. }),
                "job still valid at home: {back:?}"
            );
            if let CompileOutcome::TimedOut { job } = back {
                drop(job);
            }
        }
        other => panic!("expected Unresolved with custody, got {other:?}"),
    }
    assert_eq!(
        (f_start.get(), f_poll.get(), f_stop.get()),
        (0, 0, 0),
        "wrong executor makes no scope calls"
    );
}

#[test]
fn wrong_executor_output_fails_without_native_action() {
    let dir = TempDir::named("wrong-out");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let mut backend = Scripted::new();
    backend.write_object = Some(b"obj".to_vec());
    backend.polls.borrow_mut().push_back(ScriptPoll::Settled {
        exit: BuildExit::Exited(0),
        objects: vec![dir.join("out").join("obj.o")],
        diagnostic: Vec::new(),
    });
    let mut home = new_executor(backend);
    let source = make_source(&dir);
    let outcome = compile_fixture(&mut home, &tools, &request_in(&source, &dir.join("out")));
    let output = match outcome {
        CompileOutcome::Emitted { output } => output,
        other => panic!("expected Emitted, got {other:?}"),
    };
    assert_eq!(output.objects(), &[dir.join("out").join("obj.o")]);
    let mut away = new_executor(Scripted::new());
    let failure = output.release(&mut away).unwrap_err();
    assert_eq!(
        (failure.error.kind(), failure.error.stage()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    failure.output.release(&mut home).unwrap();
    assert!(matches!(
        home.close(),
        scopebase_testkit::toolchain::ExecutorClose::Closed
    ));
}

#[test]
fn no_effect_with_failed_cleanup_returns_output_only_job() {
    let dir = TempDir::named("noeffect");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let mut backend = Scripted::new();
    backend
        .starts
        .borrow_mut()
        .push_back(ScriptStart::NoEffect(ErrorKind::Backend, Stage::Execute));
    backend.write_object = Some(b"partial".to_vec());
    backend.sabotage_root_mode = Some(0o555);
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &request_in(&source, &dir.join("out")),
    );
    let job = match outcome {
        CompileOutcome::Unresolved { job, error } => {
            assert_eq!(
                error.stage(),
                Stage::Retire,
                "cleanup failure keeps custody: {error:?}"
            );
            job
        }
        other => panic!("expected Unresolved output-only job, got {other:?}"),
    };
    assert_eq!(executor.usage().jobs, 1);
    // The root stays reserved while cleanup is unresolved.
    let second = compile_fixture(
        &mut executor,
        &tools,
        &short_request_in(&source, &dir.join("out"), 50),
    );
    assert_rejected(second, ErrorKind::InvalidInput, Stage::Admission);
    // Repair the mode; the job resolves to the original NoEffect cause.
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir.join("out"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let outcome = job.reconcile(&mut executor, Instant::now() + Duration::from_secs(5));
    assert_rejected(outcome, ErrorKind::Backend, Stage::Execute);
    assert_eq!(executor.usage().jobs, 0);
    assert!(!dir.join("out").exists());
    assert!(matches!(
        executor.close(),
        scopebase_testkit::toolchain::ExecutorClose::Closed
    ));
}

#[test]
fn tool_missing_and_rejected_cannot_discard_custody() {
    let dir = TempDir::named("nodiscard");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let mut backend = Scripted::new();
    backend
        .starts
        .borrow_mut()
        .push_back(ScriptStart::NoEffect(ErrorKind::Backend, Stage::Execute));
    backend.write_object = Some(b"partial".to_vec());
    backend.sabotage_root_mode = Some(0o555);
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &request_in(&source, &dir.join("out")),
    );
    let job = match outcome {
        CompileOutcome::Unresolved { job, .. } => job,
        other => panic!("expected Unresolved, got {other:?}"),
    };
    // A ToolMissing call (nonexistent executable path, same executor shape).
    let missing_selection = RoleSelection {
        llc: Some(binding("test-llc", Path::new("/nonexistent/tool"), b"v")),
        loaded_llvm: Some(binding("test-libllvm", &fake_tool("silent-ok"), b"v")),
        ..RoleSelection::none()
    };
    let missing_tools = SelectedClosure::select(&manifest, &missing_selection).unwrap();
    let outcome = compile_fixture(
        &mut executor,
        &missing_tools,
        &request_in(&source, &dir.join("other")),
    );
    assert!(
        matches!(outcome, CompileOutcome::ToolMissing { .. }),
        "got {outcome:?}"
    );
    // A Rejected call (forbidden env key).
    let mut bad = request_in(&source, &dir.join("third"));
    bad.environment
        .insert(OsString::from("RUSTC"), OsString::from("x"));
    let outcome = compile_fixture(&mut executor, &tools, &bad);
    assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
    // The output-only entry is untouched.
    assert_eq!(executor.usage().jobs, 1);
    assert!(dir.join("out").exists());
    drop(job);
    // Teardown only: restore the sabotaged mode so the scratch dir removes.
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir.join("out"), std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn uncertain_start_retains_custody_then_settles() {
    let dir = TempDir::named("uncertain");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let mut backend = Scripted::new();
    backend
        .starts
        .borrow_mut()
        .push_back(ScriptStart::Uncertain(ErrorKind::Backend, Stage::Execute));
    backend.write_object = Some(b"obj".to_vec());
    backend.polls.borrow_mut().push_back(ScriptPoll::Running);
    backend.polls.borrow_mut().push_back(ScriptPoll::Settled {
        exit: BuildExit::Exited(0),
        objects: vec![dir.join("out").join("obj.o")],
        diagnostic: Vec::new(),
    });
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &short_request_in(&source, &dir.join("out"), 100),
    );
    // Uncertain start surfaces immediately with custody, without polling.
    let job = match outcome {
        CompileOutcome::Unresolved { job, error } => {
            assert_eq!(
                (error.kind(), error.stage()),
                (ErrorKind::Backend, Stage::Execute)
            );
            job
        }
        other => panic!("expected Unresolved, got {other:?}"),
    };
    assert_eq!(executor.usage().jobs, 1);
    let outcome = job.reconcile(&mut executor, Instant::now() + Duration::from_secs(5));
    match outcome {
        CompileOutcome::Emitted { output } => output.release(&mut executor).unwrap(),
        other => panic!("expected Emitted after settlement, got {other:?}"),
    }
    assert!(matches!(
        executor.close(),
        scopebase_testkit::toolchain::ExecutorClose::Closed
    ));
}

#[test]
fn signaled_exit_refuses_only_after_settlement() {
    let dir = TempDir::named("signaled");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let backend = Scripted::new();
    backend.polls.borrow_mut().push_back(ScriptPoll::Running);
    backend.polls.borrow_mut().push_back(ScriptPoll::Running);
    backend.polls.borrow_mut().push_back(ScriptPoll::Settled {
        exit: BuildExit::Signaled(9),
        objects: Vec::new(),
        diagnostic: b"killed\n".to_vec(),
    });
    let polls = Rc::clone(&backend.poll_calls);
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &request_in(&source, &dir.join("out")),
    );
    match outcome {
        CompileOutcome::Refused { diagnostic, output } => {
            assert_eq!(diagnostic, b"killed\n");
            assert!(output.objects().is_empty());
            // Refusal output is inspectable but leased: release still required.
            output.release(&mut executor).unwrap();
        }
        other => panic!("expected Refused, got {other:?}"),
    }
    assert!(
        polls.get() >= 3,
        "refusal waits for settlement, polls={}",
        polls.get()
    );
    assert!(matches!(
        executor.close(),
        scopebase_testkit::toolchain::ExecutorClose::Closed
    ));
}

#[test]
fn nonzero_and_empty_and_foreign_outputs_refuse_emitted() {
    let dir = TempDir::named("refuse-shape");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let source = make_source(&dir);
    // Foreign object: a real file outside the output root.
    let foreign = dir.join("foreign.o");
    std::fs::write(&foreign, b"foreign").unwrap();
    let cases: Vec<(BuildExit, Vec<PathBuf>, &'static str)> = vec![
        (BuildExit::Exited(1), Vec::new(), "nonzero"),
        (BuildExit::Exited(0), Vec::new(), "no objects"),
        (BuildExit::Exited(0), vec![foreign], "foreign object"),
    ];
    for (exit, objects, label) in cases {
        let backend = Scripted::new();
        backend.polls.borrow_mut().push_back(ScriptPoll::Settled {
            exit,
            objects,
            diagnostic: b"d".to_vec(),
        });
        let mut executor = new_executor(backend);
        let outcome = compile_fixture(
            &mut executor,
            &tools,
            &request_in(&source, &dir.join(format!("out-{label}"))),
        );
        match outcome {
            CompileOutcome::Refused { output, .. } => output.release(&mut executor).unwrap(),
            other => panic!("{label}: expected Refused, got {other:?}"),
        }
        assert!(matches!(
            executor.close(),
            scopebase_testkit::toolchain::ExecutorClose::Closed
        ));
    }
}

#[test]
fn oversize_objects_refuse_emitted() {
    let dir = TempDir::named("oversize");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let mut backend = Scripted::new();
    backend.write_object = Some(vec![0x6f; 100]);
    backend.polls.borrow_mut().push_back(ScriptPoll::Settled {
        exit: BuildExit::Exited(0),
        objects: vec![dir.join("out").join("obj.o")],
        diagnostic: Vec::new(),
    });
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let mut request = request_in(&source, &dir.join("out"));
    request.max_artifact_bytes = 99;
    let outcome = compile_fixture(&mut executor, &tools, &request);
    match outcome {
        CompileOutcome::Refused { output, .. } => output.release(&mut executor).unwrap(),
        other => panic!("expected Refused for oversize objects, got {other:?}"),
    }
}

#[test]
fn unresolved_poll_retains_job_for_retry() {
    let dir = TempDir::named("retry");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let mut backend = Scripted::new();
    backend.write_object = Some(b"obj".to_vec());
    backend
        .polls
        .borrow_mut()
        .push_back(ScriptPoll::Unresolved(ErrorKind::Backend, Stage::Execute));
    backend.polls.borrow_mut().push_back(ScriptPoll::Settled {
        exit: BuildExit::Exited(0),
        objects: vec![dir.join("out").join("obj.o")],
        diagnostic: Vec::new(),
    });
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &request_in(&source, &dir.join("out")),
    );
    let job = match outcome {
        CompileOutcome::Unresolved { job, error } => {
            assert_eq!(
                (error.kind(), error.stage()),
                (ErrorKind::Backend, Stage::Execute)
            );
            job
        }
        other => panic!("expected Unresolved, got {other:?}"),
    };
    let outcome = job.reconcile(&mut executor, Instant::now() + Duration::from_secs(5));
    match outcome {
        CompileOutcome::Emitted { output } => output.release(&mut executor).unwrap(),
        other => panic!("expected Emitted after retry, got {other:?}"),
    }
    assert!(matches!(
        executor.close(),
        scopebase_testkit::toolchain::ExecutorClose::Closed
    ));
}

#[test]
fn descendant_writer_blocks_settlement_stop_and_root_reuse() {
    // The plan's key model: a parent exits while a linker descendant keeps
    // writing. Neither settlement, stop success nor root reuse is allowed
    // until the writer is positively retired.
    let dir = TempDir::named("descendant");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let mut backend = Scripted::new();
    // Initial poll loop: parent gone, descendant writing.
    // request_stop: stop requested, writer still active.
    // Final reconcile: writer retired, scope settled with an object.
    backend.write_object = Some(b"obj".to_vec());
    let polls = Rc::clone(&backend.polls);
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &short_request_in(&source, &dir.join("out"), 100),
    );
    let job = match outcome {
        CompileOutcome::TimedOut { job } => job,
        other => panic!("expected TimedOut, got {other:?}"),
    };
    // Root reuse refuses while the writer scope is live.
    let second = compile_fixture(
        &mut executor,
        &tools,
        &short_request_in(&source, &dir.join("out"), 50),
    );
    assert_rejected(second, ErrorKind::InvalidInput, Stage::Admission);
    // A stop request against an active writer times out with custody.
    let outcome = job.request_stop(&mut executor, Instant::now() + Duration::from_millis(100));
    let job = match outcome {
        CompileOutcome::TimedOut { job } => job,
        other => panic!("expected TimedOut while writer active, got {other:?}"),
    };
    // The writer retires; the same job settles and its root releases.
    polls.borrow_mut().push_back(ScriptPoll::Settled {
        exit: BuildExit::Exited(0),
        objects: vec![dir.join("out").join("obj.o")],
        diagnostic: Vec::new(),
    });
    let outcome = job.reconcile(&mut executor, Instant::now() + Duration::from_secs(5));
    match outcome {
        CompileOutcome::Emitted { output } => output.release(&mut executor).unwrap(),
        other => panic!("expected Emitted after writer retirement, got {other:?}"),
    }
    assert!(matches!(
        executor.close(),
        scopebase_testkit::toolchain::ExecutorClose::Closed
    ));
}

#[test]
fn release_failure_retains_custody() {
    let dir = TempDir::named("release-fail");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let mut backend = Scripted::new();
    backend.write_object = Some(b"obj".to_vec());
    backend.polls.borrow_mut().push_back(ScriptPoll::Settled {
        exit: BuildExit::Exited(0),
        objects: vec![dir.join("out").join("obj.o")],
        diagnostic: Vec::new(),
    });
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &request_in(&source, &dir.join("out")),
    );
    let output = match outcome {
        CompileOutcome::Emitted { output } => output,
        other => panic!("expected Emitted, got {other:?}"),
    };
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir.join("out"), std::fs::Permissions::from_mode(0o555)).unwrap();
    let failure = output.release(&mut executor).unwrap_err();
    assert_eq!(failure.error.stage(), Stage::Retire);
    assert_eq!(executor.usage().jobs, 1, "failed release retains custody");
    assert!(!failure.output.objects().is_empty());
    std::fs::set_permissions(dir.join("out"), std::fs::Permissions::from_mode(0o755)).unwrap();
    failure.output.release(&mut executor).unwrap();
    assert_eq!(executor.usage().jobs, 0);
    assert!(!dir.join("out").exists());
    assert!(matches!(
        executor.close(),
        scopebase_testkit::toolchain::ExecutorClose::Closed
    ));
}

#[test]
fn close_returns_executor_while_owned() {
    let dir = TempDir::named("close");
    let (manifest, lib) = rich_manifest(&dir);
    let tools = SelectedClosure::select(&manifest, &llc_selection(&lib)).unwrap();
    let backend = Scripted::new();
    let mut executor = new_executor(backend);
    let source = make_source(&dir);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &short_request_in(&source, &dir.join("out"), 100),
    );
    let job = match outcome {
        CompileOutcome::TimedOut { job } => job,
        other => panic!("expected TimedOut, got {other:?}"),
    };
    drop(job);
    match executor.close() {
        scopebase_testkit::toolchain::ExecutorClose::Closed => {
            panic!("live entry must block close")
        }
        scopebase_testkit::toolchain::ExecutorClose::Unresolved(executor) => {
            // Recovery intact: the orphan is still reconciled, not lost.
            assert_eq!(executor.usage().jobs, 1);
        }
    }
}

// ---------------------------------------------------------------------------
// Direct no-children scope: real subprocesses under enforcement.
// ---------------------------------------------------------------------------

fn direct_tools(dir: &TempDir, tool: &str, pin_id: &str) -> SelectedClosure {
    let lib = fake_lib_llvm(dir, "libLLVM.so");
    let manifest = manifest_of(&[
        pin_json(pin_id, "backend", "23.1.2", &fake_tool(tool)),
        pin_json("direct-libllvm", "backend", "23.1.2", &lib),
    ]);
    let selection = RoleSelection {
        llc: Some(binding(pin_id, &fake_tool(tool), b"fake direct tool")),
        loaded_llvm: Some(binding("direct-libllvm", &lib, b"fake libLLVM")),
        ..RoleSelection::none()
    };
    SelectedClosure::select(&manifest, &selection).unwrap()
}

fn direct_executor() -> CompilerExecutor<DirectScope> {
    CompilerExecutor::new(DirectScope::new(), generous_limits()).unwrap()
}

/// Parse a record-build output: `TC02OBJ\n` then NUL-separated argv.
fn recorded_argv(object: &Path) -> Vec<Vec<u8>> {
    let bytes = std::fs::read(object).unwrap();
    assert!(bytes.starts_with(b"TC02OBJ\n"), "missing object marker");
    let mut parts: Vec<Vec<u8>> = bytes[b"TC02OBJ\n".len()..]
        .split(|byte| *byte == 0)
        .map(<[u8]>::to_vec)
        .collect();
    assert_eq!(parts.pop(), Some(Vec::new()));
    parts
}

fn llvm_hex(tools: &SelectedClosure) -> String {
    tools
        .loaded_llvm()
        .sha256
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn direct_positive_emits_object() {
    let dir = TempDir::named("direct-ok");
    let tools = direct_tools(&dir, "record-build", "direct-llc");
    let mut executor = direct_executor();
    let source = make_source(&dir);
    let out = dir.join("out");
    let mut request = request_in(&source, &out);
    request.environment.insert(
        OsString::from("TC02_SPAWN_MARKER"),
        dir.join("spawned").into_os_string(),
    );
    let outcome = compile_fixture(&mut executor, &tools, &request);
    match outcome {
        CompileOutcome::Emitted { output } => {
            assert_eq!(output.objects(), &[out.join("output.o")]);
            assert!(dir.join("spawned").exists(), "tool ran with explicit env");
            output.release(&mut executor).unwrap();
        }
        other => panic!("expected Emitted, got {other:?}"),
    }
    assert_eq!(executor.usage().jobs, 0);
    assert!(matches!(
        executor.close(),
        scopebase_testkit::toolchain::ExecutorClose::Closed
    ));
}

#[test]
fn direct_argv_is_pinned_and_audited() {
    let dir = TempDir::named("direct-argv");
    let tools = direct_tools(&dir, "record-build", "direct-llc");
    let mut executor = direct_executor();
    let source = make_source(&dir);
    let out = dir.join("out");
    let mut request = request_in(&source, &out);
    request.cpu = Some("v4".to_owned());
    request.features = vec!["+x".to_owned(), "-y".to_owned()];
    let outcome = compile_fixture(&mut executor, &tools, &request);
    let output = match outcome {
        CompileOutcome::Emitted { output } => output,
        other => panic!("expected Emitted, got {other:?}"),
    };
    let argv = recorded_argv(&output.objects()[0]);
    let expected: Vec<Vec<u8>> = vec![
        b"-mtriple=bpfel-unknown-none".to_vec(),
        b"-mcpu=v4".to_vec(),
        b"--mattr=+x".to_vec(),
        b"--mattr=-y".to_vec(),
        b"-O2".to_vec(),
        b"-filetype=obj".to_vec(),
        source.join("input.ll").as_os_str().as_bytes().to_vec(),
        b"-o".to_vec(),
        out.join("output.o").as_os_str().as_bytes().to_vec(),
    ];
    assert_eq!(argv, expected, "direct argv is fixed by the profile");
    output.release(&mut executor).unwrap();
}

#[test]
fn direct_cpu_variants_distinct() {
    let dir = TempDir::named("direct-cpu");
    let tools = direct_tools(&dir, "record-build", "direct-llc");
    let mut executor = direct_executor();
    let source = make_source(&dir);
    let mut seen = Vec::new();
    for (cpu, label) in [
        (None, "none"),
        (Some("generic".to_owned()), "generic"),
        (Some("v3".to_owned()), "v3"),
        (Some("v4".to_owned()), "v4"),
    ] {
        let out = dir.join(format!("out-{label}"));
        let mut request = request_in(&source, &out);
        request.cpu = cpu;
        let outcome = compile_fixture(&mut executor, &tools, &request);
        let output = match outcome {
            CompileOutcome::Emitted { output } => output,
            other => panic!("cpu {label}: expected Emitted, got {other:?}"),
        };
        let argv = recorded_argv(&output.objects()[0]);
        let mcpu: Vec<&[u8]> = argv
            .iter()
            .filter(|arg| arg.starts_with(b"-mcpu="))
            .map(Vec::as_slice)
            .collect();
        match label {
            "none" => assert!(mcpu.is_empty(), "None cpu omits -mcpu"),
            other => assert_eq!(
                mcpu,
                vec![format!("-mcpu={other}").as_bytes()],
                "cpu {label}"
            ),
        }
        seen.push(argv);
        output.release(&mut executor).unwrap();
    }
    for (i, a) in seen.iter().enumerate() {
        for b in seen.iter().skip(i + 1) {
            assert_ne!(a, b, "cpu variants must stay distinct");
        }
    }
}

#[test]
fn direct_cpu_empty_and_unknown_refuse() {
    let dir = TempDir::named("direct-cpu-bad");
    let tools = direct_tools(&dir, "record-build", "direct-llc");
    let mut executor = direct_executor();
    let source = make_source(&dir);
    for cpu in ["", "v9"] {
        let marker = dir.join(format!("marker-{cpu}"));
        let mut request = request_in(&source, &dir.join(format!("out-{cpu}")));
        request.cpu = Some(cpu.to_owned());
        request.environment.insert(
            OsString::from("TC02_SPAWN_MARKER"),
            marker.clone().into_os_string(),
        );
        let outcome = compile_fixture(&mut executor, &tools, &request);
        assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
        assert!(!marker.exists(), "cpu {cpu:?} refuses before spawn");
    }
    assert_eq!(executor.usage().jobs, 0);
}

#[test]
fn direct_cargo_profile_refused_without_spawn() {
    let dir = TempDir::named("direct-cargo");
    // A coherent cargo/rustc/sysroot triple plus llc: the host direct scope
    // admits no Cargo profile, even a verified one.
    let (manifest, mut selection, _) = pair_selection(&dir, "1.90.0", "1.90.0", true, true);
    selection.llc = Some(binding("pair-llc", &fake_tool("record-build"), b"fake llc"));
    let tools = SelectedClosure::select(&manifest, &selection).unwrap();
    let mut executor = direct_executor();
    let source = make_source(&dir);
    let marker = dir.join("marker");
    let mut request = request_in(&source, &dir.join("out"));
    request.environment.insert(
        OsString::from("TC02_SPAWN_MARKER"),
        marker.clone().into_os_string(),
    );
    let outcome = compile_fixture(&mut executor, &tools, &request);
    assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
    assert!(!marker.exists(), "cargo profile refuses before spawn");
    assert_eq!(executor.usage().jobs, 0);
}

#[test]
fn direct_linker_role_refused() {
    let dir = TempDir::named("direct-linker");
    let (manifest, lib) = rich_manifest(&dir);
    let mut selection = llc_selection(&lib);
    selection.linker = Some(binding(
        "test-linker",
        &fake_tool("fake-linker"),
        b"fake linker",
    ));
    let tools = SelectedClosure::select(&manifest, &selection).unwrap();
    let mut executor = direct_executor();
    let source = make_source(&dir);
    let marker = dir.join("marker");
    let mut request = request_in(&source, &dir.join("out"));
    request.environment.insert(
        OsString::from("TC02_SPAWN_MARKER"),
        marker.clone().into_os_string(),
    );
    let outcome = compile_fixture(&mut executor, &tools, &request);
    assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
    assert!(!marker.exists(), "linker role refuses before spawn");
}

#[test]
fn direct_fork_attempt_killed_by_enforcement() {
    let dir = TempDir::named("direct-fork");
    let tools = direct_tools(&dir, "try-spawn", "direct-llc");
    let mut executor = direct_executor();
    let source = make_source(&dir);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &request_in(&source, &dir.join("out")),
    );
    match outcome {
        CompileOutcome::Refused { diagnostic, output } => {
            let text = String::from_utf8_lossy(&diagnostic);
            assert!(
                text.starts_with("direct-no-children-v1 exit=Signaled(31)"),
                "fork attempt must die SIGSYS under enforcement: {text:?}"
            );
            output.release(&mut executor).unwrap();
        }
        other => panic!("expected Refused, got {other:?}"),
    }
    // Control: without the sandbox the same tool is a sound exit-zero fake.
    let manifest = manifest_of(&[pin_json("ctl", "backend", "1.0.0", &fake_tool("try-spawn"))]);
    let bounds = NestedBounds {
        max_stdout_bytes: 1 << 20,
        max_stderr_bytes: 1 << 20,
        timeout_ms: 10_000,
        max_args: 64,
        max_env: 64,
    };
    let out = run_pinned(&manifest, "ctl", &fake_tool("try-spawn"), &[], &[], &bounds).unwrap();
    assert!(out.success(), "unenforced try-spawn exits zero");
}

#[test]
fn direct_timeout_then_stop_settles() {
    let dir = TempDir::named("direct-stop");
    let tools = direct_tools(&dir, "block-on-input", "direct-llc");
    let mut executor = direct_executor();
    // The input itself is a fifo with no writer: the tool blocks in open.
    let source = dir.join("src");
    std::fs::create_dir_all(&source).unwrap();
    let fifo = source.join("input.ll");
    let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    let rc = unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o644) };
    assert_eq!(rc, 0, "mkfifo failed");
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &short_request_in(&source, &dir.join("out"), 300),
    );
    let job = match outcome {
        CompileOutcome::TimedOut { job } => job,
        other => panic!("expected TimedOut, got {other:?}"),
    };
    let outcome = job.request_stop(&mut executor, Instant::now() + Duration::from_secs(10));
    match outcome {
        CompileOutcome::Refused { diagnostic, output } => {
            let text = String::from_utf8_lossy(&diagnostic);
            assert!(
                text.contains("exit=Signaled(15)"),
                "stop kills with SIGTERM: {text:?}"
            );
            output.release(&mut executor).unwrap();
        }
        other => panic!("expected Refused after stop, got {other:?}"),
    }
    assert!(matches!(
        executor.close(),
        scopebase_testkit::toolchain::ExecutorClose::Closed
    ));
}

#[test]
fn direct_stdout_cap_n_nplus1() {
    let dir = TempDir::named("direct-cap");
    let tools = direct_tools(&dir, "bounded-emit", "direct-llc");
    let mut executor = direct_executor();
    let source = make_source(&dir);
    for (emit, cap, emits) in [(64u32, 64usize, true), (65u32, 64usize, false)] {
        let out = dir.join(format!("out-{emit}"));
        let mut request = request_in(&source, &out);
        request.max_output_bytes = cap;
        request.environment.insert(
            OsString::from("TC02_EMIT_BYTES"),
            OsString::from(emit.to_string()),
        );
        let outcome = compile_fixture(&mut executor, &tools, &request);
        if emits {
            match outcome {
                CompileOutcome::Emitted { output } => output.release(&mut executor).unwrap(),
                other => panic!("N={emit} must emit, got {other:?}"),
            }
        } else {
            match outcome {
                CompileOutcome::Refused { diagnostic, output } => {
                    let text = String::from_utf8_lossy(&diagnostic);
                    assert!(
                        text.contains("overrun=stdout"),
                        "N+1 reports overrun: {text:?}"
                    );
                    output.release(&mut executor).unwrap();
                }
                other => panic!("N+1={emit} must refuse, got {other:?}"),
            }
        }
    }
}

#[test]
fn direct_missing_input_refuses() {
    let dir = TempDir::named("direct-noinput");
    let tools = direct_tools(&dir, "record-build", "direct-llc");
    let mut executor = direct_executor();
    let source = dir.join("src");
    std::fs::create_dir_all(&source).unwrap(); // no input.ll
    let marker = dir.join("marker");
    let mut request = request_in(&source, &dir.join("out"));
    request.environment.insert(
        OsString::from("TC02_SPAWN_MARKER"),
        marker.clone().into_os_string(),
    );
    let outcome = compile_fixture(&mut executor, &tools, &request);
    assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
    assert!(!marker.exists(), "missing input refuses before spawn");
}

#[test]
fn direct_non_utf8_paths_retain_bytes() {
    let dir = TempDir::named("direct-nonutf8");
    // Non-UTF8 tool path: copy the fake aside and pin the copy.
    let tool = dir
        .path
        .join(OsString::from_vec(vec![0x74, 0x80, 0x6f, 0x6c]));
    std::fs::copy(fake_tool("record-build"), &tool).unwrap();
    let lib = fake_lib_llvm(&dir, "libLLVM.so");
    let manifest = manifest_of(&[
        pin_json("nonutf8-llc", "backend", "23.1.2", &tool),
        pin_json("nonutf8-libllvm", "backend", "23.1.2", &lib),
    ]);
    let selection = RoleSelection {
        llc: Some(binding("nonutf8-llc", &tool, b"v")),
        loaded_llvm: Some(binding("nonutf8-libllvm", &lib, b"v")),
        ..RoleSelection::none()
    };
    let tools = SelectedClosure::select(&manifest, &selection).unwrap();
    let mut executor = direct_executor();
    let source = dir
        .path
        .join(OsString::from_vec(vec![0x73, 0x80, 0x72, 0x63]));
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("input.ll"), b"; fake IR\n").unwrap();
    let out = dir
        .path
        .join(OsString::from_vec(vec![0x6f, 0x80, 0x75, 0x74]));
    let outcome = compile_fixture(&mut executor, &tools, &request_in(&source, &out));
    let output = match outcome {
        CompileOutcome::Emitted { output } => output,
        other => panic!("expected Emitted, got {other:?}"),
    };
    let argv = recorded_argv(&output.objects()[0]);
    let joined: Vec<u8> = argv.join(&0);
    assert!(
        joined.windows(4).any(|w| w == [0x6f, 0x80, 0x75, 0x74]),
        "non-UTF8 output bytes survive argv transport"
    );
    output.release(&mut executor).unwrap();
}

#[test]
fn direct_tampered_tool_refuses() {
    let dir = TempDir::named("direct-tamper");
    let tool = dir.join("tool");
    std::fs::copy(fake_tool("record-build"), &tool).unwrap();
    let lib = fake_lib_llvm(&dir, "libLLVM.so");
    let manifest = manifest_of(&[
        pin_json("tamper-llc", "backend", "23.1.2", &tool),
        pin_json("tamper-libllvm", "backend", "23.1.2", &lib),
    ]);
    let selection = RoleSelection {
        llc: Some(binding("tamper-llc", &tool, b"v")),
        loaded_llvm: Some(binding("tamper-libllvm", &lib, b"v")),
        ..RoleSelection::none()
    };
    let tools = SelectedClosure::select(&manifest, &selection).unwrap();
    // Tamper after selection: the start-time re-hash must catch it.
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&tool)
        .unwrap()
        .write_all(b"x")
        .unwrap();
    let mut executor = direct_executor();
    let source = make_source(&dir);
    let marker = dir.join("marker");
    let mut request = request_in(&source, &dir.join("out"));
    request.environment.insert(
        OsString::from("TC02_SPAWN_MARKER"),
        marker.clone().into_os_string(),
    );
    let outcome = compile_fixture(&mut executor, &tools, &request);
    assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
    assert!(!marker.exists(), "tampered tool refuses before spawn");
}

#[test]
fn direct_feature_surface_audited() {
    let dir = TempDir::named("direct-feat");
    let tools = direct_tools(&dir, "record-build", "direct-llc");
    let mut executor = direct_executor();
    let source = make_source(&dir);
    // Response files and plugin-shaped features refuse: the only caller
    // arg surface is the validated feature list.
    for (features, label) in [
        (vec!["@resp".to_owned()], "response"),
        (vec!["bad feat".to_owned()], "space"),
        (vec!["a;b".to_owned()], "semicolon"),
    ] {
        let mut request = request_in(&source, &dir.join(format!("out-{label}")));
        request.features = features;
        let outcome = compile_fixture(&mut executor, &tools, &request);
        assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
    }
    // A valid feature enters argv as --mattr and the build emits.
    let mut request = request_in(&source, &dir.join("out-ok"));
    request.features = vec!["+v4".to_owned()];
    let outcome = compile_fixture(&mut executor, &tools, &request);
    let output = match outcome {
        CompileOutcome::Emitted { output } => output,
        other => panic!("expected Emitted, got {other:?}"),
    };
    let argv = recorded_argv(&output.objects()[0]);
    assert!(argv.iter().any(|arg| arg == b"--mattr=+v4"));
    output.release(&mut executor).unwrap();
    assert_eq!(executor.usage().jobs, 0);
}

#[test]
fn direct_invalid_target_refuses() {
    let dir = TempDir::named("direct-target");
    let tools = direct_tools(&dir, "record-build", "direct-llc");
    let mut executor = direct_executor();
    let source = make_source(&dir);
    let marker = dir.join("marker");
    let mut request = request_in(&source, &dir.join("out"));
    request.target = "bpf el".to_owned();
    request.environment.insert(
        OsString::from("TC02_SPAWN_MARKER"),
        marker.clone().into_os_string(),
    );
    let outcome = compile_fixture(&mut executor, &tools, &request);
    assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
    assert!(!marker.exists(), "invalid target refuses before spawn");
}

#[test]
fn direct_enforcement_available() {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    assert!(DirectScope::enforcement_available());
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    assert!(!DirectScope::enforcement_available());
}

#[test]
fn direct_records_loaded_llvm_identity() {
    let dir = TempDir::named("direct-llvm");
    // silent-ok exits zero with no outputs: Refused, with the header intact.
    let tools = direct_tools(&dir, "silent-ok", "direct-llc");
    let mut executor = direct_executor();
    let source = make_source(&dir);
    let outcome = compile_fixture(
        &mut executor,
        &tools,
        &request_in(&source, &dir.join("out")),
    );
    match outcome {
        CompileOutcome::Refused { diagnostic, output } => {
            let text = String::from_utf8_lossy(&diagnostic);
            assert!(
                text.starts_with("direct-no-children-v1 exit=Exited(0)"),
                "header: {text:?}"
            );
            assert!(text.contains("tool=direct-llc"), "tool pin: {text:?}");
            assert!(
                text.contains(&format!("loaded_llvm={}", llvm_hex(&tools))),
                "llvm: {text:?}"
            );
            assert!(text.contains("overrun=none"), "overrun: {text:?}");
            output.release(&mut executor).unwrap();
        }
        other => panic!("expected Refused, got {other:?}"),
    }
}

#[test]
fn fake_linker_records_loaded_llvm_distinct() {
    // The fake linker records the loaded LLVM identity next to Rust's and
    // Clang's LLVM, all three distinct, through the bounded helper.
    let manifest = manifest_of(&[pin_json(
        "fake-linker",
        "linker",
        "0.11.1",
        &fake_tool("fake-linker"),
    )]);
    let bounds = NestedBounds {
        max_stdout_bytes: 1 << 20,
        max_stderr_bytes: 1 << 20,
        timeout_ms: 10_000,
        max_args: 64,
        max_env: 64,
    };
    let loaded = sha_hex_of(&fake_tool("fake-linker"));
    let rust = "rust-llvm-22.1.4";
    let clang = "clang-llvm-18.1.8";
    let out = run_pinned(
        &manifest,
        "fake-linker",
        &fake_tool("fake-linker"),
        &[],
        &[
            (OsString::from("LOADED_LLVM_SHA"), OsString::from(&loaded)),
            (OsString::from("RUST_LLVM_SHA"), OsString::from(rust)),
            (OsString::from("CLANG_LLVM_SHA"), OsString::from(clang)),
        ],
        &bounds,
    )
    .unwrap();
    let text = String::from_utf8(out.stdout().to_vec()).unwrap();
    assert!(text.contains(&format!("loaded_llvm={loaded}")), "{text:?}");
    assert!(text.contains(&format!("rust_llvm={rust}")), "{text:?}");
    assert!(text.contains(&format!("clang_llvm={clang}")), "{text:?}");
    assert_ne!(loaded, rust);
    assert_ne!(loaded, clang);
}

fn max_timeout_bounds() -> NestedBounds {
    NestedBounds {
        max_stdout_bytes: 1 << 20,
        max_stderr_bytes: 1 << 20,
        timeout_ms: u64::MAX,
        max_args: 64,
        max_env: 64,
    }
}

/// R05 sweep: `timeout_ms` is u64 MILLISECONDS, so even u64::MAX
/// (~584M years) stays inside the Instant range: the MAX timeout is
/// honored as very-long, never refused and never panicking. Only raw
/// `Duration` params (audit/target sites) can overflow. This locks
/// the no-panic behavior: if the site ever takes a raw Duration,
/// MAX must panic here loudly instead of silently passing.
#[test]
fn run_pinned_max_timeout_is_honored_without_panic() {
    let manifest = manifest_of(&[pin_json("ctl", "backend", "1.0.0", &fake_tool("try-spawn"))]);
    let out = run_pinned(
        &manifest,
        "ctl",
        &fake_tool("try-spawn"),
        &[],
        &[],
        &max_timeout_bounds(),
    )
    .unwrap();
    assert!(out.success(), "MAX timeout must still run the tool");
}

/// S224: the steady-state half of hash-pinned-before-use. Bytes
/// corrupted after pin selection refuse at admission, before any
/// spawn — the hash is re-verified on every start. (The live-swap
/// race between hash and exec is the documented tool-dir-immutable
/// trust assumption in `DirectScope::start`, not covered here: no
/// deterministic test can hit a ~40-line window without injection.)
#[test]
fn s224_direct_corrupt_tool_refuses_before_spawn() {
    let dir = TempDir::named("direct-corrupt");
    let tool = dir.join("tool");
    std::fs::copy(fake_tool("record-build"), &tool).unwrap();
    let lib = fake_lib_llvm(&dir, "libLLVM.so");
    let manifest = manifest_of(&[
        pin_json("direct-llc", "backend", "23.1.2", &tool),
        pin_json("direct-libllvm", "backend", "23.1.2", &lib),
    ]);
    let selection = RoleSelection {
        llc: Some(binding("direct-llc", &tool, b"fake direct tool")),
        loaded_llvm: Some(binding("direct-libllvm", &lib, b"fake libLLVM")),
        ..RoleSelection::none()
    };
    let tools = SelectedClosure::select(&manifest, &selection).unwrap();
    // Corrupt AFTER pinning: the steady-state swap the hash catches.
    std::fs::write(&tool, b"tampered-bytes-not-the-tool").unwrap();
    let mut executor = direct_executor();
    let source = make_source(&dir);
    let marker = dir.join("marker");
    let mut request = request_in(&source, &dir.join("out"));
    request.environment.insert(
        OsString::from("TC02_SPAWN_MARKER"),
        marker.clone().into_os_string(),
    );
    let outcome = compile_fixture(&mut executor, &tools, &request);
    assert_rejected(outcome, ErrorKind::InvalidInput, Stage::Admission);
    assert!(!marker.exists(), "corrupt tool refuses before spawn");
}

/// S229/R32 canary: a preplanted symlink at the claimed path is
/// refused, never followed: the outside canary survives and nothing
/// is written through the link.
#[test]
fn s229_temp_claim_refuses_preplanted_symlink() {
    let nonce = start_nonce();
    let plant = std::env::temp_dir().join(format!(
        "tc02exec-{}-canary-plant-{:x}",
        std::process::id(),
        nonce
    ));
    let _ = std::fs::remove_file(&plant);
    let _ = std::fs::remove_dir_all(&plant);
    let outside = std::env::temp_dir().join(format!(
        "tc02exec-{}-canary-outside-{:x}",
        std::process::id(),
        nonce
    ));
    let _ = std::fs::remove_dir_all(&outside);
    claim_temp_dir(&outside);
    let canary = outside.join("canary.txt");
    std::fs::write(&canary, b"canary").unwrap();
    std::os::unix::fs::symlink(&outside, &plant).unwrap();
    let outcome = std::panic::catch_unwind(|| claim_temp_dir(&plant));
    assert!(
        outcome.is_err(),
        "preplanted symlink was claimed instead of refused"
    );
    assert_eq!(
        std::fs::read(&canary).unwrap(),
        b"canary",
        "claim wrote through the planted link"
    );
    std::fs::remove_file(&plant).unwrap();
    std::fs::remove_dir_all(&outside).unwrap();
}
