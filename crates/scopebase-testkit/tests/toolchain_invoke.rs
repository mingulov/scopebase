// SPDX-License-Identifier: Apache-2.0
//! TC02: explicit compiler closure admission and bounded nested-build helper.
//!
//! Donor slices (p11scope-ws w000 @ 6f97aa47, frozen tree):
//! `evidence/llvm-toolchain-review-20260922/kernel-oracle/prepare.py`
//! (lines 122-126: argv-array subprocess, timeout=20, bounded capture;
//! line 114 is core-dump `setrlimit`, not ported),
//! `evidence/llvm-toolchain-review-20260922/kernel-oracle/run.py`
//! (lines 56-57, 63-66: wall-clock budget, hash re-verify before exec).
//! Whole files are user-authored (TC01). ADAPT to Rust; no upstream lines
//! copied. Grant: OWNER-2026-10-23.
use scopebase_bpf::{ErrorKind, Limits, OperationError, Stage};
use scopebase_testkit::object::ToolchainInventory;
use scopebase_testkit::toolchain::{run_pinned, CompilerClosure, NestedBounds};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
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

fn refusal(error: &OperationError) -> (ErrorKind, Stage) {
    (error.kind(), error.stage())
}

fn generous() -> NestedBounds {
    NestedBounds {
        max_stdout_bytes: 1 << 20,
        max_stderr_bytes: 1 << 20,
        timeout_ms: 10_000,
        max_args: 64,
        max_env: 64,
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

fn valid_closure() -> String {
    format!(
        r#"{{
  "schema_version": 1,
  "kind": "tc02_compiler_closure",
  "tools": [
    {{
      "id": "llvm-23.1.2-source",
      "role": "source-archive",
      "name": "llvm-project",
      "version": "23.1.2",
      "version_detail": "llvmorg-23.1.2 release archive",
      "sha256": "c98bbef08a2b4c2613cd50e9aa9ae7b69b1fe6c16b2c40373bc0ab6116fdf78a",
      "origin": "pinned-archive",
      "origin_ref": "evidence EXCLUDED-large-files.sha256",
      "used_for": "pristine baseline build"
    }}
  ]
}}"#
    )
}

fn closure() -> CompilerClosure {
    CompilerClosure::from_json(valid_closure().as_bytes(), &limits()).unwrap()
}

// ---------------------------------------------------------------------------
// Closure admission
// ---------------------------------------------------------------------------

#[test]
fn valid_closure_admits_with_exact_pin() {
    let admitted = closure();
    assert_eq!(admitted.len(), 1);
    let tool = admitted.find("llvm-23.1.2-source").unwrap();
    assert_eq!(tool.version(), "23.1.2");
    assert_eq!(tool.origin(), "pinned-archive");
    assert_eq!(
        tool.sha256(),
        &[
            0xc9, 0x8b, 0xbe, 0xf0, 0x8a, 0x2b, 0x4c, 0x26, 0x13, 0xcd, 0x50, 0xe9, 0xaa, 0x9a,
            0xe7, 0xb6, 0x9b, 0x1f, 0xe6, 0xc1, 0x6b, 0x2c, 0x40, 0x37, 0x3b, 0xc0, 0xab, 0x61,
            0x16, 0xfd, 0xf7, 0x8a
        ]
    );
    assert!(admitted.find("no-such-tool").is_none());
}

#[test]
fn shipped_closure_manifest_admits_and_crosschecks_tc01() {
    let manifest = std::fs::read(repo_file("tools/bpf-compat/compiler-closure.json")).unwrap();
    // Offline-resolvable by construction: no URL or download reference anywhere.
    let text = std::str::from_utf8(&manifest).unwrap();
    for forbidden in [
        "http://", "https://", "ftp://", "download", "curl ", "wget ",
    ] {
        assert!(
            !text.contains(forbidden),
            "closure manifest must not reference the network: {forbidden:?}"
        );
    }
    let admitted = CompilerClosure::from_json(&manifest, &limits()).unwrap();
    assert!(!admitted.is_empty());
    let inventory_bytes = std::fs::read(repo_file("tools/bpf-compat/toolchains.json")).unwrap();
    let inventory = ToolchainInventory::from_json(&inventory_bytes, &limits()).unwrap();
    // Every closure pin must exist in the TC01 inventory with the identical hash.
    for tool in admitted.tools() {
        let pinned = inventory
            .find(tool.id())
            .unwrap_or_else(|| panic!("closure tool {} missing from TC01 inventory", tool.id()));
        assert_eq!(pinned.sha256(), Some(tool.sha256()));
        assert_eq!(pinned.version(), tool.version());
    }
    // Every TC01 recorded-hash tool is carried into the closure; unrecorded
    // system-observed tools are exactly the ones left out.
    for pinned in inventory.tools() {
        if pinned.hash_recorded() {
            assert!(
                admitted.find(pinned.id()).is_some(),
                "recorded TC01 pin {} must be in the closure",
                pinned.id()
            );
        } else {
            assert!(
                admitted.find(pinned.id()).is_none(),
                "unrecorded TC01 pin {} must stay out of the closure",
                pinned.id()
            );
        }
    }
}

#[test]
fn unpinned_tool_refuses() {
    // Null sha256: the TC01 inventory tolerates it, the closure must not.
    let null = valid_closure().replace(
        "\"sha256\": \"c98bbef08a2b4c2613cd50e9aa9ae7b69b1fe6c16b2c40373bc0ab6116fdf78a\"",
        "\"sha256\": null",
    );
    assert_eq!(
        refusal(&CompilerClosure::from_json(null.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    // Missing sha256 field.
    let missing: serde_json::Value = serde_json::from_str(&valid_closure()).unwrap();
    let mut missing = missing.clone();
    missing["tools"][0]
        .as_object_mut()
        .unwrap()
        .remove("sha256");
    assert_eq!(
        refusal(
            &CompilerClosure::from_json(
                serde_json::to_vec(&missing).unwrap().as_slice(),
                &limits()
            )
            .unwrap_err()
        ),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    // System-observed origin is not offline-resolvable.
    let observed = valid_closure().replace(
        "\"origin\": \"pinned-archive\"",
        "\"origin\": \"system-observed\"",
    );
    assert_eq!(
        refusal(&CompilerClosure::from_json(observed.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    // Wildcard version is not an exact pin.
    for bad_version in ["*", "23.*", "latest", ""] {
        let doc = valid_closure().replace(
            "\"version\": \"23.1.2\"",
            &format!("\"version\": \"{bad_version}\""),
        );
        assert_eq!(
            refusal(&CompilerClosure::from_json(doc.as_bytes(), &limits()).unwrap_err()),
            (ErrorKind::InvalidInput, Stage::Admission),
            "version {bad_version:?} must refuse"
        );
    }
    // Empty closure admits nothing.
    let mut empty: serde_json::Value = serde_json::from_str(&valid_closure()).unwrap();
    *empty.get_mut("tools").unwrap() = serde_json::json!([]);
    assert_eq!(
        refusal(
            &CompilerClosure::from_json(serde_json::to_vec(&empty).unwrap().as_slice(), &limits())
                .unwrap_err()
        ),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    // Duplicate tool id merges two pins.
    let mut dup: serde_json::Value = serde_json::from_str(&valid_closure()).unwrap();
    let twin = dup["tools"][0].clone();
    dup["tools"].as_array_mut().unwrap().push(twin);
    assert_eq!(
        refusal(
            &CompilerClosure::from_json(serde_json::to_vec(&dup).unwrap().as_slice(), &limits())
                .unwrap_err()
        ),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    // Unknown fields (a future `url` key included) refuse.
    let url = valid_closure().replacen(
        "\"used_for\": \"pristine baseline build\"",
        "\"used_for\": \"pristine baseline build\", \"url\": \"https://example.invalid/llvm.tar.gz\"",
        1,
    );
    assert_eq!(
        refusal(&CompilerClosure::from_json(url.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    // Wrong kind and version refuse.
    let kind = valid_closure().replace("tc02_compiler_closure", "tc01_toolchain_inventory");
    assert_eq!(
        refusal(&CompilerClosure::from_json(kind.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    let version = valid_closure().replace("\"schema_version\": 1", "\"schema_version\": 2");
    assert_eq!(
        refusal(&CompilerClosure::from_json(version.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    // Duplicate JSON fields refuse at every level.
    let dup_field = valid_closure().replacen(
        "\"origin_ref\":",
        "\"id\": \"llvm-23.1.2-source\", \"origin_ref\":",
        1,
    );
    assert_eq!(
        refusal(&CompilerClosure::from_json(dup_field.as_bytes(), &limits()).unwrap_err()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
}

#[test]
fn malformed_hashes_refuse_including_newline_suffix() {
    for bad in [
        "c98bbef08a2b4c2613cd50e9aa9ae7b69b1fe6c16b2c40373bc0ab6116fdf78a0",
        "C98BBEF08A2B4C2613CD50E9AA9AE7B69B1FE6C16B2C40373BC0AB6116FDF78A",
        "x98bbef08a2b4c2613cd50e9aa9ae7b69b1fe6c16b2c40373bc0ab6116fdf78a",
        "c98bbef08a2b4c2613cd50e9aa9ae7b69b1fe6c16b2c40373bc0ab6116fdf78a\\n",
        "",
    ] {
        let doc = valid_closure().replace(
            "c98bbef08a2b4c2613cd50e9aa9ae7b69b1fe6c16b2c40373bc0ab6116fdf78a",
            bad,
        );
        assert_eq!(
            refusal(&CompilerClosure::from_json(doc.as_bytes(), &limits()).unwrap_err()),
            (ErrorKind::InvalidInput, Stage::Admission),
            "hash {bad:?} must refuse"
        );
    }
}

#[test]
fn closure_input_bounds_refuse_before_parsing() {
    let bytes = valid_closure().into_bytes();
    let tight = Limits {
        input_bytes: bytes.len() - 1,
        ..limits()
    };
    assert_eq!(
        refusal(&CompilerClosure::from_json(&bytes, &tight).unwrap_err()),
        (ErrorKind::LimitExceeded, Stage::Admission)
    );
    assert_eq!(
        refusal(&CompilerClosure::from_json(b"{not json", &limits()).unwrap_err()),
        (ErrorKind::Malformed, Stage::Admission)
    );
}

// ---------------------------------------------------------------------------
// Bounded nested-build helper
// ---------------------------------------------------------------------------

#[test]
fn argv_passes_literally_with_no_shell() {
    let marker = std::env::temp_dir().join(format!("tc02-no-shell-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let tricky = format!("$(touch {})", marker.display());
    let args: Vec<OsString> = vec![
        OsString::from("a b"),
        OsString::from(";"),
        OsString::from(tricky),
        OsString::from("`id`"),
        OsString::from("--flag=x"),
        OsString::from_vec(vec![0x66, 0x80, 0x66]),
    ];
    let out = run_pinned(
        &closure(),
        "llvm-23.1.2-source",
        &fake_tool("echo-argv"),
        &args,
        &[],
        &generous(),
    )
    .unwrap();
    assert!(out.success());
    assert_eq!(out.code(), Some(0));
    let mut echoed: Vec<&[u8]> = out.stdout().split(|byte| *byte == 0).collect();
    assert_eq!(echoed.pop(), Some([].as_slice()));
    let expected: Vec<&[u8]> = args
        .iter()
        .map(|arg| {
            use std::os::unix::ffi::OsStrExt as _;
            arg.as_os_str().as_bytes()
        })
        .collect();
    assert_eq!(echoed, expected);
    assert!(
        !marker.exists(),
        "shell metacharacters must pass literally, never execute"
    );
}

#[test]
fn stdout_cap_boundary_aborts_typed() {
    let tool = fake_tool("emit-stdout");
    let bounds = NestedBounds {
        max_stdout_bytes: 64,
        ..generous()
    };
    let ok = run_pinned(
        &closure(),
        "llvm-23.1.2-source",
        &tool,
        &[OsString::from("64")],
        &[],
        &bounds,
    )
    .unwrap();
    assert_eq!(ok.stdout().len(), 64);
    let error = run_pinned(
        &closure(),
        "llvm-23.1.2-source",
        &tool,
        &[OsString::from("65")],
        &[],
        &bounds,
    )
    .unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::LimitExceeded, Stage::Execute));
    assert_eq!(error.required_size(), Some(65));
}

#[test]
fn stderr_cap_boundary_aborts_typed() {
    let tool = fake_tool("emit-stderr");
    let bounds = NestedBounds {
        max_stderr_bytes: 64,
        ..generous()
    };
    let ok = run_pinned(
        &closure(),
        "llvm-23.1.2-source",
        &tool,
        &[OsString::from("64")],
        &[],
        &bounds,
    )
    .unwrap();
    assert_eq!(ok.stderr().len(), 64);
    let error = run_pinned(
        &closure(),
        "llvm-23.1.2-source",
        &tool,
        &[OsString::from("65")],
        &[],
        &bounds,
    )
    .unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::LimitExceeded, Stage::Execute));
    assert_eq!(error.required_size(), Some(65));
}

#[test]
fn timeout_aborts_typed_without_waiting() {
    let bounds = NestedBounds {
        timeout_ms: 200,
        ..generous()
    };
    let started = Instant::now();
    let error = run_pinned(
        &closure(),
        "llvm-23.1.2-source",
        &fake_tool("sleep-tool"),
        &[OsString::from("30")],
        &[],
        &bounds,
    )
    .unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::LimitExceeded, Stage::Execute));
    assert_eq!(error.required_size(), None);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "timed-out child must be killed, not awaited"
    );
}

#[test]
fn unpinned_id_refuses_before_spawn() {
    // Unknown id refuses even though the local tool path exists.
    let error = run_pinned(
        &closure(),
        "no-such-tool",
        &fake_tool("silent-ok"),
        &[],
        &[],
        &generous(),
    )
    .unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::InvalidInput, Stage::Admission));
    // Unknown id also wins over a missing path: the closure is consulted first.
    let error = run_pinned(
        &closure(),
        "no-such-tool",
        &fake_tool("does-not-exist"),
        &[],
        &[],
        &generous(),
    )
    .unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::InvalidInput, Stage::Admission));
}

#[test]
fn missing_executable_is_typed() {
    let error = run_pinned(
        &closure(),
        "llvm-23.1.2-source",
        &fake_tool("does-not-exist"),
        &[],
        &[],
        &generous(),
    )
    .unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::InvalidInput, Stage::Execute));
}

#[test]
fn no_network_access_attempted() {
    // Serial requirement: this mutates process-global environment. It must
    // stay the only set_var/remove_var user in this binary; a second one
    // needs a shared static lock (or --test-threads=1) to avoid races.
    std::env::set_var("TC02_PROBE_LEAK", "must-not-propagate");
    let out = run_pinned(
        &closure(),
        "llvm-23.1.2-source",
        &fake_tool("dump-env"),
        &[],
        &[(OsString::from("FOO"), OsString::from("bar"))],
        &generous(),
    )
    .unwrap();
    std::env::remove_var("TC02_PROBE_LEAK");
    let env = String::from_utf8(out.stdout().to_vec()).unwrap();
    assert!(env.lines().any(|line| line == "FOO=bar"));
    assert!(env.lines().any(|line| line == "CARGO_NET_OFFLINE=true"));
    assert!(
        !env.lines().any(|line| line.starts_with("PATH=")),
        "inherited environment must not propagate"
    );
    assert!(
        !env.lines().any(|line| line.contains("TC02_PROBE_LEAK")),
        "process environment must not leak into the child"
    );
    assert!(
        !env.to_ascii_lowercase().contains("proxy"),
        "no proxy configuration may reach the child"
    );
}

#[test]
fn network_env_refuses_before_spawn() {
    for (key, value) in [
        ("http_proxy", "http://proxy.invalid:8080"),
        ("HTTPS_PROXY", "https://proxy.invalid:8080"),
        ("CARGO_NET_OFFLINE", "false"),
    ] {
        // Refusal wins even over a missing tool path: env is checked pre-spawn.
        let error = run_pinned(
            &closure(),
            "llvm-23.1.2-source",
            &fake_tool("does-not-exist"),
            &[],
            &[(OsString::from(key), OsString::from(value))],
            &generous(),
        )
        .unwrap_err();
        assert_eq!(
            refusal(&error),
            (ErrorKind::InvalidInput, Stage::Admission),
            "network env {key}={value} must refuse"
        );
    }
}

#[test]
fn nul_and_malformed_request_refuse_without_spawn() {
    // NUL bytes would panic std::process::Command; refuse first.
    let error = run_pinned(
        &closure(),
        "llvm-23.1.2-source",
        &fake_tool("does-not-exist"),
        &[OsString::from_vec(vec![0x61, 0x00])],
        &[],
        &generous(),
    )
    .unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::InvalidInput, Stage::Admission));
    // `=` in an env key cannot survive execve encoding.
    let error = run_pinned(
        &closure(),
        "llvm-23.1.2-source",
        &fake_tool("does-not-exist"),
        &[],
        &[(OsString::from("A=B"), OsString::from("c"))],
        &generous(),
    )
    .unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::InvalidInput, Stage::Admission));
    // Work caps: arg and env counts refuse pre-spawn with the attempted count.
    let tight = NestedBounds {
        max_args: 1,
        max_env: 1,
        ..generous()
    };
    let error = run_pinned(
        &closure(),
        "llvm-23.1.2-source",
        &fake_tool("does-not-exist"),
        &[OsString::from("a"), OsString::from("b")],
        &[],
        &tight,
    )
    .unwrap_err();
    assert_eq!(
        refusal(&error),
        (ErrorKind::LimitExceeded, Stage::Admission)
    );
    assert_eq!(error.required_size(), Some(2));
    let error = run_pinned(
        &closure(),
        "llvm-23.1.2-source",
        &fake_tool("does-not-exist"),
        &[],
        &[
            (OsString::from("A"), OsString::from("1")),
            (OsString::from("B"), OsString::from("2")),
        ],
        &tight,
    )
    .unwrap_err();
    assert_eq!(
        refusal(&error),
        (ErrorKind::LimitExceeded, Stage::Admission)
    );
    assert_eq!(error.required_size(), Some(2));
}

#[test]
fn nonzero_exit_is_backend_failure() {
    let error = run_pinned(
        &closure(),
        "llvm-23.1.2-source",
        &fake_tool("exit-code"),
        &[OsString::from("3")],
        &[],
        &generous(),
    )
    .unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::Backend, Stage::Execute));
}

#[test]
fn zero_byte_cap_admits_only_silent_tools() {
    let silent = NestedBounds {
        max_stdout_bytes: 0,
        max_stderr_bytes: 0,
        ..generous()
    };
    let ok = run_pinned(
        &closure(),
        "llvm-23.1.2-source",
        &fake_tool("silent-ok"),
        &[],
        &[],
        &silent,
    )
    .unwrap();
    assert!(ok.stdout().is_empty() && ok.stderr().is_empty());
    let error = run_pinned(
        &closure(),
        "llvm-23.1.2-source",
        &fake_tool("echo-argv"),
        &[OsString::from("x")],
        &[],
        &silent,
    )
    .unwrap_err();
    assert_eq!(refusal(&error), (ErrorKind::LimitExceeded, Stage::Execute));
}

/// S33: a silent descendant holding stdout does not hang the exit
/// path, and the tool tree retires it. The tool exits at once while
/// its grandchild sleeps on the pipe; observing the exit proves the
/// pidfile is written and the grandchild alive, so the kill below is
/// fully deterministic. Old code joined the reader unbounded (hang);
/// settlement SIGKILLs the group and joins. A detach-only fix would
/// return while the grandchild still lived.
#[cfg(target_os = "linux")]
#[test]
fn exited_tool_settles_descendant_held_stdout() {
    let dir = std::env::temp_dir().join(format!(
        "tc02-s33-exit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let pidfile = dir.join("grandchild.pid");
    let tool = fake_tool("fork-silent-grandchild");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let out = run_pinned(
            &closure(),
            "llvm-23.1.2-source",
            &tool,
            &[OsString::from(pidfile.as_os_str())],
            &[],
            &generous(),
        );
        let _ = tx.send(
            out.map(|out| (out.code(), out.stdout().len()))
                .map_err(refusal_owned),
        );
    });
    let outcome = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("invoke hung on descendant-held stdout");
    let (code, stdout_len) = outcome.expect("exited tool succeeds");
    assert_eq!(code, Some(0));
    assert_eq!(stdout_len, 0, "tool and grandchild are silent");
    assert_grandchild_dead(&dir.join("grandchild.pid"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// S33: second-reader spawn failure completes (no hang) and reports
/// the spawn error. The stderr gate waits for the fixture's sleeper
/// RUNNING (sleep-prefixed cmdline) BEFORE the denied builder runs,
/// so the production cleanup branch always faces a proven-live
/// descendant holding stdout — lived-proven then dead-required, a
/// closed chain with no opportunistic branch.
#[cfg(target_os = "linux")]
#[test]
fn second_reader_failure_completes_with_forking_tool() {
    use scopebase_testkit::toolchain::run_pinned_with_builders;
    let dir = std::env::temp_dir().join(format!(
        "tc02-s33-fail-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let pidfile = dir.join("grandchild.pid");
    let tool = fake_tool("fork-silent-grandchild");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // R06: absurd stack size fails spawn deterministically.
        let denied = std::thread::Builder::new().stack_size(usize::MAX);
        let normal = std::thread::Builder::new().name("s33-stdout".to_string());
        let gate_pidfile = pidfile.clone();
        let lived = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gate_lived = lived.clone();
        let out = run_pinned_with_builders(
            &closure(),
            "llvm-23.1.2-source",
            &tool,
            &[OsString::from(pidfile.as_os_str())],
            &[],
            &generous(),
            normal,
            denied,
            Some(Box::new(move || {
                // Bounded wait only: a missing proof fails the
                // required assertions below, after cleanup retires
                // whatever the tool started (no panic-unwind leak).
                let deadline = Instant::now() + Duration::from_secs(10);
                while Instant::now() < deadline {
                    let running = std::fs::read_to_string(&gate_pidfile)
                        .ok()
                        .and_then(|text| text.trim().parse::<i32>().ok())
                        .and_then(|pid| std::fs::read(format!("/proc/{pid}/cmdline")).ok())
                        .map(|bytes| bytes.starts_with(b"sleep"))
                        .unwrap_or(false);
                    if running {
                        gate_lived.store(true, std::sync::atomic::Ordering::SeqCst);
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            })),
            None,
        );
        let lived = lived.load(std::sync::atomic::Ordering::SeqCst);
        let _ = tx.send((out.map(|_| ()).map_err(refusal_owned), lived));
    });
    let (outcome, lived) = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("cleanup hung on descendant-held stdout");
    assert_eq!(
        outcome.expect_err("spawn failure reports"),
        (ErrorKind::Backend, Stage::Execute)
    );
    // Required chain: the gate proved the sleeper RUNNING before
    // the failure, so cleanup must have retired it.
    assert!(lived, "gate must prove the sleeper running");
    assert_grandchild_dead(&dir.join("grandchild.pid"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
fn refusal_owned(error: OperationError) -> (ErrorKind, Stage) {
    refusal(&error)
}

/// S67-round4: with the WNOWAIT observation denied (seccomp EPERM
/// on `waitid`, reap and signaling allowed), the run still fails
/// `Backend/Execute`, retires the tool tree, and settles the
/// readers — never drops a live child and two reader handles. The
/// driver gates on the fixture's recorded sleeper RUNNING before
/// the first (denied) observation, so the denial branch always
/// faces a proven-live descendant (closed chain, like the S33
/// gate): the grandchild must be dead afterward with zero children
/// left behind and no unsettled/retirement fallout in the report.
/// Pre-fix the child was dropped live (a `sleep 300` survivor plus
/// an unreaped zombie).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn waitid_denial_still_retires_tool_and_readers() {
    let dir = std::env::temp_dir().join(format!(
        "tc02-s67-deny-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let pidfile = dir.join("grandchild.pid");
    let closure_path = dir.join("closure.json");
    std::fs::write(&closure_path, valid_closure()).unwrap();
    let tool = fake_tool("fork-silent-grandchild");
    let driver = PathBuf::from(env!("CARGO_BIN_EXE_scopebase-tc02-invoke-denial"));
    let mut child = std::process::Command::new(&driver)
        .arg("--tool")
        .arg(&tool)
        .arg("--closure")
        .arg(&closure_path)
        .arg("--timeout")
        .arg("10000")
        .arg("--gate-pidfile")
        .arg(&pidfile)
        .arg("--")
        .arg(&pidfile)
        .arg("307")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("denial driver spawns");
    let start_tick = boot_ticks_now();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait().expect("try_wait runs") {
            Some(_) => break,
            None => {
                if Instant::now() >= deadline {
                    // S98-round6: a hung driver never reported
                    // survivors — sweep the PATH-`sleep 307`
                    // grandchild before failing. (The fixture tool
                    // itself exits at once; only the grandchild can
                    // outlive the hang.) S112-round8: sweep first so
                    // any still-descended strays are in custody;
                    // already-reparented ones are spared and leaked.
                    let grandchild_args = ["307"];
                    let swept = hang_sweep(&[("sleep", grandchild_args.as_slice())], start_tick);
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("denial driver hung (S67 regression; swept {swept:?})");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
    let output = child.wait_with_output().expect("output collected");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.code() == Some(3) {
        assert!(
            stdout.starts_with("setup="),
            "exit 3 must carry its setup reason, got: {stdout}"
        );
        return;
    }
    assert!(
        output.status.success(),
        "driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.starts_with("verdict=err")
            && stdout.contains("kind=Backend")
            && stdout.contains("stage=Execute")
            && stdout.contains("errno=Some(1)"),
        "waitid denial must fail Backend/Execute with EPERM, got: {stdout}"
    );
    assert!(
        stdout.contains("children_after=0"),
        "no child may survive retirement, got: {stdout}"
    );
    assert!(
        !stdout.contains("unsettled") && !stdout.contains("retirement failed"),
        "clean retirement carries no fallout, got: {stdout}"
    );
    // Required chain: the gate proved the sleeper RUNNING before
    // the denied observation, so retirement must have reaped it.
    assert_grandchild_dead(&pidfile);
    let _ = std::fs::remove_dir_all(&dir);
}

/// S33: the recorded grandchild must be dead: SIGKILL is async, so
/// poll until its pid no longer names a sleep (gone, or conceivably
/// reused by a non-sleep — either way our sleeper is retired).
#[cfg(target_os = "linux")]
fn assert_grandchild_dead(pidfile: &std::path::Path) {
    let pid: i32 = std::fs::read_to_string(pidfile)
        .expect("tool recorded its grandchild")
        .trim()
        .parse()
        .expect("pidfile holds a pid");
    let cmdline = format!("/proc/{pid}/cmdline");
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let sleeper = std::fs::read(&cmdline)
            .map(|bytes| bytes.starts_with(b"sleep"))
            .unwrap_or(false);
        if !sleeper {
            return;
        }
        assert!(
            Instant::now() < end,
            "grandchild {pid} survived tool-tree retirement"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// S98-round6: boot clock ticks (clock ticks since boot) at this
/// instant: `CLOCK_MONOTONIC` seconds x HZ plus the sub-second
/// ticks. `/proc` starttimes live in this domain; comparing against
/// it keeps the hang sweep inside this test's window.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn boot_ticks_now() -> Option<u64> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime with a valid out-pointer.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
        return None;
    }
    // SAFETY: sysconf with a valid name.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz <= 0 {
        return None;
    }
    let hz = hz as u64;
    Some(now.tv_sec as u64 * hz + (now.tv_nsec as u64 * hz) / 1_000_000_000)
}

/// S112-round8: parent pid of a live task (field 4 of
/// `/proc/PID/stat`). `None` when unreadable/gone — unproven, and
/// the sweep spares unproven tasks.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn proc_ppid(pid: i32) -> Option<i32> {
    let row = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = row.rsplit_once(") ")?.1;
    after_comm.split_whitespace().nth(1)?.parse().ok()
}

/// IR-002: /proc state letter of `pid` (None when
/// unreadable/gone). A tick check cannot tell live from
/// zombie — the liveness verdict needs the state.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn task_state(pid: i32) -> Option<char> {
    let row = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = row.rsplit_once(") ")?.1;
    after_comm.split_whitespace().next()?.chars().next()
}

/// S112-round8: true when `pid` descends from `ancestor` (the test
/// process) through live parent links. Any unreadable link, a
/// cycle-guard trip, or reaching init first answers false —
/// custody unproven means SPARED, never swept.
/// R11-004: each hop starttime-binds its parent and the next
/// hop re-verifies the binding, so a number recycled between
/// hops (or mid-hop) spares instead of following a
/// replacement into a forged descent.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn is_test_descendant(pid: i32, ancestor: u32) -> bool {
    is_test_descendant_with_hook(pid, ancestor, None, None)
}

/// R11-004: seam for the intermediate-replacement regression:
/// `bind_hook`, when set, runs after each intermediate parent
/// is starttime-bound and before the walk advances past it,
/// receiving that number — the regression kills+reaps+replaces
/// the bound parent there. Production callers use
/// [`is_test_descendant`].
/// R12-002: `check_hook`, when set, runs after the binding
/// decision with the cursor sample fixed — the regression
/// replaces the checked intermediate there (between the old
/// check-read and sample-read; the single sample closes the
/// gap, and the sandwich refuses the replacement).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn is_test_descendant_with_hook(
    pid: i32,
    ancestor: u32,
    bind_hook: Option<&dyn Fn(i32)>,
    check_hook: Option<&dyn Fn(i32)>,
) -> bool {
    let ancestor = ancestor as i32;
    let mut cursor = pid;
    // Starttime bound by the previous hop for the CURRENT
    // holder: None on the first hop (the target's identity is
    // the caller's — pinned plus argv plus window plus
    // re-verified before the signal).
    let mut bound: Option<u64> = None;
    for _ in 0..64 {
        if cursor == ancestor {
            return true;
        }
        if cursor <= 1 {
            return false;
        }
        // R12-002: ONE sample serves both the previous-hop
        // binding check and the sandwich's cursor_before — a
        // replacement between a check-read and a separate
        // sample-read validated the replacement's stable life
        // without ever comparing it to the bound (false
        // descent authorizing destruction). No gap remains by
        // construction: a changed holder (number recycled
        // between hops) is unproven, spared.
        let cursor_before = match task_starttime_checked(cursor) {
            Ok(Some(started)) => started,
            _ => return false,
        };
        if let Some(want) = bound {
            if cursor_before != want {
                return false;
            }
        }
        // R12-002 seam: fires after the binding decision with
        // the sampled starttime already fixed — a replacement
        // here meets the sandwich (cursor_after mismatch),
        // never a second uncompared sample. Fires only where
        // a check ran (bound is Some).
        if bound.is_some() {
            if let Some(hook) = check_hook {
                hook(cursor);
            }
        }
        // Bind this hop: cursor starttime, ppid, parent
        // starttime, ppid again, cursor starttime again. A
        // stable cursor (S100: equal starttimes name one task)
        // with a stable ppid proves the parent lived throughout
        // (a dead parent reparents a live cursor) — so the
        // mid-pair parent starttime is the parent's own, and a
        // recycle anywhere in the pair spares instead of
        // following a replacement.
        let ppid_first = match proc_ppid(cursor) {
            Some(ppid) if ppid > 0 => ppid,
            _ => return false,
        };
        let parent_started = match task_starttime_checked(ppid_first) {
            Ok(Some(started)) => started,
            _ => return false,
        };
        let ppid_second = match proc_ppid(cursor) {
            Some(ppid) if ppid > 0 => ppid,
            _ => return false,
        };
        match task_starttime_checked(cursor) {
            Ok(Some(now)) if now == cursor_before => {}
            _ => return false,
        }
        if ppid_first != ppid_second {
            return false;
        }
        if let Some(hook) = bind_hook {
            hook(ppid_first);
        }
        bound = Some(parent_started);
        cursor = ppid_first;
    }
    false
}

/// S98-round6: sweep OUR OWN descendant tasks whose argv EXACTLY
/// matches one of `patterns` and whose starttime is at or after
/// this test's start tick, SIGKILLing each through a held pidfd.
/// Only the hang guards call this: a hung driver never prints
/// `survivors=`, so its orphaned tool would otherwise leak.
/// S112-round8: the round-6 global scan is gone. Custody is
/// ancestry — a task outside our own tree (an unrelated same-argv
/// task, a concurrent suite's tree) is NEVER touched — and
/// precision is the pidfd: an exit+recycle between scan and signal
/// addresses the dead original (ESRCH), never a replacement.
/// S128-round9: the pin opens BEFORE any custody evidence (argv,
/// starttime, ancestry are all read after it) and the starttime is
/// re-verified before the signal — a late open after a recycle
/// would pin the replacement while the evidence described the
/// original. Exact-argv plus time-window plus per-test-unique
/// durations (distinct sleeps; `/bin/sleep` and PATH-`sleep` differ
/// in argv[0]) select WHICH descendants. Returns the signaled pids
/// for the failure log. Strays already reparented to init are
/// outside custody: spared (loudly) and leaked — a leak beats a
/// kill. When the start tick is unknown the sweep fires nothing.
/// S128-round9: production callers use this; the acquisition-order
/// regression uses [`hang_sweep_with_hooks`].
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn hang_sweep(patterns: &[(&str, &[&str])], start_tick: Option<u64>) -> Vec<u32> {
    hang_sweep_with_hooks(patterns, start_tick, &pidfd_open_task, None)
}

/// S128-round9: seam for the acquisition-order regression: `open`
/// pins a candidate (production: [`pidfd_open_task`]) and
/// `window_hook` runs after identity re-verification and before the
/// signal (the [`kill_survivors_with_hook`] pattern). Production
/// callers use [`hang_sweep`].
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn hang_sweep_with_hooks(
    patterns: &[(&str, &[&str])],
    start_tick: Option<u64>,
    open: &dyn Fn(i32) -> Option<i32>,
    window_hook: Option<&dyn Fn(i32)>,
) -> Vec<u32> {
    let Some(start_tick) = start_tick else {
        eprintln!("hang sweep skipped: no start tick");
        return Vec::new();
    };
    let me = std::process::id();
    let mut killed = Vec::new();
    let entries = std::fs::read_dir("/proc").into_iter().flatten().flatten();
    for entry in entries {
        let name = entry.file_name();
        let pid: i32 = match name.to_string_lossy().parse() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        if pid as u32 == me {
            continue;
        }
        // S128-round9: PIN FIRST — the pin names whoever holds the
        // number at open time, and every custody check below runs
        // AFTER it. A recycle anywhere in the sequence is safe: a
        // changed holder fails the evidence or the re-verification
        // (spared — the pinned original is retired), and a dead
        // pinned task answers ESRCH (nobody signaled). The signal
        // can only ever address the pinned task.
        let pin = match open(pid) {
            Some(pin) => SweepPin(pin),
            None => match task_starttime_checked(pid) {
                // Raced exit between the directory scan and the
                // open: quiet (the common short-lived-task case).
                Ok(None) => continue,
                Ok(Some(_)) => {
                    eprintln!("hang sweep cannot pin live task {pid}; leaking");
                    continue;
                }
                Err(error) => {
                    eprintln!("hang sweep spares {pid}: {error}");
                    continue;
                }
            },
        };
        if sweep_candidate(pid, me, patterns, start_tick, pin, window_hook) {
            killed.push(pid as u32);
        }
    }
    killed
}

/// S128-round9: owns a sweep pin across one candidate; closes on
/// drop so every spare path releases it.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct SweepPin(i32);

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl Drop for SweepPin {
    fn drop(&mut self) {
        // SAFETY: fd owned by this guard.
        unsafe { libc::close(self.0) };
    }
}

/// S128-round9: examine one sweep candidate through a HELD pin: the
/// pin is acquired BEFORE any custody evidence, the evidence (exact
/// argv, window starttime, descendant ancestry) is gathered after,
/// the starttime is re-verified immediately before the signal, and
/// the signal goes through the pin. Returns true when the signal
/// was issued (ESRCH counts: the pinned task died in the window —
/// nobody else was addressed). Any mismatch spares WITHOUT
/// signaling. The guard closes the pin on every path.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn sweep_candidate(
    pid: i32,
    me: u32,
    patterns: &[(&str, &[&str])],
    start_tick: u64,
    pin: SweepPin,
    window_hook: Option<&dyn Fn(i32)>,
) -> bool {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    if cmdline.is_empty() {
        return false;
    }
    let argv: Vec<&str> = cmdline
        .split(|byte| *byte == 0)
        .filter(|word| !word.is_empty())
        .filter_map(|word| std::str::from_utf8(word).ok())
        .collect();
    let matched = patterns
        .iter()
        .any(|(head, tail)| argv.first() == Some(head) && argv.get(1..) == Some(*tail));
    if !matched {
        return false;
    }
    // `>=`: starttimes tick at 10ms, so a tool spawned within
    // the same tick as the capture is still ours.
    let started = match task_starttime_checked(pid) {
        Ok(Some(started)) if started >= start_tick => started,
        Ok(_) => return false,
        Err(error) => {
            eprintln!("hang sweep spares {pid}: {error}");
            return false;
        }
    };
    // Descendant custody: spare anything outside our own tree.
    if !is_test_descendant(pid, me) {
        eprintln!("hang sweep spares non-descendant {pid} (argv match, outside custody)");
        return false;
    }
    // Re-verify the CURRENT holder is the task the evidence
    // described: a recycle between the evidence and the signal must
    // spare (the pinned original is then retired), never record a
    // kill against a dead pin.
    match task_starttime_checked(pid) {
        Ok(Some(now)) if now == started => {}
        Ok(_) => return false,
        Err(error) => {
            eprintln!("hang sweep spares {pid}: re-verify {error}");
            return false;
        }
    }
    if let Some(hook) = window_hook {
        hook(pid);
    }
    // Signal THROUGH the pin: exit+recycle after re-verification
    // addresses the dead original (ESRCH — quietly retired), never
    // whoever holds the number now.
    let errno = pidfd_signal_task(pin.0, libc::SIGKILL);
    if errno != 0 && errno != libc::ESRCH {
        eprintln!("hang sweep signal of {pid} refused: errno {errno}");
        return false;
    }
    if !poll_pin_retired(pin.0) {
        eprintln!("hang sweep cannot prove {pid} retired (kill was signaled)");
    }
    true
}

/// S85/S86-round5: run the invoke-denial driver with mode flags,
/// returning its output, wall elapsed, and scratch dir (the caller
/// removes the dir last, so failures keep their evidence — the S67
/// test's convention). The hang guard matches S67's: 30s, then the
/// driver is killed and the test fails.
/// S98-round6: `extra_sweep` adds known-descendant argv patterns
/// (grandchildren the tool spawns under a different argv) to the
/// hang-guard sweep; the tool's own argv is always swept.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn run_denial_driver(
    tag: &str,
    tool: &std::path::Path,
    timeout_ms: u64,
    mode_flags: &[&str],
    tool_args: &[&str],
    extra_sweep: &[(&str, &[&str])],
) -> (std::process::Output, Duration, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "tc02-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let closure_path = dir.join("closure.json");
    std::fs::write(&closure_path, valid_closure()).unwrap();
    let driver = PathBuf::from(env!("CARGO_BIN_EXE_scopebase-tc02-invoke-denial"));
    let mut command = std::process::Command::new(&driver);
    command
        .arg("--tool")
        .arg(tool)
        .arg("--closure")
        .arg(&closure_path)
        .arg("--timeout")
        .arg(timeout_ms.to_string());
    for flag in mode_flags {
        command.arg(flag);
    }
    command.arg("--");
    for arg in tool_args {
        command.arg(arg);
    }
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("denial driver spawns");
    let start = Instant::now();
    // S98-round6: tick floor for the hang sweep, captured before
    // the driver spawns anything.
    let start_tick = boot_ticks_now();
    let deadline = start + Duration::from_secs(30);
    loop {
        match child.try_wait().expect("try_wait runs") {
            Some(_) => break,
            None => {
                if Instant::now() >= deadline {
                    // S112-round8: sweep BEFORE killing the driver:
                    // descendant custody needs the live chain
                    // (test → driver → tool); killing first would
                    // orphan the tool to init, outside custody. The
                    // hung driver never reported survivors, so its
                    // tool (own argv plus known descendants) is swept
                    // before failing, or the stray outlives the run.
                    let tool_head = tool.to_string_lossy().into_owned();
                    let mut patterns: Vec<(&str, &[&str])> = vec![(tool_head.as_str(), tool_args)];
                    patterns.extend_from_slice(extra_sweep);
                    let swept = hang_sweep(&patterns, start_tick);
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("denial driver hung ({tag} regression; swept {swept:?})");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
    let output = child.wait_with_output().expect("output collected");
    (output, start.elapsed(), dir)
}

/// S123-round8: starttime of a live task (field 22 of
/// `/proc/PID/stat`). `Ok(None)` ONLY when the task is proven gone
/// (the stat row is absent: ENOENT). Any other failure —
/// descriptor exhaustion, permission, an unparseable row — is
/// `Err` (UNRESOLVED): the caller must treat the task as neither
/// live nor retired. (The old helper mapped every failure to
/// None, which cleanup read as "already gone".)
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn task_starttime_checked(pid: i32) -> Result<Option<u64>, String> {
    let row = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(row) => row,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("task {pid} stat unreadable: {error}")),
    };
    // Fields 1 (pid) and 2 (comm) consumed with the parens;
    // starttime is field 22, index 19 of the remainder.
    let parsed: Option<u64> = (|| {
        let after_comm = row.rsplit_once(") ")?.1;
        after_comm.split_whitespace().nth(19)?.parse().ok()
    })();
    match parsed {
        Some(starttime) => Ok(Some(starttime)),
        None => Err(format!("task {pid} stat unparseable")),
    }
}

/// S123-round8: retirement is proven ONLY by disappearance
/// (ENOENT) or a zombie state (dead-but-unreaped). Unreadable or
/// unparseable rows are `Err` (UNRESOLVED) — never retired. (The
/// old helper retired every read failure.)
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn task_retired_checked(pid: i32) -> Result<bool, String> {
    let row = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(row) => row,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(format!("task {pid} stat unreadable: {error}")),
    };
    let state = (|| {
        row.rsplit_once(") ")
            .and_then(|(_, after)| after.split_whitespace().next())
    })();
    match state {
        Some("Z") => Ok(true),
        Some(_) => Ok(false),
        None => Err(format!("task {pid} stat unparseable")),
    }
}

/// S115-round8: survivor cleanup without a window hook.
/// Production callers use this; the exit-during-window regression
/// uses [`kill_survivors_with_hook`].
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn kill_survivors(stdout: &str) {
    kill_survivors_with_hook(stdout, None);
}

/// S98-round6: SIGKILL every survivor the driver reports — but only
/// after re-verifying its pinned (pid, starttime) identity. A
/// sleeper that died and whose number was recycled between the
/// driver's report and this cleanup must NOT kill its replacement:
/// entries that no longer match (gone, or a different task under
/// the number) are skipped, because the pinned original is then
/// definitionally retired.
/// S115-round8: PIN FIRST, then verify, then signal through the
/// pin — never a numeric kill on a non-child. The pin names the
/// task behind the number at open time; the re-read verification
/// observes the CURRENT number holder. Exit+recycle anywhere in
/// this sequence is safe: a changed holder fails verification
/// (skipped — the original is retired), and a dead pinned task
/// answers ESRCH (nobody signaled). The signal can only ever
/// address the pinned task. Residual: sub-tick exit+recycle BEFORE
/// the open (a replacement born in the original's birth tick)
/// would verify spuriously — but a reported survivor lived whole
/// seconds (observed, reported, driver exited), so its birth tick
/// is long past. Unpinnable-but-live tasks refuse LOUD instead of
/// falling back to a numeric signal.
/// `hook` (test-only) runs after identity verification and before
/// the signal, so the regression can deterministically retire the
/// victim inside the race window.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn kill_survivors_with_hook(stdout: &str, hook: Option<&dyn Fn(i32, u64)>) {
    let field = stdout
        .split_whitespace()
        .find_map(|word| word.strip_prefix("survivors="))
        .expect("driver reports survivors=");
    assert!(!field.is_empty(), "expected survivors, got: {stdout}");
    for entry in field.split(',') {
        let (pid_text, start_text) = entry.split_once(':').expect("survivor pins pid:starttime");
        let pid: i32 = pid_text.parse().expect("survivor pid parses");
        let pinned: u64 = start_text.parse().expect("survivor starttime parses");
        let pin = match pidfd_open_task(pid) {
            Some(pin) => pin,
            None => match task_starttime_checked(pid) {
                Err(error) => panic!("survivor {pid} observation unresolved: {error}"),
                Ok(None) => continue,
                Ok(Some(now)) if now != pinned => continue,
                Ok(Some(_)) => panic!("survivor {pid} live but unpinnable (unresolved)"),
            },
        };
        // Verify the CURRENT holder is the reported task. A
        // changed holder (or none) means the original is retired —
        // close the pin and skip WITHOUT signaling.
        let current = match task_starttime_checked(pid) {
            Err(error) => {
                // SAFETY: pin owned by this scope.
                unsafe { libc::close(pin) };
                panic!("survivor {pid} observation unresolved: {error}");
            }
            Ok(current) => current,
        };
        if current != Some(pinned) {
            // SAFETY: pin owned by this scope.
            unsafe { libc::close(pin) };
            if let Some(now) = current {
                // A different task owns the number now: the pinned
                // original is retired. The replacement is none of
                // this test's business.
                eprintln!("survivor {pid}: pinned starttime {pinned} replaced by {now}; skipped");
            }
            continue;
        }
        if let Some(hook) = hook {
            hook(pid, pinned);
        }
        // Signal THROUGH the pin: exit+recycle after verification
        // addresses the dead original (ESRCH — quietly retired),
        // never whoever holds the number now.
        let errno = pidfd_signal_task(pin, libc::SIGKILL);
        if errno != 0 && errno != libc::ESRCH {
            // SAFETY: pin owned by this scope.
            unsafe { libc::close(pin) };
            panic!("survivor {pid} signal refused: errno {errno}");
        }
        let retired = poll_pin_retired(pin);
        // SAFETY: pin owned by this scope.
        unsafe { libc::close(pin) };
        assert!(retired, "survivor {pid} resisted SIGKILL");
    }
}

/// S98-round6 negative: a survivor entry pinning the WRONG starttime
/// for a live task must not signal it. Deterministic: no pid
/// recycling is raced; the mismatch itself is the fixture. Neuter
/// check: deleting the starttime comparison kills the victim and
/// fails this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn survivor_cleanup_skips_starttime_mismatch() {
    let mut victim = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("victim spawns");
    let pid = victim.id() as i32;
    let live = task_starttime_checked(pid)
        .expect("victim stat readable")
        .expect("victim visible");
    kill_survivors(&format!(
        "verdict=err survivors={pid}:{} children_after=1",
        live + 1
    ));
    // Aliveness, not just identity: a killed-but-unreaped victim
    // keeps its starttime as a zombie, so identity alone would pass
    // a neutered (comparison-deleted) verifier.
    assert_eq!(
        task_starttime_checked(pid),
        Ok(Some(live)),
        "mismatched survivor keeps its identity"
    );
    assert_eq!(
        task_retired_checked(pid),
        Ok(false),
        "mismatched survivor must survive cleanup"
    );
    // SAFETY: retiring our own verified victim.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let _ = victim.wait();
}

/// S98-round6: the hang sweep retires an argv- and window-matched
/// stray and spares everything else (wrong argv, or older than the
/// window). Deterministic and fast: no driver hang involved.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn hang_sweep_retires_window_matched_stray() {
    let start_tick = boot_ticks_now().expect("tick reads");
    let mut stray = std::process::Command::new("/bin/sleep")
        .arg("997")
        .spawn()
        .expect("stray spawns");
    let pid = stray.id();
    let stray_tick = task_starttime_checked(pid as i32)
        .expect("stray stat readable")
        .expect("stray visible");
    let swept = hang_sweep(&[("/bin/sleep", &["997"])], Some(start_tick));
    assert_eq!(swept, vec![pid], "window-matched stray is swept");
    assert_eq!(
        task_retired_checked(pid as i32),
        Ok(true),
        "swept stray is retired"
    );
    // R12-003: the sweep reaped the stray — reap only while the
    // number still names it (never a recycled holder's status).
    wait_child_unless_reaped(&mut stray, pid as i32, stray_tick);
    // An older-than-window floor spares even an exact-argv task.
    let mut keeper = std::process::Command::new("/bin/sleep")
        .arg("998")
        .spawn()
        .expect("keeper spawns");
    let keeper_pid = keeper.id() as i32;
    assert!(
        matches!(task_starttime_checked(keeper_pid), Ok(Some(_))),
        "keeper visible"
    );
    let future_tick = task_starttime_checked(keeper_pid)
        .expect("keeper stat readable")
        .map(|started| started + 10_000);
    let swept = hang_sweep(&[("/bin/sleep", &["998"])], future_tick);
    assert!(swept.is_empty(), "predated task is spared, got: {swept:?}");
    assert_eq!(
        task_retired_checked(keeper_pid),
        Ok(false),
        "spared task survives"
    );
    // SAFETY: retiring our own keeper.
    unsafe {
        libc::kill(keeper_pid, libc::SIGKILL);
    }
    let _ = keeper.wait();
}

/// S98-round6 positive: a survivor entry pinning the CORRECT
/// identity is retired — the verifier still kills what it should.
/// S123-round8: the assertions use the strict observers, so this
/// control cannot pass through the false-success path (an
/// unreadable row is Err, never retired).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn survivor_cleanup_retires_verified_identity() {
    let mut sleeper = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("sleeper spawns");
    let pid = sleeper.id() as i32;
    let live = task_starttime_checked(pid)
        .expect("sleeper stat readable")
        .expect("sleeper visible");
    kill_survivors(&format!(
        "verdict=err survivors={pid}:{live} children_after=1"
    ));
    assert_eq!(
        task_retired_checked(pid),
        Ok(true),
        "verified survivor must be retired"
    );
    // R12-003: cleanup reaped the sleeper — reap only while the
    // number still names it (never a recycled holder's status).
    wait_child_unless_reaped(&mut sleeper, pid, live);
}

/// R12-003 (steal direction): `hang_sweep` reaps the stray
/// through `poll_pin_retired`'s P_PIDFD waitid; a stale numeric
/// wait would reap whoever holds the number now — here a killed
/// replacement at a DIFFERENT birth tick — stealing the
/// replacement owner's status. The gated wait skips (the number
/// no longer names the stray) and the owner reaps its own
/// zombie. Pre-fix the owner's wait fails ECHILD (RED).
/// Duration 887 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn stale_child_wait_after_sweep_steals_nothing() {
    // R12-002: serialize steerers (whole-test hold).
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let last_path = "/proc/sys/kernel/ns_last_pid";
    let last_before = match std::fs::read_to_string(last_path) {
        Ok(text) => text.trim().to_string(),
        Err(_) => {
            eprintln!("skip: ns_last_pid unreadable (no reuse control)");
            return;
        }
    };
    if !locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
        eprintln!("skip: ns_last_pid unwritable (no reuse control)");
        return;
    }
    let start_tick = boot_ticks_now().expect("tick reads");
    let mut stray = std::process::Command::new("/bin/sleep")
        .arg("887")
        .spawn()
        .expect("stray spawns");
    let stray_pid = stray.id() as i32;
    let stray_tick = task_starttime_checked(stray_pid)
        .expect("stray stat readable")
        .expect("stray visible");
    let swept = hang_sweep(&[("/bin/sleep", &["887"])], Some(start_tick));
    assert_eq!(swept, vec![stray_pid as u32], "stray swept");
    assert_eq!(task_retired_checked(stray_pid), Ok(true), "stray retired");
    // Controlled reuse: land a replacement on the stray's
    // number at a DIFFERENT birth tick (same-tick is the
    // exotic accepted residual, not this finding).
    let mut replacement = None;
    // R12-005: cross-process placement lock (lib tests steer
    // concurrently in another process).
    let _nsflock = ns_last_pid_flock();
    for _ in 0..100 {
        if !steer_next_pid_unlocked(stray_pid) {
            break;
        }
        let mut cand = std::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("replacement spawns");
        if cand.id() as i32 != stray_pid {
            let _ = cand.kill();
            let _ = cand.wait();
            continue;
        }
        let placed_different = match task_starttime_checked(stray_pid) {
            Ok(Some(tick)) => tick != stray_tick,
            _ => false,
        };
        if !placed_different {
            let _ = cand.kill();
            let _ = cand.wait();
            continue;
        }
        replacement = Some(cand);
        break;
    }
    // R13-009: placement done — release the cross-process lock
    // BEFORE any locked_* call below (same-process POSIX locks
    // merge: a nested locked_* drop would release this guard).
    drop(_nsflock);
    let mut replacement = replacement.expect("replacement placed on stray's number");
    // Kill the replacement: it becomes a zombie holding the
    // number (nothing reaps it before the stale wait — the
    // owner handle below is its only waiter).
    // SAFETY: retiring our own replacement.
    unsafe {
        libc::kill(stray_pid, libc::SIGKILL);
    }
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if task_retired_checked(stray_pid) == Ok(true) {
            break;
        }
        assert!(Instant::now() < end, "replacement never zombied");
        std::thread::sleep(Duration::from_millis(10));
    }
    // R12-003: the gated wait skips (the number holds a
    // replacement, not the stray) instead of stealing status.
    wait_child_unless_reaped(&mut stray, stray_pid, stray_tick);
    // The replacement owner's status must survive the stale wait.
    let status = replacement
        .wait()
        .expect("replacement owner reaps its own zombie");
    assert!(!status.success(), "killed replacement reports signal death");
    locked_restore_hint(&last_before);
}

/// R12-003 (block direction): a stale numeric wait after a
/// sweep would block on a LIVE replacement's whole lifetime.
/// The gated wait skips at once (starttime mismatch) and the
/// replacement survives for its owner to retire. Pre-fix a
/// detached waiter never returns promptly (RED). Duration 888
/// is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn stale_child_wait_after_sweep_blocks_on_nothing() {
    // R12-002: serialize steerers (whole-test hold).
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let last_path = "/proc/sys/kernel/ns_last_pid";
    let last_before = match std::fs::read_to_string(last_path) {
        Ok(text) => text.trim().to_string(),
        Err(_) => {
            eprintln!("skip: ns_last_pid unreadable (no reuse control)");
            return;
        }
    };
    if !locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
        eprintln!("skip: ns_last_pid unwritable (no reuse control)");
        return;
    }
    let start_tick = boot_ticks_now().expect("tick reads");
    let mut stray = std::process::Command::new("/bin/sleep")
        .arg("888")
        .spawn()
        .expect("stray spawns");
    let stray_pid = stray.id() as i32;
    let stray_tick = task_starttime_checked(stray_pid)
        .expect("stray stat readable")
        .expect("stray visible");
    let swept = hang_sweep(&[("/bin/sleep", &["888"])], Some(start_tick));
    assert_eq!(swept, vec![stray_pid as u32], "stray swept");
    assert_eq!(task_retired_checked(stray_pid), Ok(true), "stray retired");
    // Controlled reuse: a LIVE replacement on the stray's
    // number at a DIFFERENT birth tick.
    let mut replacement = None;
    // R12-005: cross-process placement lock (lib tests steer
    // concurrently in another process).
    let _nsflock = ns_last_pid_flock();
    for _ in 0..100 {
        if !steer_next_pid_unlocked(stray_pid) {
            break;
        }
        let mut cand = std::process::Command::new("/bin/sleep")
            .arg("6")
            .spawn()
            .expect("replacement spawns");
        if cand.id() as i32 != stray_pid {
            let _ = cand.kill();
            let _ = cand.wait();
            continue;
        }
        let placed_different = match task_starttime_checked(stray_pid) {
            Ok(Some(tick)) => tick != stray_tick,
            _ => false,
        };
        if !placed_different {
            let _ = cand.kill();
            let _ = cand.wait();
            continue;
        }
        replacement = Some(cand);
        break;
    }
    // R13-009: placement done — release the cross-process lock
    // BEFORE any locked_* call below (same-process POSIX locks
    // merge: a nested locked_* drop would release this guard).
    drop(_nsflock);
    let mut replacement = replacement.expect("replacement placed on stray's number");
    // R12-003: the gated wait skips at once (the live holder is
    // a replacement, not the stray) instead of blocking on its
    // lifetime.
    let start = Instant::now();
    wait_child_unless_reaped(&mut stray, stray_pid, stray_tick);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "gated wait must skip at once, not block on the replacement"
    );
    assert_eq!(
        task_retired_checked(stray_pid),
        Ok(false),
        "live replacement survives the stale wait"
    );
    // Owner retires its live replacement.
    // SAFETY: retiring our own replacement.
    unsafe {
        libc::kill(stray_pid, libc::SIGKILL);
    }
    let _ = replacement.wait();
    locked_restore_hint(&last_before);
}

/// S112/S115-round8: pin any live same-UID task (child or not).
/// The fd names the task, never the number: an exit+recycle
/// between open and signal addresses the dead original (ESRCH),
/// never a replacement. `None` when the task is already gone or
/// the kernel cannot pin it.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn pidfd_open_task(pid: i32) -> Option<i32> {
    scopebase_testkit::fixture::linux::seccomp::pidfd_open_raw(pid).ok()
}

/// S112/S115-round8: poll a pin-signaled task to retirement:
/// reaped-if-ours (a zombie owned child still answers the pin) or
/// pin-ESRCH (dead and reaped by its owner). Never the /proc
/// number: a recycled number would poll a stranger. Bounded (5s).
/// S129-round9: the reap runs through `waitid(P_PIDFD, …)` — the pin
/// names OUR task even when the number was recycled as a sibling
/// thread's child (a numeric `waitpid` would steal that
/// replacement's status: children are process-wide in the test
/// binary). The numeric pid is no longer even a parameter. A
/// non-child answers ECHILD — not retired, just not ours to reap —
/// and retirement is then proven by the pin-ESRCH probe alone. The
/// waitid return needs no status decode: its only job is reaping
/// our own zombie; ESRCH proves the reap.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn poll_pin_retired(pin: i32) -> bool {
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        // SAFETY: waitid with a null siginfo reaps the PINNED task
        // when it is our exited child, ECHILD otherwise (non-child
        // or already reaped; EINVAL on a kernel predating P_PIDFD —
        // then the ESRCH probe below still proves retirement for
        // non-children, while an owned zombie on such a kernel
        // stays unproven to the bound rather than risking a
        // numeric reap).
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                pin as libc::id_t,
                std::ptr::null_mut(),
                libc::WEXITED | libc::WNOHANG,
            )
        };
        if pidfd_signal_task(pin, 0) == libc::ESRCH {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// R12-003: reap a `Child` ONLY while its number still names the
/// expected task. A sweep or hook may have reaped our task
/// already (`poll_pin_retired`'s P_PIDFD waitid, hook waitpids);
/// a blind numeric wait then steals a recycled number-holder's
/// status or blocks on its lifetime. A zombie keeps its
/// starttime, so a match means ours (live or zombie): bounded
/// try_wait poll (a zombie reaps at once; a signaled task dies
/// in ms — never block past the bound on an impostor). A
/// mismatch, a freed number, or an unresolvable stat all skip
/// WITHOUT waiting (spare, don't hazard — an unresolvable stat
/// may strand our zombie to process exit; loud, bounded).
/// Residual: a same-tick recycled zombie at poll time is still
/// reaped as ours (exotic: reap + same-tick recycle +
/// zombie-at-poll; S100-class).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn wait_child_unless_reaped(child: &mut std::process::Child, pid: i32, expected: u64) {
    match task_starttime_checked(pid) {
        Ok(Some(now)) if now == expected => {}
        Ok(_) => return,
        Err(error) => {
            eprintln!("wait skips unresolved task {pid}: {error}");
            return;
        }
    }
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(_) => return, // reaped between the check and the poll
        }
        if Instant::now() >= end {
            eprintln!("wait gives up on live task {pid} past 5s (impostor?)");
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// S112/S115-round8: signal through a held pin; returns the raw
/// errno (0 on success, ESRCH when OUR task is already reaped).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn pidfd_signal_task(fd: i32, sig: i32) -> i32 {
    // SAFETY: pidfd_send_signal(pidfd, sig, NULL, 0).
    let sent = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd as libc::c_long,
            sig as libc::c_long,
            0 as libc::c_long,
            0 as libc::c_long,
        )
    };
    if sent == 0 {
        0
    } else {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }
}

/// S138-round9: a pipe whose ends close on exec, so concurrently
/// spawned commands never inherit the fixture's report channel.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn cloexec_pipe() -> [libc::c_int; 2] {
    let mut pipe = [0; 2];
    // SAFETY: valid out-pointer for the pipe ends.
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    pipe
}

/// S112/S115-round8: spawn a sleeper that is NOT our descendant:
/// the middle child reports the grandchild pid through a pipe and
/// exits, so the sleeper reparents to init. Returns the orphan's
/// (pid, starttime) after its argv becomes `sleep <duration>`. The
/// caller retires the orphan (pin its identity first — it is a
/// non-child). Durations must stay unique across the suite's sweep
/// patterns.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn spawn_orphan_sleeper(duration: &str) -> (i32, u64) {
    spawn_orphan_sleeper_with_hook(duration, None, true)
}

/// R10-013: best-effort orphan retirement for the report-read
/// expiry path. Returns a note for the timeout panic. The middle
/// child may have reported its pid before the stall: when the
/// buffer holds a COMPLETE line (a partial line parses to a
/// wrong number) AND that number's argv still proves the expected
/// `sleep <duration>` (a recycled number must never be signaled),
/// pin it and retire it. Anything unproven is NAMED, never
/// touched.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn retire_reported_orphan(buffer: &[u8], duration: &str) -> String {
    retire_reported_orphan_with_hook(buffer, duration, None)
}

/// R11-015: seam for the swap regression — `window_hook` runs
/// after an argv match and before the starttime sample (the
/// finding's window: verification → acquisition). The hook
/// takes no arguments (the pid is known to its caller).
/// Production callers use [`retire_reported_orphan`].
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn retire_reported_orphan_with_hook(
    buffer: &[u8],
    duration: &str,
    window_hook: Option<&dyn Fn()>,
) -> String {
    if !buffer.contains(&b'\n') {
        return "orphan pid never reported".to_string();
    }
    let pid: i32 = match std::str::from_utf8(buffer)
        .ok()
        .map(str::trim)
        .and_then(|text| text.parse().ok())
    {
        Some(pid) if pid > 0 => pid,
        _ => return "orphan pid unparsable".to_string(),
    };
    let mut expected = b"sleep\0".to_vec();
    expected.extend_from_slice(duration.as_bytes());
    expected.push(0);
    match verify_reported_orphan(
        pid,
        &expected,
        &|| std::fs::read(format!("/proc/{pid}/cmdline")),
        &|| task_starttime_checked(pid),
        Duration::from_secs(5),
        window_hook,
    ) {
        Ok(pinned) => {
            retire_orphan(pid, pinned);
            format!("orphan {pid} retired")
        }
        Err(note) => note,
    }
}

/// R11-015: pair the argv match with its starttime sample — one
/// paired observation, never a sample after an unverified gap.
/// Only a life proven CONTINUOUS across starttime→argv→starttime
/// with matching argv verifies; Ok(pinned) authorizes the kill
/// (the caller re-verifies at signal time through
/// [`retire_orphan`]); every other outcome is a NAMED verdict
/// (Err — never touched). The kill binds to the FIRST
/// argv-verified life (locked starttime): post-lock, any holder
/// change means OUR life exited — whoever holds the number now
/// (matching argv or not) is definitionally not ours. Readers
/// are injected (production reads /proc; the regression scripts
/// them); `window_hook` runs after an argv match and before the
/// second sample.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn verify_reported_orphan(
    pid: i32,
    expected: &[u8],
    read_cmdline: &dyn Fn() -> std::io::Result<Vec<u8>>,
    read_starttime: &dyn Fn() -> Result<Option<u64>, String>,
    bound: std::time::Duration,
    window_hook: Option<&dyn Fn()>,
) -> Result<u64, String> {
    // Await exec-or-gone: a pre-exec task still carries the test
    // binary's argv and proves nothing yet.
    let mut locked: Option<u64> = None;
    let end = std::time::Instant::now() + bound;
    loop {
        let first = match read_starttime() {
            Ok(Some(first)) => first,
            Ok(None) => return Err(format!("orphan {pid} exited on its own")),
            Err(_) => {
                return Err(format!(
                    "orphan {pid} stat unreadable, left for manual retirement"
                ))
            }
        };
        if let Some(verified) = locked {
            if first != verified {
                return Err(format!(
                    "orphan {pid} exited on its own (verified life replaced)"
                ));
            }
        }
        match read_cmdline() {
            Err(_) => return Err(format!("orphan {pid} exited on its own")),
            Ok(cmdline) if cmdline == expected => {
                if locked.is_none() {
                    locked = Some(first);
                }
                if let Some(hook) = window_hook {
                    hook();
                }
                match read_starttime() {
                    Ok(Some(second)) if second == first => return Ok(first),
                    Ok(Some(_)) => {}
                    Ok(None) => return Err(format!("orphan {pid} exited on its own")),
                    Err(_) => {
                        return Err(format!(
                            "orphan {pid} stat unreadable, left for manual retirement"
                        ))
                    }
                }
            }
            Ok(_) => {}
        }
        if std::time::Instant::now() >= end {
            return Err(format!(
                "orphan {pid} unproven after {bound:?}, left for manual retirement"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// R11-015: scripted observation streams for the pairing
/// regression — each read pops its scripted answer (exhaustion
/// panics: the script is the test's contract). The function's
/// only window into lives is this stream — swapping the stream
/// IS swapping the observed life, exactly as the code sees it.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct OrphanScript {
    cmdlines: std::cell::RefCell<std::collections::VecDeque<std::io::Result<Vec<u8>>>>,
    starts: std::cell::RefCell<std::collections::VecDeque<Result<Option<u64>, String>>>,
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl OrphanScript {
    fn read_cmdline(&self) -> std::io::Result<Vec<u8>> {
        self.cmdlines
            .borrow_mut()
            .pop_front()
            .expect("script cmdline")
    }
    fn read_starttime(&self) -> Result<Option<u64>, String> {
        self.starts
            .borrow_mut()
            .pop_front()
            .expect("script starttime")
    }
}

/// R11-015: replacing the observed life between argv verification
/// and identity acquisition must spare the replacement (which
/// need not match argv — the finding's literal shape). The swap
/// is scripted into the observation stream (S1=A, MATCH, S2=B,
/// S1'=B); the verdict must be Replaced (Err), never Verified —
/// the kill is reachable only through Ok, so Err structurally
/// proves no signal. Pre-fix the post-match sample binds B and
/// the caller kills it (RED).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn orphan_verify_spares_swapped_unmatched() {
    let expected = b"sleep\096\0".to_vec();
    let script = OrphanScript {
        cmdlines: std::cell::RefCell::new(std::collections::VecDeque::from([Ok(expected.clone())])),
        starts: std::cell::RefCell::new(std::collections::VecDeque::from([
            Ok(Some(1000)),
            Ok(Some(2000)),
            Ok(Some(2000)),
        ])),
    };
    let verdict = verify_reported_orphan(
        4242,
        &expected,
        &|| script.read_cmdline(),
        &|| script.read_starttime(),
        std::time::Duration::from_secs(5),
        None,
    );
    let note = verdict.expect_err("swap must not verify");
    assert!(
        note.contains("replaced"),
        "verdict must name the swap, got: {note}"
    );
}

/// R11-015: a SAME-ARGV replacement survives the swap — this
/// pins the first-verified lock. The trailing MATCH is never
/// read post-lock (the S1'-vs-lock check returns first); it
/// exists to fail the lockless pairing shape, which would
/// re-verify B on the next iteration and return Ok (kill).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn orphan_verify_spares_swapped_same_argv() {
    let expected = b"sleep\096\0".to_vec();
    let script = OrphanScript {
        cmdlines: std::cell::RefCell::new(std::collections::VecDeque::from([
            Ok(expected.clone()),
            Ok(expected.clone()),
        ])),
        starts: std::cell::RefCell::new(std::collections::VecDeque::from([
            Ok(Some(1000)),
            Ok(Some(2000)),
            Ok(Some(2000)),
            Ok(Some(2000)),
        ])),
    };
    let verdict = verify_reported_orphan(
        4242,
        &expected,
        &|| script.read_cmdline(),
        &|| script.read_starttime(),
        std::time::Duration::from_secs(5),
        None,
    );
    let note = verdict.expect_err("same-argv swap must not verify");
    assert!(
        note.contains("replaced"),
        "verdict must name the swap, got: {note}"
    );
}

/// R11-015: an argv that never matches stays unproven past the
/// bound (the preserved arm — nothing verified, nothing
/// touched). The bound is a parameter so the test pays 50ms,
/// not the production 5s.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn orphan_verify_unproven_after_bound() {
    let expected = b"sleep\096\0".to_vec();
    let other = b"sleep\097\0".to_vec();
    let script = OrphanScript {
        cmdlines: std::cell::RefCell::new((0..40).map(|_| Ok(other.clone())).collect()),
        starts: std::cell::RefCell::new((0..40).map(|_| Ok(Some(1000))).collect()),
    };
    let verdict = verify_reported_orphan(
        4242,
        &expected,
        &|| script.read_cmdline(),
        &|| script.read_starttime(),
        std::time::Duration::from_millis(50),
        None,
    );
    let note = verdict.expect_err("silence must not verify");
    assert!(
        note.contains("unproven"),
        "verdict must stay unproven, got: {note}"
    );
}

/// R11-015: the window-hook seam fires with real pids and the
/// verdict plumbing holds end to end. A (sleep 96, our child)
/// verifies by argv; the hook retires A through pinned
/// authority and reaps it (no steering: true pid reuse needs
/// ns_last_pid, which refuses writes here despite world-writable
/// mode bits — EPERM); the number is then empty, so the
/// verdict is Exited (or Replaced under freak suite-noise
/// recycling — both contain "exited on its own"). An unrelated
/// sleeper B' (different number) proves no indiscriminate
/// signal. The swap itself is pinned scripted above.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn orphan_hook_fires_and_spares_unrelated() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let unrelated = std::process::Command::new("sleep")
        .arg("97")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn unrelated");
    let other = unrelated.id() as i32;
    let a = std::process::Command::new("sleep")
        .arg("96")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn A");
    let number = a.id() as i32;
    let a_start = task_starttime_checked(number)
        .expect("A stat readable")
        .expect("A alive");
    let fired = AtomicUsize::new(0);
    let buffer = format!("{number}\n");
    let note = retire_reported_orphan_with_hook(
        buffer.as_bytes(),
        "96",
        Some(&|| {
            fired.fetch_add(1, Ordering::SeqCst);
            retire_orphan(number, a_start);
            let mut status = 0;
            // SAFETY: our own child, dead by SIGKILL — the
            // blocking reap cannot hang.
            let got = unsafe { libc::waitpid(number, &mut status, 0) };
            assert_eq!(got, number, "hook must reap A");
        }),
    );
    // The handle is stale (A reaped inside the hook — wait()
    // would ECHILD); dropping reaps nothing twice.
    drop(a);
    assert!(
        note.contains("exited on its own"),
        "verdict must report the exit, got: {note}"
    );
    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "hook must fire exactly once"
    );
    // B' untouched (different number, never addressed).
    let cmdline = std::fs::read(format!("/proc/{other}/cmdline")).expect("B' cmdline readable");
    assert_eq!(cmdline, b"sleep\x0097\x00");
    let other_start = task_starttime_checked(other)
        .expect("B' stat readable")
        .expect("B' alive");
    retire_orphan(other, other_start);
    let mut status = 0;
    // SAFETY: our own child, dead.
    let got = unsafe { libc::waitpid(other, &mut status, libc::WNOHANG) };
    assert_eq!(got, other, "test must reap B'");
}

/// S138-round9: seam for the concurrent-inheritor regression:
/// `hook` runs after the report pipe exists (receiving both ends)
/// and before the middle fork, so the test can fork a deliberate
/// inheritor holding the write end. Production callers use
/// [`spawn_orphan_sleeper`].
/// R10-013: `framed` selects the newline-framed report read
/// (true: return on the `pid\n` line — the S138 fix) or the
/// legacy EOF-waiting read (false: the framing bad control —
/// a held write end stalls to the 10s bound, and the expiry
/// path must retire everything owned before failing loud).
/// R11-016: the hook RETURNS the pid of any long-lived holder
/// it forked (-1 if none) so the expiry path can retire a
/// holder the helper would otherwise never receive.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn spawn_orphan_sleeper_with_hook(
    duration: &str,
    hook: Option<&dyn Fn(i32, i32) -> i32>,
    framed: bool,
) -> (i32, u64) {
    let pipe = cloexec_pipe();
    let holder = if let Some(hook) = hook {
        hook(pipe[0], pipe[1])
    } else {
        -1
    };
    // SAFETY: the middle child forks the sleeper, reports its pid,
    // and exits; the sleeper execs sleep. Stack buffers only — no
    // allocation in either forked child.
    let middle = unsafe { libc::fork() };
    assert!(middle >= 0, "orphan fork failed");
    if middle == 0 {
        unsafe {
            libc::close(pipe[0]);
            let sleeper = libc::fork();
            if sleeper == 0 {
                libc::close(pipe[1]);
                let prog = b"sleep\0";
                let mut arg = [0u8; 16];
                let bytes = duration.as_bytes();
                if bytes.len() + 1 > arg.len() {
                    libc::_exit(3);
                }
                arg[..bytes.len()].copy_from_slice(bytes);
                libc::execlp(
                    prog.as_ptr() as *const libc::c_char,
                    prog.as_ptr() as *const libc::c_char,
                    arg.as_ptr() as *const libc::c_char,
                    std::ptr::null::<libc::c_char>(),
                );
                libc::_exit(3);
            }
            if sleeper > 0 {
                let mut digits = [0u8; 16];
                let mut len = 0;
                let mut value = sleeper as u32;
                loop {
                    digits[len] = b'0' + (value % 10) as u8;
                    len += 1;
                    value /= 10;
                    if value == 0 {
                        break;
                    }
                }
                let mut i = 0;
                while i < len / 2 {
                    digits.swap(i, len - 1 - i);
                    i += 1;
                }
                digits[len] = b'\n';
                len += 1;
                let mut written = 0;
                while written < len {
                    let got = libc::write(
                        pipe[1],
                        digits[written..len].as_ptr() as *const libc::c_void,
                        (len - written) as libc::size_t,
                    );
                    if got <= 0 {
                        break;
                    }
                    written += got as usize;
                }
            }
            libc::close(pipe[1]);
            libc::_exit(if sleeper > 0 { 0 } else { 3 });
        }
    }
    // SAFETY: pipe write end owned by this scope.
    unsafe { libc::close(pipe[1]) };
    // S138-round9: bounded newline-framed report read — the middle
    // child sends one `pid\n` line, and EOF is NOT required (a
    // forked inheritor holding the write end must not stall the
    // fixture: CLOEXEC covers exec'd inheritors, framing covers
    // fork-only ones). 10s bound; expiry fails loud.
    // R10-013: `framed` false restores the legacy EOF-waiting
    // shape (the bad control): the break below is skipped and a
    // held write end stalls to the bound.
    let mut text = [0u8; 32];
    let mut len = 0;
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if len >= text.len() {
            break;
        }
        if framed && text[..len].contains(&b'\n') {
            break;
        }
        let remaining = end
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(i32::MAX as u128) as i32;
        if remaining <= 0 {
            // R10-013: the report read expired (the bad control:
            // an inheritor holds the write end past the bound) —
            // retire EVERYTHING owned before failing loud, so the
            // expiry never leaks a descriptor, a zombie middle
            // child, or a live orphan.
            // SAFETY: pipe read end owned by this scope.
            unsafe { libc::close(pipe[0]) };
            // SAFETY: the middle child is ours (fork succeeded,
            // never reaped on this path): SIGKILL (a no-op when
            // already a zombie) then blocking reap.
            unsafe {
                libc::kill(middle, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(middle, &mut status, 0);
            }
            // R11-016(a1): the hook's holder is ours too (its
            // pid arrived through the hook's return) — retire
            // it with the same owned-child exactness. The
            // caller only learns the pid through its own
            // channel, which it must not reap before us, so
            // the blocking reap cannot hang; a raced exit
            // surfaces as ESRCH/ECHILD, never a hang.
            if holder > 0 {
                // SAFETY: holder is our own unreaped child.
                unsafe {
                    libc::kill(holder, libc::SIGKILL);
                    let mut status = 0;
                    libc::waitpid(holder, &mut status, 0);
                }
            }
            let orphan_note = retire_reported_orphan(&text[..len], duration);
            panic!(
                "orphan report read timed out (an inheritor holds the write end?) [{orphan_note}]"
            );
        }
        let mut waiting = libc::pollfd {
            fd: pipe[0],
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: valid pollfd for an owned descriptor.
        let ready = unsafe { libc::poll(&mut waiting, 1, remaining) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            panic!("orphan report poll failed: {error}");
        }
        if ready == 0 {
            continue;
        }
        // SAFETY: bounded read from the middle-child pipe.
        let got = unsafe {
            libc::read(
                pipe[0],
                text[len..].as_mut_ptr() as *mut libc::c_void,
                (text.len() - len) as libc::size_t,
            )
        };
        if got <= 0 {
            break;
        }
        len += got as usize;
    }
    // SAFETY: pipe read end owned by this scope.
    unsafe { libc::close(pipe[0]) };
    let mut status = 0;
    // SAFETY: valid status out-pointer for the owned middle child.
    let _ = unsafe { libc::waitpid(middle, &mut status, 0) };
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "orphan middle child must report its sleeper"
    );
    let pid: i32 = std::str::from_utf8(&text[..len])
        .expect("orphan pid is text")
        .trim()
        .parse()
        .expect("orphan pid parses");
    // Wait for the exec: a pre-exec fork still carries the test
    // binary's argv and would dodge argv matching either way.
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        if cmdline.starts_with(b"sleep") {
            break;
        }
        assert!(Instant::now() < end, "orphan sleeper never execed");
        std::thread::sleep(Duration::from_millis(10));
    }
    let pinned = task_starttime_checked(pid)
        .expect("orphan stat readable")
        .expect("orphan visible after exec");
    (pid, pinned)
}

/// R12-005-stress: disappearance predicate for `retire_orphan`'s
/// poll — presence-aware PLUS a foreign-tick escape. Gone or
/// zombie retires as before (zombie counts: reaping is the live
/// parent's duty — B'-family orphans sit unreaped under live
/// parents until test-end). A LIVE holder with a different birth
/// tick also retires: our pidfd-signaled orphan is then
/// definitionally retired (S98 principle) — the stranger is a
/// steered recycle, not resistance. Only a live same-tick holder
/// keeps polling. Unreadable rows stay UNRESOLVED (loud), never
/// retired. Residual: a live same-tick recycle reads as ours and
/// polls to the bound (S100-class). Extracted (not inlined) so
/// the recycle semantics carry a direct unit regression: a
/// mid-poll recycle is unplantable end-to-end (the pin stage
/// already rejects pre-recycled numbers fail-closed, and a
/// planter thread cannot beat the poll's first read).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn orphan_retired_checked(pid: i32, pinned: u64) -> Result<bool, String> {
    if task_retired_checked(pid)? {
        return Ok(true);
    }
    match task_starttime_checked(pid) {
        Ok(None) => Ok(true),
        Ok(Some(now)) => Ok(now != pinned),
        Err(error) => Err(error),
    }
}

/// S112/S115-round8: retire a test orphan (non-child) through
/// pinned authority: pin first, verify the pinned number still
/// names the reported starttime, signal through the pin, poll for
/// disappearance. Never a numeric signal on a non-child.
/// R13-002: this gate keeps the toolchain-only build green
/// (verify: cargo test -p scopebase-testkit --features toolchain
/// --test toolchain_invoke --no-run).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn retire_orphan(pid: i32, pinned: u64) {
    let fd = pidfd_open_task(pid).expect("orphan pinnable while live");
    assert_eq!(
        task_starttime_checked(pid),
        Ok(Some(pinned)),
        "orphan identity holds"
    );
    let errno = pidfd_signal_task(fd, libc::SIGKILL);
    assert!(
        errno == 0 || errno == libc::ESRCH,
        "orphan signaled, got errno {errno}"
    );
    // SAFETY: fd owned by this scope.
    unsafe { libc::close(fd) };
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        match orphan_retired_checked(pid, pinned) {
            Ok(true) => return,
            Ok(false) => {}
            Err(error) => panic!("orphan {pid} retirement unresolved: {error}"),
        }
        assert!(Instant::now() < end, "orphan {pid} resisted retirement");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// R12-005-stress: the retirement predicate needs a foreign-tick
/// escape. R12-002's hook leaves ns_last_pid just below our orphan,
/// so a sibling fork retakes the freed number inside
/// `retire_orphan`'s 5s poll — a pure presence-poll misreads the
/// live stranger as "resisted" (3/10 full-suite flakes). Each state
/// is fabricated directly: recycled-under-foreign-tick is retired;
/// live-ours (same tick) is not; zombie-ours retires as before
/// (dead is retired — reaping is the live parent's duty).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn orphan_retirement_predicate_ignores_recycled_number() {
    // R12-002: serialize steerers (whole-test hold).
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let last_path = "/proc/sys/kernel/ns_last_pid";
    let last_before = match std::fs::read_to_string(last_path) {
        Ok(text) => text.trim().to_string(),
        Err(_) => {
            eprintln!("skip: ns_last_pid unreadable (no reuse control)");
            return;
        }
    };
    if !locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
        eprintln!("skip: ns_last_pid unwritable (no reuse control)");
        return;
    }
    // R13-008: failure injection (env-gated; inert otherwise).
    // placement-failure skips the placement loop (forced
    // contended exit); same-tick forces the same-tick branch
    // after a real placement; observe-failure corrupts the
    // live-ours observation into a real-assert failure. Unknown
    // values ignore (the driver requires its reports, so a typo
    // fails loud there, not silent here).
    let forced = std::env::var("SCOPEBASE_R13008_FORCE").ok();
    // Live-ours: an owned pauser under its own tick.
    let live = fork_pauser();
    // R13-008: custody before any exit can skip cleanup — a skip
    // return or staging panic must not leak the perpetual pauser.
    // R14-001: the guard pins the birth tick (stale drops spare
    // recycled numbers) and disarms after explicit retires.
    // R14-012: custody AT birth (auto-pins) — the reads below
    // panic safe.
    let mut live_guard = SilentChildGuard::new(live);
    let live_tick = task_starttime_checked(live)
        .expect("pauser stat readable")
        .expect("pauser live");
    // R15-004: late-pin the observed live tick (repairs a
    // construction read the retry did not outlast).
    live_guard.pin(live_tick);
    // Zombie-ours: a fork-only child that exits at once and is
    // never reaped until cleanup — keeps its tick in state Z.
    // SAFETY: fork; the child only _exits (no runtime, no locks).
    // R13-007: the intended exit is a DISTINCT code (17): a
    // post-fork panic in this single-threaded child also exits 0
    // (last-thread termination), so ==0 could not prove the child
    // reached the _exit site.
    let zombie = unsafe { libc::fork() };
    // R13-007: the child branch comes FIRST — nothing panic-capable
    // may precede it (an assert here runs in the child too, with
    // zero, invoking panic machinery after a raw fork). The child
    // path is compare-then-_exit only.
    if zombie == 0 {
        unsafe { libc::_exit(17) };
    }
    assert!(zombie > 0, "zombie fork");
    // R14-012: custody AT birth, parent-only (the child _exited
    // above and can never reach here) — the Z-poll and tick
    // read below panic safe, and the drop discharges the status.
    let mut zombie_guard = SilentChildGuard::new(zombie);
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let row = std::fs::read_to_string(format!("/proc/{zombie}/stat")).expect("zombie stat");
        let state = row
            .rsplit_once(") ")
            .and_then(|(_, after)| after.split_whitespace().next());
        if state == Some("Z") {
            break;
        }
        assert!(Instant::now() < end, "child never zombied");
        std::thread::sleep(Duration::from_millis(1));
    }
    let zombie_tick = task_starttime_checked(zombie)
        .expect("zombie stat readable")
        .expect("zombie present");
    // R15-004: late-pin the observed live tick.
    zombie_guard.pin(zombie_tick);
    // Recycled: kill an owned pauser, force a tick advance, retake
    // its number with a steered squatter (R12-005: cross-process
    // placement lock; a racing sibling spawn may steal it —
    // retried, then honestly skipped).
    let victim = fork_pauser();
    // R14-012: custody AT birth — the tick read below panics
    // safe; disarmed once explicitly retired (the number is
    // freed for the squatter).
    let mut victim_guard = SilentChildGuard::new(victim);
    let victim_tick = task_starttime_checked(victim)
        .expect("victim stat readable")
        .expect("victim live");
    // R15-004: late-pin the observed live tick.
    victim_guard.pin(victim_tick);
    kill_wait_child(victim);
    victim_guard.disarm();
    std::thread::sleep(Duration::from_millis(50));
    let _nsflock = ns_last_pid_flock();
    let mut squatter = -1;
    // R14-012: the placed squatter takes custody AT placement
    // (inside the loop — a staging panic between placement and
    // the tick read below must not leak it).
    let mut squatter_guard: Option<SilentChildGuard> = None;
    // R13-008: forced placement failure skips the loop (the
    // contended exit below runs with staged fixtures).
    if forced.as_deref() != Some("placement-failure") {
        for _ in 0..100 {
            if !steer_next_pid_unlocked(victim) {
                break;
            }
            let kid = fork_pauser();
            if kid == victim {
                squatter = kid;
                squatter_guard = Some(SilentChildGuard::new(kid));
                break;
            }
            // Non-placed candidate: guarded across the explicit
            // retire (a kill_wait panic still retires it).
            let mut kid_guard = SilentChildGuard::new(kid);
            kill_wait_child(kid);
            kid_guard.disarm();
        }
    }
    drop(_nsflock);
    locked_restore_hint(&last_before);
    if squatter != victim {
        // R13-008: the driver requires the R13008 line (fixture
        // identities for its independent absence checks) before
        // the report on forced runs.
        if forced.is_some() {
            eprintln!("R13008 live={live}:{live_tick} zombie={zombie}:{zombie_tick} squatter=none");
        }
        // R13-008: retire before reporting — drop the guards
        // (silent) and VERIFY (loud) so the skip itself proves
        // clean fixtures, never trusts them.
        drop(live_guard);
        drop(zombie_guard);
        assert_child_gone(live, live_tick, "pauser");
        assert_child_gone(zombie, zombie_tick, "zombie");
        if forced.as_deref() == Some("placement-failure") {
            eprintln!("skip: FORCED placement failure (inject)");
        } else {
            eprintln!("skip: victim number not retaken (contended)");
        }
        return;
    }
    // R14-012: placed (the contended exit returned above), so
    // the loop armed the guard — unwrap it for the disarms
    // below.
    let mut squatter_guard = squatter_guard.expect("placed squatter guarded");
    let now = task_starttime_checked(victim)
        .expect("squatter stat readable")
        .expect("squatter live");
    // R15-004: late-pin the squatter's live tick (the guard was
    // armed at placement; this repairs a raced construction).
    squatter_guard.pin(now);
    // R13-008: forced same-tick rejection runs the branch after a
    // real placement (a natural contended exit instead would miss
    // the scenario — the driver requires the forced report).
    if now == victim_tick || forced.as_deref() == Some("same-tick") {
        if forced.is_some() {
            eprintln!(
                "R13008 live={live}:{live_tick} zombie={zombie}:{zombie_tick} squatter={victim}:{now}"
            );
        }
        kill_wait_child(squatter);
        squatter_guard.disarm();
        // R13-008: retire before reporting (squatter explicit
        // above; guards for the staged pair) and VERIFY all three.
        drop(live_guard);
        drop(zombie_guard);
        assert_child_gone(squatter, now, "squatter");
        assert_child_gone(live, live_tick, "pauser");
        assert_child_gone(zombie, zombie_tick, "zombie");
        if forced.as_deref() == Some("same-tick") {
            eprintln!("skip: FORCED same-tick rejection (inject)");
        } else {
            eprintln!("skip: same-tick recycle (S100, vacuous)");
        }
        return;
    }
    // The incident: a proven-foreign task under the number means
    // OUR orphan is definitionally retired (S98 principle).
    // R13-008: record BEFORE cleanup (R12-014 pattern) — the
    // asserts below must not own live fixtures. Recording cannot
    // skip cleanup: a recording panic still unwinds through the
    // guards (silent retire), while assert panics land after
    // explicit cleanup with nothing left to leak.
    // The incident: a proven-foreign task under the number means
    // OUR orphan is definitionally retired (S98 principle).
    let recycled_retired = orphan_retired_checked(victim, victim_tick);
    // Forced observation failure corrupts the live-ours
    // observation into a real-assert failure (indistinguishable
    // from a genuine poll regression); the driver requires the
    // R13008 line plus the assert message.
    if forced.as_deref() == Some("observe-failure") {
        eprintln!(
            "R13008 live={live}:{live_tick} zombie={zombie}:{zombie_tick} squatter={victim}:{now}"
        );
    }
    let live_retired = if forced.as_deref() == Some("observe-failure") {
        Ok(true)
    } else {
        orphan_retired_checked(live, live_tick)
    };
    // Zombie-ours retires as before (dead is retired) — only live
    // same-tick polls on.
    let zombie_retired = orphan_retired_checked(zombie, zombie_tick);
    // Explicit loud cleanup before every assert, then the
    // guards disarm (R14-001: their numbers are free now — a
    // stale drop would signal whoever recycled them).
    kill_wait_child(squatter);
    squatter_guard.disarm();
    kill_wait_child(live);
    // SAFETY: our own zombie child.
    let mut status = 0;
    let got = unsafe { libc::waitpid(zombie, &mut status, 0) };
    live_guard.disarm();
    zombie_guard.disarm();
    assert_eq!(got, zombie, "zombie reaped in cleanup");
    // R13-007: the zombie must have reached the intended
    // immediate _exit site — only that path yields 17 (a
    // post-fork panic exits 0 here and risks inherited-lock
    // deadlock on the way there).
    assert!(
        libc::WIFEXITED(status),
        "zombie must exit, not die by signal"
    );
    assert_eq!(
        libc::WEXITSTATUS(status),
        17,
        "zombie must reach the intended immediate exit"
    );
    assert_eq!(recycled_retired, Ok(true), "recycled number is retired");
    assert_eq!(zombie_retired, Ok(true), "zombie-ours is retired");
    assert_eq!(live_retired, Ok(false), "live-ours is not retired");
}

/// R13-008: every forced exit of the predicate regression must
/// retire its fixtures BEFORE reporting. Drives the test binary
/// three times (placement-failure, same-tick, observe-failure)
/// and requires on each: the right report (forced skip line or
/// the real assert message), the R13008 line (fixture identities),
/// and tick-gated absence of every named fixture (a recycled
/// number with a different tick is NOT our fixture; same-tick
/// presence is a leak, loud). The child also self-verifies (loud
/// cleanup asserts before reporting), so a cleanup failure
/// surfaces as the WRONG report — the driver's /proc checks are
/// independent teeth (a leaked pauser survives the child's exit
/// and is observable here; zombie discharge is proven child-side,
/// where only the owner can reap). Output is drained bounded
/// (drain_exited_child_output) — never read to EOF: a RED-shape
/// child leaks a pipe-holding pauser that would hang an EOF drain
/// forever. Holds STEER_SERIAL across each child run (in-process
/// steering siblings block while the child steers alone).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn predicate_forced_exits_retire_fixtures() {
    use std::os::unix::process::CommandExt as _;
    use std::time::{Duration, Instant};
    // R13-010: capability absence skips (same shape as the R12-014
    // driver — the children would skip before injection).
    if let Some(reason) = driver_steering_skip_reason() {
        eprintln!("{reason}");
        return;
    }
    for (forced, success, message) in [
        (
            "placement-failure",
            true,
            "skip: FORCED placement failure (inject)",
        ),
        (
            "same-tick",
            true,
            "skip: FORCED same-tick rejection (inject)",
        ),
        ("observe-failure", false, "live-ours is not retired"),
    ] {
        // R12-002: serialize steerers (whole-child hold).
        let _steer = STEER_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let exe = std::env::current_exe().expect("probe test binary path");
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("orphan_retirement_predicate_ignores_recycled_number")
            .arg("--exact")
            .arg("--nocapture")
            .env("SCOPEBASE_R13008_FORCE", forced)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // SAFETY: setpgid on self pre-exec, no userspace state.
        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let mut child = cmd.spawn().expect("spawn forced probe");
        // R12-005: pin before any wait (retirement identity gate).
        let staged = task_starttime_checked(child.id() as i32)
            .expect("probe stat readable")
            .expect("probe visible");
        let end = Instant::now() + Duration::from_secs(90);
        let (status, stdout, stderr) = loop {
            if let Some(status) = child.try_wait().expect("probe wait") {
                let (out, err) = drain_exited_child_output(&child);
                break (status, out, err);
            }
            if Instant::now() >= end {
                retire_probe_tree(&mut child, staged);
                panic!("forced probe ({forced}) hung past 90s");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let _ = stdout;
        let stderr_text = String::from_utf8_lossy(&stderr);
        assert_eq!(
            status.success(),
            success,
            "forced probe ({forced}) exit mismatch, got {status}: {stderr_text}"
        );
        assert!(
            stderr_text.contains(message),
            "forced probe ({forced}) must report '{message}': {stderr_text}"
        );
        let line = stderr_text
            .lines()
            .find(|l| l.starts_with("R13008 "))
            .unwrap_or_else(|| {
                panic!("forced probe ({forced}) missing R13008 line: {stderr_text}")
            });
        let field = |name: &str| -> &str {
            line.split_whitespace()
                .filter_map(|f| f.split_once('='))
                .find(|(key, _)| *key == name)
                .unwrap_or_else(|| panic!("R13008 missing {name}=: {line}"))
                .1
        };
        // Every named fixture must be gone-or-recycled (tick-gated
        // absence — same-tick presence is a leak, loud).
        for name in ["live", "zombie", "squatter"] {
            let value = field(name);
            if value == "none" {
                continue;
            }
            let (pid_text, tick_text) = value
                .split_once(':')
                .unwrap_or_else(|| panic!("R13008 {name} unparseable: {value}"));
            let pid: i32 = pid_text.parse().expect("fixture pid numeric");
            let tick: u64 = tick_text.parse().expect("fixture tick numeric");
            if let Ok(Some(now)) = task_starttime_checked(pid) {
                assert_ne!(now, tick, "fixture {name}={pid} survives (tick {now})");
            }
        }
    }
}

/// R13-010: the forced-failure drivers must SKIP (not fail) when
/// steering is unavailable. Drives each driver test with forced
/// absence and requires exit success plus the forced-skip report.
/// On steering-capable machines only the injection can produce
/// that report (a natural skip is impossible), so it proves the
/// skip path ran; capability absence stays explicitly
/// unexecuted. The executable paths stay covered by the drivers
/// themselves (run unforced in-suite). No steering happens here
/// (the drivers skip before spawning), so no lock is needed.
/// Bounded hang guard with tree retirement (house driver shape).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn forced_failure_drivers_skip_without_steering() {
    use std::time::{Duration, Instant};
    for test in [
        "intermediate_forced_failure_cleans_before_reporting",
        "predicate_forced_exits_retire_fixtures",
    ] {
        let exe = std::env::current_exe().expect("probe test binary path");
        let mut child = std::process::Command::new(exe)
            .arg(test)
            .arg("--exact")
            .arg("--nocapture")
            .env("SCOPEBASE_R13010_FORCE_NOSTEER", "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn driver probe");
        // R12-005: pin before any wait (retirement identity gate).
        let staged = task_starttime_checked(child.id() as i32)
            .expect("probe stat readable")
            .expect("probe visible");
        // The driver skips before spawning — instant. Bound the
        // wait anyway (a hang here means the skip never ran).
        let end = Instant::now() + Duration::from_secs(30);
        let (status, stderr) = loop {
            if let Some(status) = child.try_wait().expect("probe wait") {
                let (_, err) = drain_exited_child_output(&child);
                break (status, err);
            }
            if Instant::now() >= end {
                retire_probe_tree(&mut child, staged);
                panic!("driver probe ({test}) hung past 30s");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let stderr_text = String::from_utf8_lossy(&stderr);
        assert!(
            status.success(),
            "driver ({test}) must skip on forced absence, got {status}: {stderr_text}"
        );
        assert!(
            stderr_text.contains("skip: FORCED unavailable steering (inject)"),
            "driver ({test}) must report its forced skip: {stderr_text}"
        );
    }
}

/// S115/S123-round8: reap a confined probe child under a hang
/// guard. Returns its exit code; panics (after killing) on hang,
/// wait failure, or death by signal.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn reap_probe(pid: i32, guard: Duration) -> i32 {
    let deadline = Instant::now() + guard;
    loop {
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if got == pid {
            assert!(
                libc::WIFEXITED(status),
                "probe died by signal {}",
                libc::WTERMSIG(status)
            );
            return libc::WEXITSTATUS(status);
        }
        if got < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            panic!("probe wait failed: {error}");
        }
        if Instant::now() >= deadline {
            // SAFETY: retiring our own hung probe.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(pid, &mut status, 0);
            }
            panic!("probe hung past {guard:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// S112-round8: an unrelated same-argv task — reparented to init,
/// NOT our descendant — must survive the hang sweep. Pre-fix the
/// global argv scan kills it (RED); post-fix descendant custody
/// spares it. Duration 91 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn hang_sweep_spares_unrelated_matching_task() {
    let start_tick = boot_ticks_now().expect("tick reads");
    let (pid, pinned) = spawn_orphan_sleeper("91");
    assert_eq!(
        task_starttime_checked(pid),
        Ok(Some(pinned)),
        "orphan pinned"
    );
    let swept = hang_sweep(&[("sleep", &["91"])], Some(start_tick));
    assert!(
        swept.is_empty(),
        "unrelated task must be spared, got: {swept:?}"
    );
    assert_eq!(
        task_retired_checked(pid),
        Ok(false),
        "unrelated matching task must survive"
    );
    assert_eq!(
        task_starttime_checked(pid),
        Ok(Some(pinned)),
        "same task, not a replacement"
    );
    retire_orphan(pid, pinned);
}

/// R11-004: sole child pid of `pid` (via the children file),
/// polled bounded.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn sole_child_pid(pid: i32) -> i32 {
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")) {
            let kids: Vec<i32> = text
                .split_whitespace()
                .filter_map(|word| word.parse().ok())
                .collect();
            if kids.len() == 1 {
                return kids[0];
            }
        }
        assert!(Instant::now() < end, "child of {pid} never appeared");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// R11-004: steer the pid allocator so the next fork takes
/// `want` (ns_last_pid = want - 1). Direct write first,
/// passwordless sudo fallback; false when unwritable (the
/// regression skips — without reuse control the replacement
/// shape is unconstructible).
/// IR1 contract (internal review round 1): this mutates
/// GLOBAL allocator state during parallel libtest — but the
/// kernel never hands one live pid to two tasks, so sibling
/// tests (which assert freshness/inequality, never pid
/// magnitude or ordering) are unaffected; pid-steals of OUR
/// steered number retry bounded and loud (100 tries), and
/// the test restores the prior hint politely after.
/// R12-002: steering tests serialize AMONG THEMSELVES
/// ([`STEER_SERIAL`], whole-test hold) — two concurrent
/// steerers overwrite each other's hint and livelock the
/// bounded steal loops, and the combined fork churn
/// recycles numbers under number-based retire polls.
/// Ordinary (non-steering) forks need no coordination:
/// the only shared invariant is live-pid uniqueness, which
/// the kernel guarantees.
///
/// R12-002: only one pid-steering walk regression runs at a
/// time (see above). Poison is ignored (a panicked sibling
/// already failed; each test still reports its own fate).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
static STEER_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// R14-002: serialize placement-lock TAKERS within this
/// process. POSIX locks merge per-process (a second take
/// succeeds instantly instead of excluding, and its drop
/// releases the first holder early) — the mutex restores
/// exclusion; the fd lock below still excludes foreign
/// processes. Held for the guard's whole lifetime. Never
/// nest takes (callers use `*_unlocked` under a held guard).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
static FLOCK_TAKER: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// R12-005: cross-process ns_last_pid placement lock (twin of
/// the audit lib-tests' guard — SAME lockfile path, kept in
/// sync by hand): lib tests and integration tests run as
/// separate (possibly concurrent) processes, so the
/// in-process mutexes cannot serialize them; without this a
/// foreign steer between our steer and our spawn corrupts
/// exact-number placement. POSIX fcntl locks (NOT flock):
/// flock locks leak into fork-only children (the lock survives
/// our close on their inherited fd), while POSIX locks are
/// dropped across fork. O_CLOEXEC keeps the fd out of exec'd
/// children (their fd-count asserts would see it). NEVER NEST:
/// same-process POSIX locks merge, so an inner drop would
/// release the outer's lock — hold at most one (placement
/// loops never nest). R13-009: locked_* helpers take this guard
/// internally — never call them under a held guard (explicit
/// drop/scope after placement first). Lock order everywhere:
/// STEER_SERIAL first (test top), this guard second (loop top).
/// R14-002: the in-process taker mutex rides inside the guard
/// (POSIX locks merge per-process, so the fd lock alone does
/// not exclude same-process takers).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct NsLastPidFlock {
    fd: libc::c_int,
    _taker: std::sync::MutexGuard<'static, ()>,
}

/// R12-005: take the cross-process placement lock (blocking;
/// held for milliseconds across one steer-then-spawn
/// placement loop).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn ns_last_pid_flock() -> NsLastPidFlock {
    use std::os::unix::ffi::OsStrExt as _;
    // R14-002: in-process exclusion FIRST (POSIX takes merge
    // within a process); the fd lock below then excludes
    // foreign processes. Poison is ignored (as STEER_SERIAL).
    let taker = FLOCK_TAKER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = std::env::temp_dir().join("scopebase-ns-last-pid.lock");
    let bytes = path.as_os_str().as_bytes();
    let cpath = std::ffi::CString::new(bytes).expect("lock path c-str");
    // SAFETY: valid path pointer; O_CLOEXEC documented above.
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC,
            0o600,
        )
    };
    assert!(fd >= 0, "placement lock opens");
    // SAFETY: F_SETLKW on an owned fd, whole-file write lock.
    let locked = unsafe {
        libc::fcntl(
            fd,
            libc::F_SETLKW,
            &libc::flock {
                l_type: libc::F_WRLCK as libc::c_short,
                l_whence: libc::SEEK_SET as libc::c_short,
                l_start: 0,
                l_len: 0,
                l_pid: 0,
            },
        )
    };
    assert_eq!(locked, 0, "placement lock acquires");
    NsLastPidFlock { fd, _taker: taker }
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl Drop for NsLastPidFlock {
    fn drop(&mut self) {
        // SAFETY: unlock-then-close an owned fd (never nest:
        // releasing here releases the process's lock).
        unsafe {
            libc::fcntl(
                self.fd,
                libc::F_SETLK,
                &libc::flock {
                    l_type: libc::F_UNLCK as libc::c_short,
                    l_whence: libc::SEEK_SET as libc::c_short,
                    l_start: 0,
                    l_len: 0,
                    l_pid: 0,
                },
            );
            libc::close(self.fd);
        }
    }
}

/// R14-002: same-process placement-lock takes must exclude
/// each other. POSIX locks merge within a process: a second
/// take succeeds instantly instead of blocking, and its drop
/// releases the first holder's lock early — the mechanism
/// behind the driver's probe-completing-while-held flake. Hold
/// the lock, require a taker thread still blocked after 300ms,
/// release, require it acquire promptly.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn placement_lock_takes_exclude_in_process() {
    let held = ns_last_pid_flock();
    let (tx, rx) = std::sync::mpsc::channel();
    let taker = std::thread::spawn(move || {
        let _second = ns_last_pid_flock();
        let _ = tx.send(());
        std::thread::sleep(Duration::from_millis(50));
    });
    assert_eq!(
        rx.recv_timeout(Duration::from_millis(300)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout),
        "second same-process take must block while held (RED: merged)"
    );
    drop(held);
    rx.recv_timeout(Duration::from_secs(5))
        .expect("taker acquires after release");
    taker.join().expect("taker joins");
}

/// R12-002: fork a pausing child WITHOUT exec (microsecond
/// placement for pid-stealing loops — Command::spawn's
/// millisecond fork+exec window loses the steered number to
/// siblings too often, and a squatter holding P defeats all
/// 100 retries deterministically). The child pauses until
/// SIGKILLed; the parent MUST kill+reap it (see
/// [`kill_wait_child`]). Fork-only children inherit fds:
/// safe in this binary (no test holds pipe write ends
/// in-process — stdin is always null — so no EOF can be
/// held hostage). Returns the child's pid.
/// SAFETY: the child touches nothing but pause().
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn fork_pauser() -> i32 {
    // SAFETY: fork; the child pauses (async-signal-safe
    // only — no Rust runtime, no locks), the parent returns
    // the pid.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "pauser fork failed");
    if pid == 0 {
        loop {
            unsafe {
                libc::pause();
            }
        }
    }
    pid
}

/// R12-002: SIGKILL + bounded reap of an owned fork-pauser
/// (discarded steal attempts and final adoptees). Panics
/// loud on failure — our own child must die and reap.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn kill_wait_child(pid: i32) {
    // SAFETY: our own fork-pauser child.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        // SAFETY: waitpid on our own child.
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if got == pid || got < 0 {
            return;
        }
        assert!(Instant::now() < end, "pauser {pid} unreaped");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// R13-008: silent best-effort retirement for Drop guards (never
/// panics — a panicking Drop during unwinding aborts).
/// IR-002: waitpid-probes FIRST (R14-006 observe-first for the
/// unpinned path too) — ECHILD (not our child: a gone number,
/// or one recycled by a foreign task) returns WITHOUT
/// signaling; a reaped status (got == pid) was our zombie —
/// done, no kill needed; only a live owned child (0) takes
/// SIGKILL plus the bounded reap. Every error ignored. The
/// loud paths retire explicitly (kill_wait_child / asserted
/// waits) first, so a guard firing means an exit that skipped
/// explicit cleanup.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn retire_child_silent(pid: i32) {
    let mut status = 0;
    // SAFETY: WNOHANG probe of a possibly-owned child; never blocks.
    let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if got != 0 {
        // Our zombie discharged (got == pid), or not our child
        // at all (got < 0: gone, or a foreign recycle) —
        // either way no signal is owed.
        return;
    }
    // SAFETY: signal-only to a live owned child; errors ignored.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        // SAFETY: waitpid on an owned child; WNOHANG never blocks.
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if got == pid || got < 0 {
            return;
        }
        if Instant::now() >= end {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// R15-003: toolchain twin of the audit tick-gated kill —
/// SIGKILL only when the current tick matches the pinned one.
/// Same contract (true unless unreadable; never panics), same
/// injected-read seam for the unreadable arm.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn kill_tick_gated_with(
    pid: i32,
    tick: u64,
    read: impl Fn(i32) -> Result<Option<u64>, String>,
) -> bool {
    match read(pid) {
        Ok(Some(now)) if now == tick => {
            // SAFETY: tick-pinned staged task; errors ignored.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            true
        }
        Ok(_) => true,
        Err(_) => false,
    }
}

/// R15-003: the production caller of the gate above.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn kill_tick_gated(pid: i32, tick: u64) -> bool {
    kill_tick_gated_with(pid, tick, task_starttime_checked)
}

/// R15-004: birth-tick pin with transient retry — a single
/// EMFILE-class blip at guard construction must not leave the
/// guard unpinned (an unpinned drop murders a recycled
/// same-process child it cannot distinguish). Errors retry
/// bounded (~100ms); Ok(None) (gone) returns immediately —
/// death is not transient. The read fn is injected so the
/// retry arms are unit-testable.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn pin_birth_tick_with(pid: i32, read: impl Fn(i32) -> Result<Option<u64>, String>) -> Option<u64> {
    let end = Instant::now() + Duration::from_millis(100);
    loop {
        match read(pid) {
            Ok(tick) => return tick,
            Err(_) if Instant::now() < end => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return None,
        }
    }
}

/// R15-004: the production pin reader.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn pin_birth_tick(pid: i32) -> Option<u64> {
    pin_birth_tick_with(pid, task_starttime_checked)
}

/// R13-008: Drop guard retiring an owned fixture child on every
/// exit (early return or panic). Covers pausers (retire) and
/// zombies (discharge status — the kill also reaches a child hung
/// before its immediate exit; an already-exited zombie answers
/// ESRCH and is simply reaped).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct SilentChildGuard {
    pid: i32,
    tick: Option<u64>,
    disarmed: bool,
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl SilentChildGuard {
    /// R14-012: custody AT birth — auto-pins the birth tick (our
    /// unreaped child cannot have recycled, so the read names
    /// our fixture). A failed read leaves the guard unpinned;
    /// the drop then waitpid-probes first (IR-002: ECHILD
    /// returns without signaling — a foreign recycle is spared;
    /// a reaped zombie is discharged) and signals only a live
    /// owned child. Never panics: construction itself must not
    /// be a staging failure (the birth→read window it closes).
    fn new(pid: i32) -> Self {
        let tick = pin_birth_tick(pid);
        SilentChildGuard {
            pid,
            tick,
            disarmed: false,
        }
    }
    /// R14-001: stand down after an explicit loud retire —
    /// without this the drop double-retires the (possibly
    /// recycled) number.
    fn disarm(&mut self) {
        self.disarmed = true;
    }

    /// R15-004: late-pin a birth tick read after construction
    /// (the caller just observed live identity while the guard
    /// holds None — construction raced a transient read failure
    /// the retry did not outlast). Unconditional set: the drop
    /// re-verifies against the live tick, so a pin of OUR
    /// child's tick degrades to a skip once stale, never a
    /// murder. Caller obligation: pin only ticks read while the
    /// child is known-ours and alive — never a post-retire
    /// re-read (that could pin a squatter's tick, which the
    /// drop WOULD match and signal).
    fn pin(&mut self, tick: u64) {
        self.tick = Some(tick);
    }
}

/// R15-005: drop-time fallback when the pinned tick re-read
/// FAILS (Err only — Ok arms are decided by the caller).
/// R16-004: kill-0 ONLY — never waitpid. Without the tick read
/// the number's holder is unproven: a same-process sibling test
/// may own a zombie there (threads share the child table) and a
/// numeric wait would steal its status while falsely discharging
/// our custody. ESRCH discharges silently (proven gone);
/// anything else emits the explicit identity-preserving
/// unresolved-custody line (pid + pinned tick + read error) via
/// a fallible stderr write — never eprintln! in Drop (panicking
/// during unwind aborts). Our own unreaped zombie goes loud and
/// reaps at process exit (the R15-005 silent zombie arm is gone
/// with its theft). Never signals: unresolved identity must not
/// kill (R15-003), and a present number could be our own fork's
/// recycle (R14-001 residual).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn drop_unresolved_custody(pid: i32, tick: u64, read_err: &str) {
    use std::io::Write as _;
    let loud = || {
        let _ = writeln!(
            std::io::stderr(),
            "scopebase unresolved-custody pid={pid} tick={tick} read_err={read_err}"
        );
    };
    // SAFETY: signal 0 queries only.
    if unsafe { libc::kill(pid, 0) } != 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    {
        return; // Gone: discharged, silent.
    }
    // Present (kill-0 ok, EPERM, or anything else):
    // unobservable-but-there — loud. No waitpid: the holder may
    // be a sibling's zombie (status theft) or a live task
    // (nothing to reap) — neither is ours to take.
    loud();
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl Drop for SilentChildGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        match self.tick {
            // R14-012: unpinned (birth read failed) — the
            // retire waitpid-probes first (IR-002), so a gone
            // number or a foreign recycle takes no signal.
            // Residual: recycle by OUR OWN fork is
            // indistinguishable without a pin.
            None => retire_child_silent(self.pid),
            // R14-001: retire ONLY while the number still names
            // our fixture. An explicit retire earlier (or a steal)
            // frees the number for a sibling's task within
            // milliseconds — a blind kill would murder it (the
            // full-suite flake). Residual: a same-tick recycle
            // inside the µs gate→signal window (S100-class).
            Some(tick) => match task_starttime_checked(self.pid) {
                Ok(Some(now)) if now == tick => retire_child_silent(self.pid),
                // R15-005: proven-gone/recycled stays silent (as
                // before); only a FAILED read takes the fd-less
                // fallback probe below.
                Ok(_) => {}
                Err(error) => drop_unresolved_custody(self.pid, tick, &error),
            },
        }
    }
}

/// R13-008: loud tick-gated absence proof after guard retirement
/// (skip paths verify before reporting). A recycled number with a
/// different tick is NOT our fixture; a same-tick recycle inside
/// the µs guard-drop→verify window fails loud as a real bug, not
/// a race (no fork lands there that fast). Unresolvable stat is
/// never absence — it fails loud.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn assert_child_gone(pid: i32, pinned: u64, what: &str) {
    match task_starttime_checked(pid) {
        Ok(None) => {}
        Ok(Some(now)) => assert_ne!(now, pinned, "{what} {pid} survived retirement"),
        Err(error) => panic!("{what} {pid} retirement unresolved: {error}"),
    }
}

/// R14-012: a birth number is free only when /proc proves
/// absence AND waitpid proves discharge (ECHILD — reaped). A
/// zombie fails the first (it keeps its tick); an unreaped death
/// fails the second. Checked in this order so the discharge
/// probe can never mask a zombie by reaping it mid-check.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn assert_pid_free(pid: i32, what: &str) {
    assert_eq!(
        task_starttime_checked(pid),
        Ok(None),
        "{what} {pid} survived retirement"
    );
    // SAFETY: WNOHANG discharge probe of our own child.
    let mut status = 0;
    let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    assert!(
        got < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD),
        "{what} {pid} status undischarged (waitpid gave {got})"
    );
}

/// R14-012: staging custody driver — every birth shape takes
/// custody AT birth (guard before any fallible read), proved by
/// two genuine injections per birth: (A) observation failure
/// (the fixture dies before the read — the read's expect
/// panics); (B) later-spawn failure (birth + observation
/// succeed, then a spawn of a missing binary panics). Each case
/// requires disappearance + status discharge BEFORE the failure
/// report (assert order mirrors it; the guard drops during
/// unwind, ahead of the panic). Shapes → sites: pauser =
/// driver live/victim/squatter/kids + R14-001 stand-in;
/// raw-fork = driver zombie; self-grouped command = decision
/// ours-885; plain command = decision plain-886 + R14-001
/// fixture-890.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn staging_custody_holds(tag: &str, birth: impl Fn() -> i32, observe: impl Fn(i32)) {
    // R12-002: serialize against steerers (whole-test hold) —
    // this driver's fork bursts must not steal steered
    // placements from concurrent tests.
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Case A: death before observation — the read must fail, and
    // the (already reaped) fixture must stay free. Silent bounded
    // retire (a surviving fixture fails loud below — the
    // injection must take, never pass vacuously).
    let slot_a = std::cell::Cell::new(-1);
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let pid = birth();
        slot_a.set(pid);
        // R14-012: custody AT birth (the fix under test).
        let mut _guard = SilentChildGuard::new(pid);
        // R15-004: late-pin while known-ours and alive — BEFORE
        // the explicit retire (a post-retire re-read could pin a
        // squatter's tick).
        if let Ok(Some(tick)) = task_starttime_checked(pid) {
            _guard.pin(tick);
        }
        retire_child_silent(pid);
        observe(pid);
    }));
    // A birth panic stages nothing (slot stays -1 — never
    // waitpid(-1): that would reap ANY sibling child).
    if slot_a.get() > 0 {
        assert_pid_free(slot_a.get(), tag);
    }
    assert!(
        observed.is_err(),
        "{tag}: dead-before-read must fail the observation"
    );
    // Case B: later-spawn failure — birth + observation succeed,
    // then a missing-binary spawn panics; the live fixture must
    // still disappear with its status discharged.
    let slot = std::cell::Cell::new(-1);
    let spawned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let pid = birth();
        slot.set(pid);
        // R14-012: custody AT birth (the fix under test).
        let mut _guard = SilentChildGuard::new(pid);
        observe(pid);
        // R15-004: late-pin while known-ours and alive (the
        // injected failure below unwinds through the guard).
        if let Ok(Some(tick)) = task_starttime_checked(pid) {
            _guard.pin(tick);
        }
        // Later-spawn failure (injected): a missing binary.
        // Both arms diverge (the failure must report); the
        // impossible-Ok arm retires first so even it stays
        // clean (and clippy sees the wait).
        match std::process::Command::new("/scopebase-definitely-missing-binary-r14012").spawn() {
            Ok(mut stray) => {
                let _ = stray.kill();
                let _ = stray.wait();
                panic!("later spawn unexpectedly succeeded");
            }
            Err(_) => panic!("injected later-spawn failure"),
        }
    }));
    let pid = slot.get();
    assert!(pid > 0, "{tag}: birth must stage a fixture");
    // Record state, clean best-effort (RED runs stay clean),
    // then assert: disappearance, discharge, and only then the
    // failure report.
    let state = task_starttime_checked(pid);
    retire_child_silent(pid);
    assert_eq!(
        state,
        Ok(None),
        "{tag}: spawn-failure must not leak the fixture"
    );
    assert_pid_free(pid, tag);
    assert!(spawned.is_err(), "{tag}: later-spawn failure must report");
}

/// R14-012: pauser-birth staging custody (driver
/// live/victim/squatter/kids + R14-001 stand-in shape).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn staging_custody_pauser_birth() {
    staging_custody_holds("pauser", fork_pauser, |pid| {
        task_starttime_checked(pid)
            .expect("pauser stat readable")
            .expect("pauser live");
    });
}

/// R14-012: raw-fork-birth staging custody (driver zombie
/// shape — the child _exits at once with the DISTINCT code 17,
/// mirroring R13-007).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn staging_custody_fork_birth() {
    staging_custody_holds(
        "fork",
        || {
            // SAFETY: fork; the child only _exits.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                unsafe { libc::_exit(17) };
            }
            pid
        },
        |pid| {
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                let row =
                    std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("zombie stat");
                let state = row
                    .rsplit_once(") ")
                    .and_then(|(_, after)| after.split_whitespace().next());
                if state == Some("Z") {
                    break;
                }
                assert!(Instant::now() < end, "child never zombied");
                std::thread::sleep(Duration::from_millis(1));
            }
            task_starttime_checked(pid)
                .expect("zombie stat readable")
                .expect("zombie present");
        },
    );
}

/// R14-012: self-grouped-command-birth staging custody
/// (decision ours-885 shape). Duration 73 is unique to this
/// test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn staging_custody_grouped_command_birth() {
    use std::os::unix::process::CommandExt as _;
    staging_custody_holds(
        "grouped",
        || {
            let mut ours = std::process::Command::new("/bin/sleep");
            ours.arg("73")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            // SAFETY: setpgid on self pre-exec, no userspace state.
            unsafe {
                ours.pre_exec(|| {
                    libc::setpgid(0, 0);
                    Ok(())
                });
            }
            ours.spawn().expect("grouped spawns").id() as i32
        },
        |pid| {
            task_starttime_checked(pid)
                .expect("grouped stat readable")
                .expect("grouped visible");
        },
    );
}

/// R14-012: plain-command-birth staging custody (decision
/// plain-886 + R14-001 fixture-890 shape). Duration 74 is unique
/// to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn staging_custody_plain_command_birth() {
    staging_custody_holds(
        "plain",
        || {
            std::process::Command::new("/bin/sleep")
                .arg("74")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("plain spawns")
                .id() as i32
        },
        |pid| {
            task_starttime_checked(pid)
                .expect("plain stat readable")
                .expect("plain visible");
        },
    );
}

/// R14-012 pin: a guard over an already-gone number (birth
/// read fails → unpinned) drops silently — IR-002: the waitpid
/// probe ECHILDs first and no kill ever fires. Pins the None
/// arm (the drivers above pin the tick-gated arm).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn unpinned_guard_over_gone_number_is_silent_noop() {
    // R12-002: serialize against steerers (whole-test hold).
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let pid = fork_pauser();
    kill_wait_child(pid);
    {
        let _guard = SilentChildGuard::new(pid);
    }
    assert_pid_free(pid, "gone-number");
}

/// IR-002: the toolchain twin of the audit probe-first test —
/// a live NON-child (a grandchild parented to `sh`, never
/// ours, so our waitpid ECHILDs) retired through
/// `retire_child_silent` must survive. Pre-fix the kill fires
/// before the waitpid that would have ECHILDed (RED: the
/// stranger is murdered); post-fix the waitpid probe comes
/// first (GREEN). The verdict reads /proc STATE settled,
/// never the tick (a zombie keeps its tick). Duration 58 is
/// unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn retire_child_silent_probe_first_spares_live_non_child() {
    use std::io::BufRead as _;
    // R12-002: serialize steerers (whole-test hold).
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut parent = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("sleep 58 & echo $!; wait")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("sh parent spawns");
    let mut line = String::new();
    std::io::BufReader::new(parent.stdout.take().expect("sh stdout"))
        .read_line(&mut line)
        .expect("grandchild pid readable");
    let stranger = line.trim().parse::<i32>().expect("pid parses");
    let stick = task_starttime_checked(stranger)
        .expect("stranger stat readable")
        .expect("stranger present");
    // Sanity: live, and not our child (the probe the fix
    // relies on).
    assert!(
        matches!(task_state(stranger), Some(state) if state != 'Z'),
        "staged stranger must be live"
    );
    {
        let mut status = 0;
        // SAFETY: WNOHANG probe only.
        let got = unsafe { libc::waitpid(stranger, &mut status, libc::WNOHANG) };
        assert!(got < 0, "staged stranger must not be our child");
    }
    retire_child_silent(stranger);
    // Verdict by /proc STATE, settled: a tick check cannot
    // tell live from zombie, and SIGKILL delivery is async —
    // poll until the stranger zombifies/vanishes (murdered) or
    // stays live past the settle window (spared).
    let end = Instant::now() + Duration::from_secs(2);
    let mut survived = true;
    loop {
        match task_state(stranger) {
            Some(state) if state != 'Z' => {
                if Instant::now() >= end {
                    break;
                }
            }
            _ => {
                survived = false;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // Cleanup (runs on RED too): kill our staged task by
    // number + tick, poll it gone, then reap the sh parent
    // (its `wait` ends with the grandchild). R15-003:
    // tick-gated (on RED paths sh may have reaped the
    // stranger already — a blind kill would murder a
    // recycled replacement).
    let _ = kill_tick_gated(stranger, stick);
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if task_starttime_checked(stranger) != Ok(Some(stick)) {
            break;
        }
        assert!(Instant::now() < end, "staged stranger must die");
        std::thread::sleep(Duration::from_millis(10));
    }
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if parent.try_wait().expect("parent wait").is_some() {
            break;
        }
        assert!(Instant::now() < end, "sh parent must exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(survived, "silent retire must not murder a live non-child");
}

/// R14-001: a Drop guard must never signal a recycled number.
/// The fixture is retired explicitly (kill+reap, number free),
/// then a steered stand-in retakes the number at a different
/// tick; dropping the guard must spare the stand-in. Pre-fix
/// the guard kills blind (RED: the stand-in is murdered — the
/// full-suite flake that SIGKILLs siblings' sleep fixtures);
/// post-fix the tick gate skips (GREEN). Duration 890 is
/// unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn drop_guard_spares_recycled_number() {
    // R12-002: serialize steerers (whole-test hold).
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let last_path = "/proc/sys/kernel/ns_last_pid";
    let last_before = match std::fs::read_to_string(last_path) {
        Ok(text) => text.trim().to_string(),
        Err(_) => {
            eprintln!("skip: ns_last_pid unreadable (no reuse control)");
            return;
        }
    };
    if !locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
        eprintln!("skip: ns_last_pid unwritable (no reuse control)");
        return;
    }
    let mut fixture = std::process::Command::new("/bin/sleep")
        .arg("890")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("fixture spawns");
    let owned = fixture.id() as i32;
    // R14-012: custody AT birth (auto-pins the tick the stale
    // drop below deliberately holds).
    let mut guard = SilentChildGuard::new(owned);
    let owned_tick = task_starttime_checked(owned)
        .expect("fixture stat readable")
        .expect("fixture visible");
    // R15-004: late-pin the live identity just observed — if
    // construction raced a transient read failure (None), the
    // stale drop below would murder the replacement it cannot
    // distinguish; the pin converts it to a gated drop. A
    // normally-constructed guard already holds this tick
    // (no-op).
    guard.pin(owned_tick);
    // Explicit loud retire (the R13-003/R13-008 tail shape):
    // from here the number is free and the guard is stale.
    // SAFETY: retiring our own fixture.
    unsafe {
        libc::kill(owned, libc::SIGKILL);
    }
    let _ = fixture.wait();
    std::thread::sleep(Duration::from_millis(50));
    let _nsflock = ns_last_pid_flock();
    let mut standin = -1;
    // R14-012: the placed stand-in takes custody AT placement.
    let mut standin_guard: Option<SilentChildGuard> = None;
    for _ in 0..100 {
        if !steer_next_pid_unlocked(owned) {
            break;
        }
        let kid = fork_pauser();
        if kid == owned {
            standin = kid;
            standin_guard = Some(SilentChildGuard::new(kid));
            break;
        }
        let mut kid_guard = SilentChildGuard::new(kid);
        kill_wait_child(kid);
        kid_guard.disarm();
    }
    drop(_nsflock);
    locked_restore_hint(&last_before);
    if standin != owned {
        eprintln!("skip: fixture number not retaken (contended)");
        return;
    }
    // R14-012: placed (the contended exit returned above), so
    // the loop armed the guard — unwrap it for the disarms
    // below.
    let mut standin_guard = standin_guard.expect("placed stand-in guarded");
    let standin_tick = task_starttime_checked(owned)
        .expect("stand-in stat readable")
        .expect("stand-in visible");
    // R15-004: late-pin the stand-in's live tick.
    standin_guard.pin(standin_tick);
    if standin_tick == owned_tick {
        kill_wait_child(owned);
        standin_guard.disarm();
        eprintln!("skip: same-tick retake (S100 — untestable this run)");
        return;
    }
    drop(guard);
    // The stand-in (a pauser: never exits by itself) must
    // survive the stale guard drop — then loud cleanup.
    assert_eq!(
        task_starttime_checked(owned),
        Ok(Some(standin_tick)),
        "stale guard drop must spare the recycled holder"
    );
    kill_wait_child(owned);
    standin_guard.disarm();
}

/// R15-004: a late pin converts an unpinned guard into a gated
/// drop. The guard is constructed over a gone number (initial
/// read fails persistently-None — the deterministic stand-in
/// for a transient construction blip the retry did not
/// outlast); a first replacement is steered on and late-pinned;
/// a second replacement retakes the number; dropping the guard
/// must spare it (the stale pin mismatches and skips), while an
/// unpinned drop would murder it (waitpid-0 → kill). Pre-fix
/// (no pin API) the only available drop murders (RED, proven by
/// running the same staging with the pin call removed during
/// development); post-fix the replacement survives (GREEN). A
/// literal transient-EMFILE staging is infeasible in-process
/// (fd exhaustion is process-global); transient healing is
/// covered by the scripted unit test above.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn late_pin_spares_second_replacement() {
    // R12-002: serialize steerers (whole-test hold).
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let last_path = "/proc/sys/kernel/ns_last_pid";
    let last_before = match std::fs::read_to_string(last_path) {
        Ok(text) => text.trim().to_string(),
        Err(_) => {
            eprintln!("skip: ns_last_pid unreadable (no reuse control)");
            return;
        }
    };
    if !locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
        eprintln!("skip: ns_last_pid unwritable (no reuse control)");
        return;
    }
    let seed = fork_pauser();
    kill_wait_child(seed);
    // Guard over the gone number: initial read fails → None.
    let mut guard = SilentChildGuard::new(seed);
    // First replacement, steered on and late-pinned.
    std::thread::sleep(Duration::from_millis(50));
    if steer_pauser_onto(seed, &last_before).is_none() {
        eprintln!("skip: first retake contended");
        return;
    }
    let first_tick = task_starttime_checked(seed)
        .expect("first stat readable")
        .expect("first visible");
    guard.pin(first_tick);
    // Second replacement retakes the number.
    kill_wait_child(seed);
    std::thread::sleep(Duration::from_millis(50));
    if steer_pauser_onto(seed, &last_before).is_none() {
        eprintln!("skip: second retake contended");
        return;
    }
    let second_tick = task_starttime_checked(seed)
        .expect("second stat readable")
        .expect("second visible");
    if second_tick == first_tick {
        kill_wait_child(seed);
        eprintln!("skip: same-tick retake (S100 — untestable this run)");
        return;
    }
    drop(guard);
    assert_eq!(
        task_starttime_checked(seed),
        Ok(Some(second_tick)),
        "late-pinned drop must spare the second replacement"
    );
    assert!(
        matches!(task_state(seed), Some(state) if state != 'Z'),
        "survivor must be live, not a zombie"
    );
    kill_wait_child(seed);
}

/// R15-005: run one probe mode in a FRESH process image (the
/// test binary re-executed with SCOPEBASE_R15005_MODE set): fd
/// exhaustion stays contained in the child, and the parent only
/// reads its stderr. Returns the child's stderr after asserting
/// a clean exit plus the completion marker (a filter miss or
/// harness surprise fails loud, never vacuous).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn emfile_probe_spawn(mode: &str, test: &str) -> String {
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg(test)
        .arg("--nocapture")
        .env("SCOPEBASE_R15005_MODE", mode)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "{mode}: probe child must exit 0\n{stderr}"
    );
    assert!(
        stderr.contains(&format!("R15005-CHILD-DONE mode={mode}")),
        "{mode}: completion marker missing\n{stderr}"
    );
    stderr
}

/// R15-005: parse a `PREFIX ... pid=N tick=M ...` line from the
/// probe child's stderr (R15005-PINNED or the custody line).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn emfile_probe_tagged(stderr: &str, prefix: &str, mode: &str) -> (i32, u64) {
    for line in stderr.lines() {
        if let Some(rest) = line.strip_prefix(prefix) {
            let mut pid = None;
            let mut tick = None;
            for word in rest.split_whitespace() {
                if let Some(value) = word.strip_prefix("pid=") {
                    pid = value.parse::<i32>().ok();
                }
                if let Some(value) = word.strip_prefix("tick=") {
                    tick = value.parse::<u64>().ok();
                }
            }
            if let (Some(pid), Some(tick)) = (pid, tick) {
                return (pid, tick);
            }
        }
    }
    panic!("{mode}: no parsable `{prefix}` line\n{stderr}");
}

/// R15-005: the probe-child body (runs under
/// SCOPEBASE_R15005_MODE in a fresh image): stage the fixture,
/// pin the guard, print R15005-PINNED, exhaust fds, drop the
/// guard through a panicking observation, then verify per-mode
/// (loud cites identity / silent discharged) and clean up loud.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn emfile_probe_child(mode: &str) {
    use std::io::BufRead as _;
    // Stage the fixture (all fds available here). The stranger
    // mode keeps its sh parent for loud cleanup below.
    let mut sh_parent: Option<std::process::Child> = None;
    let pid = match mode {
        "live" | "gone" | "stolen" => fork_pauser(),
        "zombie" => {
            // SAFETY: fork; the child only _exits (no runtime,
            // no locks).
            let kid = unsafe { libc::fork() };
            if kid == 0 {
                unsafe { libc::_exit(0) };
            }
            assert!(kid > 0, "zombie fork");
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                let row =
                    std::fs::read_to_string(format!("/proc/{kid}/stat")).expect("zombie stat");
                let state = row
                    .rsplit_once(") ")
                    .and_then(|(_, after)| after.split_whitespace().next());
                if state == Some("Z") {
                    break;
                }
                assert!(Instant::now() < end, "child never zombied");
                std::thread::sleep(Duration::from_millis(1));
            }
            kid
        }
        "stranger" => {
            let mut parent = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg("sleep 879 & echo $!; wait")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("sh parent spawns");
            let mut line = String::new();
            std::io::BufReader::new(parent.stdout.take().expect("sh stdout"))
                .read_line(&mut line)
                .expect("grandchild pid readable");
            let stranger = line.trim().parse::<i32>().expect("pid parses");
            assert!(
                matches!(task_state(stranger), Some(state) if state != 'Z'),
                "staged stranger must be live"
            );
            {
                let mut status = 0;
                // SAFETY: WNOHANG probe only.
                let got = unsafe { libc::waitpid(stranger, &mut status, libc::WNOHANG) };
                assert!(got < 0, "staged stranger must not be our child");
            }
            sh_parent = Some(parent);
            stranger
        }
        _ => panic!("unknown probe mode {mode}"),
    };
    // Pin BEFORE any mode-specific pre-step (gone retires
    // pre-exhaust; the pin must cite the live fixture).
    let guard = SilentChildGuard::new(pid);
    let tick = task_starttime_checked(pid)
        .expect("fixture stat readable")
        .expect("fixture present");
    assert_eq!(guard.tick, Some(tick), "constructor must pin the live tick");
    eprintln!("R15005-PINNED pid={pid} tick={tick}");
    // R16-004: retire+reap A (guard stale-armed), steer B onto
    // the number, zombify B unreaped (the sibling-owned zombie
    // the fallback must not reap). BEFORE exhaustion (fork
    // needs fds). Single-threaded probe: no in-process
    // contention, flock-only steering is sound.
    if mode == "stolen" {
        kill_wait_child(pid);
        let last_before =
            std::fs::read_to_string("/proc/sys/kernel/ns_last_pid").unwrap_or_default();
        let sibling = match steer_pauser_onto(pid, last_before.trim()) {
            Some(kid) => kid,
            None => {
                eprintln!("R16004-SKIP stolen (retake contended)");
                eprintln!("R15005-CHILD-DONE mode={mode}");
                return;
            }
        };
        let btick = task_starttime_checked(sibling)
            .expect("sibling stat readable")
            .expect("sibling visible");
        if btick == tick {
            kill_wait_child(sibling);
            eprintln!("R16004-SKIP stolen (same-tick retake S100)");
            eprintln!("R15005-CHILD-DONE mode={mode}");
            return;
        }
        // SAFETY: signal-only to our own staged sibling.
        unsafe {
            libc::kill(sibling, libc::SIGKILL);
        }
        // Settle into Z BEFORE the drop (bounded poll on task
        // state — never a reaping wait).
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            if matches!(task_state(sibling), Some(state) if state == 'Z') {
                break;
            }
            assert!(Instant::now() < end, "sibling never zombied");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    // Exhaust fds (held, so the loud asserts and cleanup below
    // can restore them).
    let mut held = Vec::new();
    while let Ok(file) = std::fs::File::open("/dev/null") {
        held.push(file);
    }
    assert!(!held.is_empty(), "exhaustion must consume fds");
    // Functional proof of the fallback's precondition: the tick
    // read now FAILS (Err, not None) in every mode.
    assert!(
        task_starttime_checked(pid).is_err(),
        "tick read must fail under exhaustion"
    );
    // Reap UNDER exhaustion (kill+wait are fd-less): the gone
    // number frees µs before the drop, so suite activity almost
    // never recycles it mid-window (any hit is an honest loud
    // skip below, never a flake).
    if mode == "gone" {
        kill_wait_child(pid);
    }
    // The panicking observation: the guard drops DURING unwind
    // (a panicking Drop would abort here — the loud line must
    // use a fallible write, never eprintln!).
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _guard_held = guard;
        panic!("R15005 injected observation failure");
    }));
    assert!(outcome.is_err(), "injection must take");
    // Restore fds for verification and cleanup.
    drop(held);
    match mode {
        "live" => {
            // The fallback never signals: the fixture survives
            // with its pinned identity — then loud cleanup.
            assert_eq!(
                task_starttime_checked(pid),
                Ok(Some(tick)),
                "live fixture must survive the unresolved drop"
            );
            kill_wait_child(pid);
            assert_eq!(task_starttime_checked(pid), Ok(None), "live retired loud");
        }
        "zombie" => {
            // R16-004: the fallback must NOT reap (a sibling's
            // zombie is indistinguishable without the tick
            // read) — it reports loud and the OWNER reaps. Our
            // reap here proves the fallback left the status
            // alone (a theft would show ECHILD).
            let mut status = 0;
            // SAFETY: WNOHANG reap of our own staged zombie.
            let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            assert_eq!(
                got, pid,
                "fallback must not reap the zombie (stolen: {got})"
            );
        }
        "gone" => {
            // A recycled number (suite activity retaking it in
            // the reap→drop window) makes the loud line CORRECT
            // — report the contention so the parent skips loud
            // instead of failing; the occupant is foreign and is
            // never touched.
            if matches!(task_starttime_checked(pid), Ok(Some(_))) {
                eprintln!("R15005-GONE-RECYCLED pid={pid}");
            }
        }
        "stolen" => {
            // R16-004: the sibling's status must be retained
            // (we reap it — a fallback theft would show ECHILD
            // here instead of discharging silently).
            let mut status = 0;
            // SAFETY: WNOHANG reap of our own staged zombie.
            let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            assert_eq!(got, pid, "sibling zombie status stolen by the fallback");
            eprintln!("R16004-STATUS retained pid={pid}");
        }
        "stranger" => {
            assert_eq!(
                task_starttime_checked(pid),
                Ok(Some(tick)),
                "stranger must survive the unresolved drop"
            );
            // Loud cleanup: kill the grandchild, reap sh.
            // SAFETY: signal-only to the staged stranger.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            let mut parent = sh_parent.expect("sh parent staged");
            let end = Instant::now() + Duration::from_secs(10);
            loop {
                if parent.try_wait().expect("parent wait").is_some() {
                    break;
                }
                assert!(Instant::now() < end, "sh parent must exit");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        _ => unreachable!("mode checked above"),
    }
    eprintln!("R15005-CHILD-DONE mode={mode}");
}

/// R15-005: a pinned guard dropped under EMFILE over a LIVE
/// child must emit the identity-preserving custody line.
/// Pre-fix the drop skips silently (RED: no line); post-fix the
/// fd-less waitpid-probe sees live-0 and yells (GREEN).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn emfile_live_drop_reports_unresolved_custody() {
    if let Ok(mode) = std::env::var("SCOPEBASE_R15005_MODE") {
        emfile_probe_child(&mode);
        return;
    }
    let stderr = emfile_probe_spawn("live", "emfile_live_drop_reports_unresolved_custody");
    let pinned = emfile_probe_tagged(&stderr, "R15005-PINNED ", "live");
    let cited = emfile_probe_tagged(&stderr, "scopebase unresolved-custody ", "live");
    assert_eq!(cited, pinned, "custody line must cite the pinned identity");
}

/// R16-004 (contract change from R15-005's silent zombie
/// arm): a pinned guard dropped under EMFILE over a ZOMBIE child
/// reports unresolved custody. The fallback must not reap (a
/// sibling's zombie is indistinguishable without the tick read),
/// so it reports loud and the owner reaps — the probe body
/// proves the status survived for the owner.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn emfile_zombie_drop_reports_unresolved_custody() {
    if let Ok(mode) = std::env::var("SCOPEBASE_R15005_MODE") {
        emfile_probe_child(&mode);
        return;
    }
    let stderr = emfile_probe_spawn("zombie", "emfile_zombie_drop_reports_unresolved_custody");
    let pinned = emfile_probe_tagged(&stderr, "R15005-PINNED ", "zombie");
    let cited = emfile_probe_tagged(&stderr, "scopebase unresolved-custody ", "zombie");
    assert_eq!(cited, pinned, "custody line must cite the pinned identity");
}

/// R16-004: a sibling-owned zombie at the stale number keeps its
/// status (the fallback must not reap it) and the drop reports
/// loud with the pinned identity. Pre-fix the fallback reaps it
/// silently (RED: the probe panics on the stolen status);
/// post-fix the owner reaps (GREEN).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn emfile_stale_drop_spares_sibling_zombie() {
    if let Ok(mode) = std::env::var("SCOPEBASE_R15005_MODE") {
        emfile_probe_child(&mode);
        return;
    }
    let stderr = emfile_probe_spawn("stolen", "emfile_stale_drop_spares_sibling_zombie");
    if stderr.contains("R16004-SKIP") {
        eprintln!("skip: stolen stage contended (see probe stderr)");
        return;
    }
    assert!(
        stderr.contains("R16004-STATUS retained"),
        "sibling zombie status must be retained\n{stderr}"
    );
    let pinned = emfile_probe_tagged(&stderr, "R15005-PINNED ", "stolen");
    let cited = emfile_probe_tagged(&stderr, "scopebase unresolved-custody ", "stolen");
    assert_eq!(cited, pinned, "custody line must cite the pinned identity");
}

/// R15-005: a pinned guard dropped under EMFILE over a GONE
/// number (ECHILD + kill-0 ESRCH) stays silent. Guard role: an
/// always-loud fallback fails here (mutant-checked, not RED —
/// the pre-fix drop is silent too).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn emfile_gone_drop_stays_silent() {
    if let Ok(mode) = std::env::var("SCOPEBASE_R15005_MODE") {
        emfile_probe_child(&mode);
        return;
    }
    let stderr = emfile_probe_spawn("gone", "emfile_gone_drop_stays_silent");
    if stderr.contains("R15005-GONE-RECYCLED") {
        eprintln!("skip: gone number recycled mid-window (contended)");
        return;
    }
    assert!(
        !stderr.contains("unresolved-custody"),
        "gone-number drop must stay silent\n{stderr}"
    );
}

/// R15-005: a pinned guard dropped under EMFILE over a LIVE
/// non-child (ECHILD + kill-0 present — the waitpid cannot see
/// it) must yell: present but unobservable is unresolved, not
/// gone. Pre-fix the drop skips silently (RED: no line).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn emfile_stranger_drop_reports_unresolved_custody() {
    if let Ok(mode) = std::env::var("SCOPEBASE_R15005_MODE") {
        emfile_probe_child(&mode);
        return;
    }
    let stderr = emfile_probe_spawn(
        "stranger",
        "emfile_stranger_drop_reports_unresolved_custody",
    );
    let pinned = emfile_probe_tagged(&stderr, "R15005-PINNED ", "stranger");
    let cited = emfile_probe_tagged(&stderr, "scopebase unresolved-custody ", "stranger");
    assert_eq!(cited, pinned, "custody line must cite the pinned identity");
}

/// R15-004 staging helper: steer a pauser onto `want`,
/// returning its pid on success (mirrors the drop_guard
/// placement loop; misses are retired inline).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn steer_pauser_onto(want: i32, last_before: &str) -> Option<i32> {
    let _nsflock = ns_last_pid_flock();
    let mut placed = None;
    for _ in 0..100 {
        if !steer_next_pid_unlocked(want) {
            break;
        }
        let kid = fork_pauser();
        if kid == want {
            placed = Some(kid);
            break;
        }
        let mut kid_guard = SilentChildGuard::new(kid);
        kill_wait_child(kid);
        kid_guard.disarm();
    }
    drop(_nsflock);
    locked_restore_hint(last_before);
    placed
}

/// R16-008: toolchain twin of the audit `steer_sleep_onto` —
/// steer a fresh `sleep 31` onto `want` (up to 100 tries under
/// the cross-process flock; misses retired inline).
/// `self_grouped` self-groupids the child pre-exec (group
/// reform needs pgid == pid). The allocator hint is restored
/// before returning either way. None when contended or
/// unsteerable (caller skips). Caller holds STEER_SERIAL
/// (in-process half) unless single-threaded (fresh-image
/// probes — documented exemption at the call).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn steer_sleep_onto(want: i32, self_grouped: bool) -> Option<std::process::Child> {
    use std::os::unix::process::CommandExt as _;
    let last_before = std::fs::read_to_string("/proc/sys/kernel/ns_last_pid").unwrap_or_default();
    let found = {
        let _nsflock = ns_last_pid_flock();
        let mut found = None;
        for _ in 0..100 {
            if !steer_next_pid_unlocked(want) {
                break;
            }
            let mut command = std::process::Command::new("/bin/sleep");
            command
                .arg("31")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            if self_grouped {
                // SAFETY: setpgid on self pre-exec, no userspace state.
                unsafe {
                    command.pre_exec(|| {
                        libc::setpgid(0, 0);
                        Ok(())
                    });
                }
            }
            let kid = command.spawn().expect("standin spawns");
            if kid.id() as i32 == want {
                found = Some(kid);
                break;
            }
            let mut miss = kid;
            let _ = miss.kill();
            let _ = miss.wait();
        }
        found
    };
    locked_restore_hint(last_before.trim());
    found
}

/// R15-003: toolchain twin of the audit steered-replacement
/// test — the gated kill must spare a steered different-birth
/// pauser on a released number. Staging mirrors drop_guard
/// above (skips unless steerable); survival via settled
/// live-state (a zombie keeps its tick) plus the unchanged
/// replacement tick. Pre-fix the replacement dies (RED);
/// post-fix it survives (GREEN).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn gated_kill_spares_steered_replacement() {
    // R12-002: serialize steerers (whole-test hold).
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let last_path = "/proc/sys/kernel/ns_last_pid";
    let last_before = match std::fs::read_to_string(last_path) {
        Ok(text) => text.trim().to_string(),
        Err(_) => {
            eprintln!("skip: ns_last_pid unreadable (no reuse control)");
            return;
        }
    };
    if !locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
        eprintln!("skip: ns_last_pid unwritable (no reuse control)");
        return;
    }
    let owned = fork_pauser();
    let owned_tick = task_starttime_checked(owned)
        .expect("fixture stat readable")
        .expect("fixture visible");
    kill_wait_child(owned);
    std::thread::sleep(Duration::from_millis(50));
    let _nsflock = ns_last_pid_flock();
    let mut standin = -1;
    for _ in 0..100 {
        if !steer_next_pid_unlocked(owned) {
            break;
        }
        let kid = fork_pauser();
        if kid == owned {
            standin = kid;
            break;
        }
        let mut kid_guard = SilentChildGuard::new(kid);
        kill_wait_child(kid);
        kid_guard.disarm();
    }
    drop(_nsflock);
    locked_restore_hint(&last_before);
    if standin != owned {
        eprintln!("skip: fixture number not retaken (contended)");
        return;
    }
    let standin_tick = task_starttime_checked(owned)
        .expect("stand-in stat readable")
        .expect("stand-in visible");
    if standin_tick == owned_tick {
        kill_wait_child(owned);
        eprintln!("skip: same-tick retake (S100 — untestable this run)");
        return;
    }
    assert!(
        kill_tick_gated(owned, owned_tick),
        "gated kill skips a recycled number"
    );
    // Settled live-state survival (pausers never exit by
    // themselves; a tick check alone would pass on a zombie).
    let end = Instant::now() + Duration::from_secs(2);
    loop {
        match task_state(owned) {
            Some(state) if state != 'Z' => {
                if Instant::now() >= end {
                    break;
                }
            }
            _ => panic!("replacement must survive gated kill (murdered)"),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        task_starttime_checked(owned),
        Ok(Some(standin_tick)),
        "survivor is the placed replacement, not a second recycle"
    );
    kill_wait_child(owned);
}

/// R15-003 efficacy + decision guard (runs everywhere, no
/// steering): the gated kill must still ACT on matching
/// identity (a gate that never signals would pass the steered
/// test vacuously); wrong-tick and gone numbers skip; the
/// unreadable arm reports false without signaling (injected
/// read). Duration 51 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn gated_kill_acts_on_matching_identity() {
    // R12-002: serialize steerers (whole-test hold).
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Matching identity: signaled, then reaped by the owner.
    let mut staged = std::process::Command::new("/bin/sleep")
        .arg("51")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("staged spawns");
    let spid = staged.id() as i32;
    let stick = task_starttime_checked(spid)
        .expect("staged stat readable")
        .expect("staged visible");
    assert!(
        kill_tick_gated(spid, stick),
        "gated kill acts on matching identity"
    );
    // Reap-then-assert (a zombie keeps its tick).
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if staged.try_wait().expect("staged wait works").is_some() {
            break;
        }
        assert!(Instant::now() < end, "signaled task must die");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        task_starttime_checked(spid),
        Ok(None),
        "signaled task reaped gone"
    );
    // Wrong tick on a live task: spared.
    let mut stranger = std::process::Command::new("/bin/sleep")
        .arg("51")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("stranger spawns");
    let xpid = stranger.id() as i32;
    let xtick = task_starttime_checked(xpid)
        .expect("stranger stat readable")
        .expect("stranger visible");
    let wrong = xtick.wrapping_add(1 << 32);
    assert!(kill_tick_gated(xpid, wrong), "wrong tick skips");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        task_starttime_checked(xpid),
        Ok(Some(xtick)),
        "wrong-tick task must survive"
    );
    assert!(
        matches!(stranger.try_wait(), Ok(None)),
        "wrong-tick owner status retained"
    );
    // SAFETY: retiring our own stranger by verified identity.
    unsafe {
        libc::kill(xpid, libc::SIGKILL);
    }
    let _ = stranger.wait();
    // Gone number: silent no-op.
    let mut gone = std::process::Command::new("/bin/true")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("gone spawns");
    let gpid = gone.id() as i32;
    let _ = gone.wait();
    assert!(
        kill_tick_gated(gpid, u64::MAX),
        "gated kill no-ops a gone number"
    );
    // Injected read: unreadable reports false without
    // signaling; scripted match signals; scripted mismatch
    // skips.
    let mut parked = std::process::Command::new("/bin/sleep")
        .arg("51")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("parked spawns");
    let ppid = parked.id() as i32;
    let ptick = task_starttime_checked(ppid)
        .expect("parked stat readable")
        .expect("parked visible");
    assert!(
        !kill_tick_gated_with(ppid, ptick, |_| Err("injected".to_string())),
        "unreadable stat must report unproven (false)"
    );
    assert_eq!(
        task_starttime_checked(ppid),
        Ok(Some(ptick)),
        "unreadable arm must not signal"
    );
    assert!(
        kill_tick_gated_with(ppid, ptick, |_| Ok(Some(ptick.wrapping_add(1)))),
        "mismatched scripted tick skips"
    );
    assert_eq!(
        task_starttime_checked(ppid),
        Ok(Some(ptick)),
        "mismatched arm must not signal"
    );
    // SAFETY: retiring our own parked task by verified identity.
    unsafe {
        libc::kill(ppid, libc::SIGKILL);
    }
    let _ = parked.wait();
}

/// R15-004: the birth pin retries transient read errors but
/// returns gone immediately (scripted reads — EMFILE blips
/// are not stageable deterministically). A fail,fail,ok
/// script must pin (naive single-read returns None — RED);
/// persistent errors exhaust to None; Ok(None) returns after
/// exactly one read (death is not transient — no retry).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn birth_pin_retries_transient_errors() {
    use std::cell::RefCell;
    let script = RefCell::new(vec![
        Err("blip1".to_string()),
        Err("blip2".to_string()),
        Ok(Some(42u64)),
    ]);
    let calls = RefCell::new(0);
    let read = |_: i32| {
        *calls.borrow_mut() += 1;
        let mut script = script.borrow_mut();
        if script.is_empty() {
            return Ok(Some(42u64));
        }
        script.remove(0)
    };
    assert_eq!(
        pin_birth_tick_with(1, read),
        Some(42),
        "transient blips must heal by retry"
    );
    assert_eq!(*calls.borrow(), 3, "two blips then the pin");
    let persistent = |_: i32| -> Result<Option<u64>, String> { Err("stuck".to_string()) };
    assert_eq!(
        pin_birth_tick_with(1, persistent),
        None,
        "persistent errors exhaust to None"
    );
    let gone_calls = RefCell::new(0);
    let gone = |_: i32| {
        *gone_calls.borrow_mut() += 1;
        Ok(None)
    };
    assert_eq!(pin_birth_tick_with(1, gone), None, "gone pins None");
    assert_eq!(*gone_calls.borrow(), 1, "gone must not retry");
}

/// R13-006: settle P's Child handle after the ancestry run. When
/// the hook acted it raw-reaped P already — NEVER poll the stale
/// handle: on failed placement P's number names a SIBLING's task
/// (possibly an exited zombie), and try_wait would reap the
/// sibling's status into P's handle (ownership theft; the
/// sibling's owner then reaps ECHILD). The pausers-never-exit
/// argument does not cover failed placement — there the holder
/// is not our pauser. When the hook never ran, P is still ours:
/// kill+reap normally.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn settle_probe_after_hook(p: &mut std::process::Child, hook_acted: bool) {
    if hook_acted {
        // The hook raw-reaped P: the handle is stale and P's
        // number may name a sibling — no poll, ever (a stale
        // try_wait would steal a sibling zombie's status into
        // this handle). Dropping the handle reaps nothing.
        return;
    }
    let _ = p.kill();
    let _ = p.wait();
}
/// R13-009: unlocked allocator steer (rename of
/// steer_next_pid). Call ONLY under a held placement guard
/// (placement loops hold it across steer-then-spawn) or via
/// [`locked_steer_next_pid`]. Every other allocator write must
/// take the lock: an unlocked write landing between another
/// process's steer and fork invalidates its placement.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn steer_next_pid_unlocked(want: i32) -> bool {
    use std::process::Stdio;
    let path = "/proc/sys/kernel/ns_last_pid";
    let text = format!("{}", want - 1);
    if std::fs::write(path, &text).is_ok() {
        return true;
    }
    std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("echo {text} | sudo -n tee {path} >/dev/null 2>&1"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// R13-009: allocator steer under the cross-process placement
/// lock (probes and restores — every write outside placement
/// loops). NEVER call under a held guard: same-process POSIX
/// locks merge, so this guard's drop would release the outer's
/// lock (see NEVER NEST on the guard).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn locked_steer_next_pid(want: i32) -> bool {
    let _lock = ns_last_pid_flock();
    steer_next_pid_unlocked(want)
}

/// R13-009: bare hint restore under the cross-process placement
/// lock (same NEVER-NEST rule as [`locked_steer_next_pid`]).
/// Keeps the direct-write-only shape (no sudo fallback — a
/// best-effort hint write, never load-bearing).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn locked_restore_hint(last_before: &str) {
    let _lock = ns_last_pid_flock();
    let _ = std::fs::write("/proc/sys/kernel/ns_last_pid", last_before);
}

/// R13-010: capability pre-check shared by the forced-failure
/// drivers (R12-014, R13-008): steering must be usable or the
/// driver skips (capability absence is explicitly unexecuted —
/// never a failure). Mirrors the children's own gates (readable
/// hint + locked no-op write-back; the locked call is safe here
/// — no guard is ever held at driver top). Returns the skip line
/// when unavailable (forced or natural), None when executable.
/// SCOPEBASE_R13010_FORCE_NOSTEER forces the absent outcome (the
/// meta-driver requires the forced report).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn driver_steering_skip_reason() -> Option<&'static str> {
    if std::env::var("SCOPEBASE_R13010_FORCE_NOSTEER").is_ok() {
        return Some("skip: FORCED unavailable steering (inject)");
    }
    let last_before = match std::fs::read_to_string("/proc/sys/kernel/ns_last_pid") {
        Ok(text) => text.trim().to_string(),
        Err(_) => return Some("skip: ns_last_pid unreadable (no reuse control)"),
    };
    if !locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
        return Some("skip: ns_last_pid unwritable (no reuse control)");
    }
    None
}

/// R11-004: replacing an intermediate parent DURING the
/// ancestry walk must not forge descent. P (our child) parents
/// A (our grandchild); the walk binds P, then the hook
/// kills+reaps P and forces the allocator to hand P's number
/// to a NEW child of the test process. The unchained walk
/// follows the replacement to the test process (TRUE = RED);
/// the starttime-chained walk detects the changed holder
/// (FALSE = GREEN) and the unrelated target survives.
/// Deterministic: the hook pauses the walk mid-traversal (no
/// timing luck); pid-steals retry bounded and loud. Skipped
/// where ns_last_pid is unwritable. Duration 96 is unique to
/// this test. Cleanup precedes every assert (R12-014-proof);
/// verdict, aliveness, and placement are recorded first.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn descendant_walk_survives_intermediate_replacement() {
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    // R12-002: serialize steerers (whole-test hold).
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let last_path = "/proc/sys/kernel/ns_last_pid";
    let last_before = match std::fs::read_to_string(last_path) {
        Ok(text) => text.trim().to_string(),
        Err(_) => {
            eprintln!("skip: ns_last_pid unreadable (no reuse control)");
            return;
        }
    };
    // No-op write-back proves writability without changing
    // allocator state (skips before any fixture exists).
    if !locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
        eprintln!("skip: ns_last_pid unwritable (no reuse control)");
        return;
    }
    let me = std::process::id();
    let mut p = std::process::Command::new("sh")
        .arg("-c")
        .arg("sleep 96 & wait")
        .spawn()
        .expect("P spawns");
    let p_pid = p.id() as i32;
    let a = sole_child_pid(p_pid);
    let pinned_a = match task_starttime_checked(a) {
        Ok(Some(started)) => started,
        other => panic!("A starttime unreadable: {other:?}"),
    };
    // Anti-vacuity: the stable chain genuinely proves descent
    // (so FALSE-after means detection, not a broken fixture).
    assert!(is_test_descendant(a, me), "stable chain must prove descent");
    let acted = AtomicBool::new(false);
    let reused = AtomicI32::new(-1);
    let hook = |bound: i32| {
        if acted.swap(true, Ordering::SeqCst) {
            return;
        }
        assert_eq!(bound, p_pid, "first bind must be P");
        // SAFETY: P is our own child.
        unsafe {
            libc::kill(p_pid, libc::SIGKILL);
        }
        // Reap P (ours): bounded WNOHANG poll.
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let mut status = 0;
            // SAFETY: waitpid on our own child.
            let got = unsafe { libc::waitpid(p_pid, &mut status, libc::WNOHANG) };
            if got == p_pid || got < 0 {
                break;
            }
            assert!(Instant::now() < end, "P unreaped");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Force P's number onto a fork-pauser of ours
        // (microsecond placement — Command::spawn's
        // millisecond window loses steered races; a squatter
        // holding P defeats every retry deterministically,
        // so the test infers skip-vs-broken below instead of
        // asserting here).
        // R12-005: cross-process placement lock.
        let _nsflock = ns_last_pid_flock();
        for _ in 0..100 {
            if !steer_next_pid_unlocked(p_pid) {
                break;
            }
            let kid = fork_pauser();
            if kid == p_pid {
                reused.store(p_pid, Ordering::SeqCst);
                break;
            }
            kill_wait_child(kid);
        }
    };
    let verdict = is_test_descendant_with_hook(a, me, Some(&hook), None);
    // Record before cleanup (R12-014): aliveness proves the
    // verdict is about the replacement, not a dead fixture
    // (the walk never signals — survival is anti-vacuity).
    // SAFETY: kill-0 probes existence only.
    let a_alive = unsafe { libc::kill(a, 0) } == 0;
    // R12-014: pauser birth tick for the retirement proof
    // (read while the kept pauser is provably live; None on
    // placement failure or a sibling's number — only the
    // fault driver consumes it).
    let pauser_tick = match task_starttime_checked(p_pid) {
        Ok(Some(tick)) => Some(tick),
        _ => None,
    };
    // Full cleanup before every assert: P's handle via the
    // R13-006 settler (never polled stale — a squatted P belongs
    // to a sibling!); A (orphaned); the pauser (only when WE kept
    // it); allocator hint.
    settle_probe_after_hook(&mut p, acted.load(Ordering::SeqCst));
    retire_orphan(a, pinned_a);
    if acted.load(Ordering::SeqCst) && reused.load(Ordering::SeqCst) == p_pid {
        kill_wait_child(p_pid);
    }
    // R12-014: restore via steer (sudo fallback), verified
    // by read-back. A bare fs::write NEVER lands here
    // (unprivileged ns_last_pid writes get EPERM). The retry
    // is TIME-bounded (2s), not count-bounded: under a fork
    // burst the test can deschedule between the write and
    // the read, exhausting any fixed attempt count (observed
    // once: 0.88s of placement sniping + restored=false).
    // Past the deadline restored stays false (loud, honest).
    let mut restored = false;
    if let Ok(num) = last_before.parse::<i32>() {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !restored && std::time::Instant::now() < end {
            let _ = locked_steer_next_pid(num + 1);
            restored = std::fs::read_to_string(last_path)
                .map(|text| text.trim() == last_before)
                .unwrap_or(false);
        }
    }
    // R12-014 fault injection (env-gated; inert otherwise):
    // force the bad verdict / hook failure AFTER cleanup so
    // the driver can require retirement+restoration before
    // either failure is reported. Unknown values ignore (the
    // driver requires the R12014 line, so a typo fails loud
    // there, not silent here).
    let forced = std::env::var("SCOPEBASE_R12014_FORCE_FAILURE").ok();
    if forced.is_some() {
        // restored was verified microseconds after the write
        // above (a sibling interleaving in that window is
        // absurd); a driver-side file check would race in
        // milliseconds.
        eprintln!(
            "R12014 p_pid={p_pid} pauser_tick={} a={a} pinned_a={pinned_a} restored={restored}",
            pauser_tick
                .map(|tick| tick.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
    }
    let verdict = if forced.as_deref() == Some("bad-verdict") {
        true
    } else {
        verdict
    };
    if forced.as_deref() == Some("hook-failure") {
        acted.store(false, Ordering::SeqCst);
    }
    // R12-002: placement failed — a squatter holding P skips
    // (contended environment, honestly reported), a free P
    // means steering itself broke (loud).
    if acted.load(Ordering::SeqCst) && reused.load(Ordering::SeqCst) != p_pid {
        match task_starttime_checked(p_pid) {
            Ok(Some(_)) => {
                eprintln!("skip: P={p_pid} squatted by a sibling (contended)");
                return;
            }
            _ => panic!("steering broken: P={p_pid} free but unretaken"),
        }
    }
    assert!(
        acted.load(Ordering::SeqCst),
        "bind hook never fired — fixture broken"
    );
    assert_eq!(
        reused.load(Ordering::SeqCst),
        p_pid,
        "P's number not retaken by our child"
    );
    assert!(
        a_alive,
        "target must survive the walk (died fixture, not detection)"
    );
    assert!(!verdict, "replaced intermediate must not forge descent");
}

/// R12-014: a forced RED run of the intermediate test must
/// retire its fixtures and restore the allocator hint BEFORE
/// reporting failure. Drives the test binary twice
/// (bad-verdict, hook-failure) and requires on each: a
/// failure exit with the right assert message (the report),
/// the R12014 line (cleanup ran first), restored=true
/// (restoration verified pre-report), and tick-gated absence
/// of both fixtures (a recycled number with a different tick
/// is NOT our fixture — same-tick recycle is the accepted
/// R12-005-class residual). Holds STEER_SERIAL across each
/// child run (in-process steering siblings block on the
/// mutex while the child process steers alone).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn intermediate_forced_failure_cleans_before_reporting() {
    use std::os::unix::process::CommandExt as _;
    use std::time::{Duration, Instant};
    // R13-010: capability absence skips (the children would skip
    // before injection — requiring their failure then would fail
    // on setup, not on cleanup-before-reporting).
    if let Some(reason) = driver_steering_skip_reason() {
        eprintln!("{reason}");
        return;
    }
    for (forced, message) in [
        (
            "bad-verdict",
            "replaced intermediate must not forge descent",
        ),
        ("hook-failure", "bind hook never fired"),
    ] {
        // R12-002: serialize steerers (whole-child hold).
        let _steer = STEER_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let exe = std::env::current_exe().expect("probe test binary path");
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("descendant_walk_survives_intermediate_replacement")
            .arg("--exact")
            .arg("--nocapture")
            .env("SCOPEBASE_R12014_FORCE_FAILURE", forced)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // SAFETY: setpgid on self pre-exec, no userspace state.
        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let mut child = cmd.spawn().expect("spawn forced probe");
        // R12-005: pin before any wait (retirement identity gate).
        let staged = task_starttime_checked(child.id() as i32)
            .expect("probe stat readable")
            .expect("probe visible");
        let end = Instant::now() + Duration::from_secs(90);
        let (status, stdout, stderr) = loop {
            if let Some(status) = child.try_wait().expect("probe wait") {
                let (out, err) = drain_exited_child_output(&child);
                break (status, out, err);
            }
            if Instant::now() >= end {
                retire_probe_tree(&mut child, staged);
                panic!("forced probe ({forced}) hung past 90s");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let _ = stdout;
        let stderr_text = String::from_utf8_lossy(&stderr);
        assert!(
            !status.success(),
            "forced probe ({forced}) must fail loud, got {status}: {stderr_text}"
        );
        assert!(
            stderr_text.contains(message),
            "forced probe ({forced}) must report '{message}': {stderr_text}"
        );
        let line = stderr_text
            .lines()
            .find(|l| l.starts_with("R12014 "))
            .unwrap_or_else(|| {
                panic!("forced probe ({forced}) missing R12014 line: {stderr_text}")
            });
        assert!(
            line.contains("restored=true"),
            "forced probe ({forced}) must restore before reporting: {line}"
        );
        let field = |name: &str| -> &str {
            line.split_whitespace()
                .filter_map(|f| f.split_once('='))
                .find(|(key, _)| *key == name)
                .unwrap_or_else(|| panic!("R12014 missing {name}=: {line}"))
                .1
        };
        // A is always ours (pinned-or-panic in the probe): its
        // number must be free or recycled (different tick).
        let a: i32 = field("a").parse().expect("a numeric");
        let pinned_a: u64 = field("pinned_a").parse().expect("pinned_a numeric");
        if let Ok(Some(now)) = task_starttime_checked(a) {
            assert_ne!(now, pinned_a, "fixture A={a} survives (tick {now})");
        }
        // P's holder may be a sibling's (placement can fail
        // while hook-failure still reports): check only when
        // the probe pinned a tick.
        if field("pauser_tick") != "none" {
            let p_pid: i32 = field("p_pid").parse().expect("p_pid numeric");
            let pauser_tick: u64 = field("pauser_tick").parse().expect("pauser_tick numeric");
            if let Ok(Some(now)) = task_starttime_checked(p_pid) {
                assert_ne!(now, pauser_tick, "fixture P={p_pid} survives (tick {now})");
            }
        }
    }
}

/// R12-002: replacing the checked intermediate between the
/// previous-hop binding check and the sandwich sample must
/// not forge descent. Same P/A shape as R11-004, but the
/// replacement lands AFTER the binding check passes (P's
/// number retaken by our child at a DIFFERENT birth tick)
/// and before cursor_before is sampled: the two-read walk
/// validates the replacement's stable life without ever
/// comparing it to the bound (TRUE = RED — false descent
/// that would authorize the target's destruction); the
/// single-sample walk refuses (FALSE = GREEN) while the
/// live target survives. Cleanup precedes every assert
/// (R12-014-proof); verdict, aliveness, and placement are
/// recorded first. Duration 90 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn descendant_walk_survives_check_sample_replacement() {
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
    // R12-002: serialize steerers (whole-test hold).
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let last_path = "/proc/sys/kernel/ns_last_pid";
    let last_before = match std::fs::read_to_string(last_path) {
        Ok(text) => text.trim().to_string(),
        Err(_) => {
            eprintln!("skip: ns_last_pid unreadable (no reuse control)");
            return;
        }
    };
    // No-op write-back proves writability without changing
    // allocator state (skips before any fixture exists).
    if !locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
        eprintln!("skip: ns_last_pid unwritable (no reuse control)");
        return;
    }
    let me = std::process::id();
    let mut p = std::process::Command::new("sh")
        .arg("-c")
        .arg("sleep 90 & wait")
        .spawn()
        .expect("P spawns");
    let p_pid = p.id() as i32;
    let a = sole_child_pid(p_pid);
    let pinned_a = match task_starttime_checked(a) {
        Ok(Some(started)) => started,
        other => panic!("A starttime unreadable: {other:?}"),
    };
    let pinned_p = match task_starttime_checked(p_pid) {
        Ok(Some(started)) => started,
        other => panic!("P starttime unreadable: {other:?}"),
    };
    // Anti-vacuity: the stable chain genuinely proves descent
    // (so FALSE-after means detection, not a broken fixture).
    assert!(is_test_descendant(a, me), "stable chain must prove descent");
    let acted = AtomicBool::new(false);
    let reused = AtomicI32::new(-1);
    let reborn_tick = AtomicU64::new(u64::MAX);
    let check_hook = |checked: i32| {
        if acted.swap(true, Ordering::SeqCst) {
            return;
        }
        assert_eq!(checked, p_pid, "first checked bind must be P");
        // SAFETY: P is our own child.
        unsafe {
            libc::kill(p_pid, libc::SIGKILL);
        }
        // Reap P (ours): bounded WNOHANG poll.
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let mut status = 0;
            // SAFETY: waitpid on our own child.
            let got = unsafe { libc::waitpid(p_pid, &mut status, libc::WNOHANG) };
            if got == p_pid || got < 0 {
                break;
            }
            assert!(Instant::now() < end, "P unreaped");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Force P's number onto a fork-pauser of ours at a
        // DIFFERENT birth tick (a same-tick retake would be
        // indistinguishable from no replacement — S100 —
        // making the verdict vacuous, not wrong). A squatter
        // holding P defeats every retry deterministically, so
        // the test infers skip-vs-broken below instead of
        // asserting here.
        // R12-005: cross-process placement lock.
        let _nsflock = ns_last_pid_flock();
        for _ in 0..100 {
            if !steer_next_pid_unlocked(p_pid) {
                break;
            }
            let kid = fork_pauser();
            if kid != p_pid {
                kill_wait_child(kid);
                continue;
            }
            let tick = match task_starttime_checked(p_pid) {
                Ok(Some(started)) => started,
                _ => {
                    kill_wait_child(kid);
                    continue;
                }
            };
            if tick == pinned_p {
                kill_wait_child(kid);
                continue;
            }
            reused.store(p_pid, Ordering::SeqCst);
            reborn_tick.store(tick, Ordering::SeqCst);
            break;
        }
    };
    let verdict = is_test_descendant_with_hook(a, me, None, Some(&check_hook));
    // Record before cleanup (R12-014): aliveness proves the
    // verdict is about the replacement, not a dead fixture
    // (the walk never signals — survival is anti-vacuity).
    // SAFETY: kill-0 probes existence only.
    let a_alive = unsafe { libc::kill(a, 0) } == 0;
    // Full cleanup before every assert: P's handle via the
    // R13-006 settler (never polled stale); A (orphaned); the
    // pauser; allocator hint.
    settle_probe_after_hook(&mut p, acted.load(Ordering::SeqCst));
    retire_orphan(a, pinned_a);
    if acted.load(Ordering::SeqCst) && reused.load(Ordering::SeqCst) == p_pid {
        kill_wait_child(p_pid);
    }
    locked_restore_hint(&last_before);
    // R12-002: placement failed — a squatter holding P skips
    // (contended environment, honestly reported), a free P
    // means steering itself broke (loud).
    if acted.load(Ordering::SeqCst) && reused.load(Ordering::SeqCst) != p_pid {
        match task_starttime_checked(p_pid) {
            Ok(Some(_)) => {
                eprintln!("skip: P={p_pid} squatted by a sibling (contended)");
                return;
            }
            _ => panic!("steering broken: P={p_pid} free but unretaken"),
        }
    }
    assert!(
        acted.load(Ordering::SeqCst),
        "check hook never fired — fixture broken"
    );
    assert_eq!(
        reused.load(Ordering::SeqCst),
        p_pid,
        "P's number not retaken by our child"
    );
    assert_ne!(
        reborn_tick.load(Ordering::SeqCst),
        pinned_p,
        "replacement must differ in birth tick (else vacuous)"
    );
    assert!(
        a_alive,
        "target must survive the walk (died fixture, not detection)"
    );
    assert!(!verdict, "check-sample replacement must not forge descent");
}

/// R13-006: ancestry cleanup must never poll a raw-reaped
/// handle. Arrange the failed-placement consequence directly: P
/// raw-reaped (as the hook does), then a DIFFERENT-birth,
/// independently-owned zombie steered onto P's number (the
/// squatter the placement loop lost to — NOT our pauser, so the
/// pausers-never-exit argument does not apply). Settling P's
/// handle must leave the sibling's owner able to reap it.
/// Pre-fix the stale try_wait steals the sibling's status (RED:
/// the owner reaps ECHILD); post-fix the owner reaps exit 3.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn ancestry_cleanup_spares_sibling_zombie() {
    // R12-002: serialize steerers (whole-test hold).
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let last_path = "/proc/sys/kernel/ns_last_pid";
    let last_before = match std::fs::read_to_string(last_path) {
        Ok(text) => text.trim().to_string(),
        Err(_) => {
            eprintln!("skip: ns_last_pid unreadable (no reuse control)");
            return;
        }
    };
    // No-op write-back proves writability without changing
    // allocator state (skips before any fixture exists).
    if !locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
        eprintln!("skip: ns_last_pid unwritable (no reuse control)");
        return;
    }
    let mut p = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("P spawns");
    let p_pid = p.id() as i32;
    let pinned_p = match task_starttime_checked(p_pid) {
        Ok(Some(started)) => started,
        other => panic!("P starttime unreadable: {other:?}"),
    };
    // Raw-reap P exactly as the ancestry hook does (kill, then
    // bounded WNOHANG waitpid): from here P's handle is stale
    // and P's number is free.
    // SAFETY: P is our own child.
    unsafe {
        libc::kill(p_pid, libc::SIGKILL);
    }
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        // SAFETY: waitpid on our own child.
        let got = unsafe { libc::waitpid(p_pid, &mut status, libc::WNOHANG) };
        if got == p_pid {
            break;
        }
        if got < 0 {
            panic!("P wait failed mid-reap (status stolen?)");
        }
        assert!(Instant::now() < end, "P unreaped");
        std::thread::sleep(Duration::from_millis(10));
    }
    // The failed-placement squatter: an independently-owned
    // child steered onto P's freed number (mirror the hook's
    // placement loop; misses are reaped at once via their own
    // handles so no zombie lingers). R12-005 cross-process
    // placement lock; nobody else targets OUR freed number, so
    // 100 consecutive misses prove steering broken (loud), not
    // contention.
    let _nsflock = ns_last_pid_flock();
    let mut owner = None;
    for _ in 0..100 {
        if !steer_next_pid_unlocked(p_pid) {
            break;
        }
        let cand = std::process::Command::new("sh")
            .arg("-c")
            .arg("exit 3")
            .spawn()
            .expect("squatter spawns");
        if cand.id() as i32 != p_pid {
            let _ = cand.wait_with_output();
            continue;
        }
        // R14-014: same-tick retakes are rejected (a same-tick
        // zombie could be a P remnant — vacuous, not wrong):
        // reap the squatter and retry (mirrors the check-sample
        // loop above — retries span jiffies, so a different
        // birth lands; the owner below always names a
        // discriminating fixture).
        let placed_tick = match task_starttime_checked(p_pid) {
            Ok(Some(started)) => started,
            _ => {
                let _ = cand.wait_with_output();
                continue;
            }
        };
        if placed_tick == pinned_p {
            let _ = cand.wait_with_output();
            continue;
        }
        owner = Some(cand);
        break;
    }
    let mut owner = match owner {
        Some(owner) => owner,
        None => panic!("steering broken: P={p_pid} free but unretaken"),
    };
    // R13-009: placement done — release the cross-process lock
    // BEFORE any locked_* call below (same-process POSIX locks
    // merge: a nested locked_* drop would release this guard).
    drop(_nsflock);
    // Different birth (the loop above rejects same-tick
    // retakes, so this pins its postcondition), then
    // zombie-state proof with the owner UNTOUCHED (a reap here
    // would be ours, not the settler's).
    let sib_tick = match task_starttime_checked(p_pid) {
        Ok(Some(started)) => started,
        other => panic!("squatter starttime unreadable: {other:?}"),
    };
    assert_ne!(
        sib_tick, pinned_p,
        "squatter must differ in birth tick (else vacuous)"
    );
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let row = std::fs::read_to_string(format!("/proc/{p_pid}/stat"))
            .expect("squatter stat readable while awaited");
        let state = row
            .rsplit_once(") ")
            .and_then(|(_, after)| after.split_whitespace().next());
        if state == Some("Z") {
            break;
        }
        assert!(
            Instant::now() < end,
            "squatter never reached zombie state (state {state:?})"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // The ancestry cleanup under test: settle P's stale handle
    // as if the hook had acted. The sibling's owner must still
    // reap exit 3 — a stale poll would have stolen it (ECHILD).
    settle_probe_after_hook(&mut p, true);
    let status = owner
        .wait()
        .expect("sibling owner must reap its zombie (status stolen?)");
    assert_eq!(
        status.code(),
        Some(3),
        "owner must reap the sibling's exit, got {status:?}"
    );
    // Restore the allocator hint via steer (sudo fallback),
    // verified by read-back (R12-014: time-bounded, loud).
    let mut restored = false;
    if let Ok(num) = last_before.parse::<i32>() {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !restored && std::time::Instant::now() < end {
            let _ = locked_steer_next_pid(num + 1);
            restored = std::fs::read_to_string(last_path)
                .map(|text| text.trim() == last_before)
                .unwrap_or(false);
        }
    }
    assert!(restored, "allocator hint must restore after steering");
}

/// R13-009: allocator-lock probe child (see
/// [`allocator_steer_excluded_during_placement`] and
/// [`allocator_restore_excluded_during_placement`]). Under a
/// normal suite run (no rendezvous) this passes silently; the
/// driver spawns a FRESH test-binary process at this exact path
/// with the rendezvous set. The probe reads the current hint,
/// signals READY (it stands AT its locked call), then performs
/// ONE out-of-loop allocator write path selected by
/// SCOPEBASE_R13009_PATHS (`steer` or `restore` — a no-op, so
/// the hint is undisturbed) and reports DONE. While the driver
/// holds the lock, the probe must BLOCK at its locked call
/// (post-fix) or sail through (pre-fix RED). Writability is
/// irrelevant here (only exclusion is measured), so steering
/// failures never fail this probe. R14-015: one path per probe
/// run — a combined probe would block at the FIRST path and
/// never prove the second's lock (an unlocked restore after a
/// locked steer sails through invisibly).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn allocator_lock_probe() {
    let ready_path = match std::env::var("SCOPEBASE_R13009_READY") {
        Ok(path) => path,
        Err(_) => return,
    };
    let paths = std::env::var("SCOPEBASE_R13009_PATHS").expect("probe paths selector set");
    let current =
        std::fs::read_to_string("/proc/sys/kernel/ns_last_pid").expect("probe reads current hint");
    let current = current.trim().to_string();
    std::fs::write(&ready_path, "ready").expect("probe signals ready");
    // One out-of-loop allocator write path, as a no-op (the
    // hint value is preserved — the probe disturbs nothing).
    match paths.as_str() {
        "steer" => {
            let _ = locked_steer_next_pid(current.parse::<i32>().unwrap_or(0) + 1);
        }
        "restore" => locked_restore_hint(&current),
        other => panic!("unknown probe paths selector: {other}"),
    }
    eprintln!("R13009 DONE");
}

/// R13-009: one out-of-loop allocator write path must take the
/// cross-process placement lock. The driver holds the lock and
/// spawns the probe child: the child must BLOCK at its locked
/// call (still running 2s after READY) and complete only after
/// the release (exit 0 + DONE). Pre-fix the unlocked path sails
/// through (RED: child exits while held). The lock is
/// blocking-absolute, so the verdict has no timing flakes — the
/// windows only bound how long we observe. Holds STEER_SERIAL
/// across the child run (in-process steering siblings block
/// while this exclusion is measured). R14-015: driven once per
/// write path (steer-only, restore-only) — each path's lock is
/// proven independently.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn allocator_path_excluded_during_placement(paths: &str) {
    use std::time::{Duration, Instant};
    // R12-002: serialize steerers (whole-child hold).
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Hold the cross-process lock BEFORE spawning: the child's
    // locked calls must block on THIS hold.
    let placement_lock = ns_last_pid_flock();
    let ready = std::env::temp_dir().join(format!(
        "scopebase-r13009-ready-{paths}-{}.pid",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&ready);
    let exe = std::env::current_exe().expect("probe test binary path");
    let mut child = std::process::Command::new(exe)
        .arg("allocator_lock_probe")
        .arg("--exact")
        .arg("--nocapture")
        .env("SCOPEBASE_R13009_READY", &ready)
        .env("SCOPEBASE_R13009_PATHS", paths)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn lock probe");
    // R12-005: pin before any wait (retirement identity gate).
    let staged = task_starttime_checked(child.id() as i32)
        .expect("probe stat readable")
        .expect("probe visible");
    // READY rendezvous (10s): the child stands AT its first
    // locked call (a child that never arrives is broken, loud —
    // never a vacuous pass).
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if ready.exists() {
            break;
        }
        // A child that exits BEFORE ready took no lock path at
        // all (broken probe — loud, never vacuous).
        if let Some(status) = child.try_wait().expect("probe wait") {
            panic!("lock probe exited {status} before READY (probe broken?)");
        }
        assert!(
            Instant::now() < end,
            "lock probe never reached its lock attempt"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // Exclusion window: 2s during which the locked child MUST
    // still run (post-fix: blocked in F_SETLKW; pre-fix RED: it
    // already exited — the {paths} path sailed through unlocked).
    std::thread::sleep(Duration::from_secs(2));
    if let Some(status) = child.try_wait().expect("probe wait") {
        panic!(
            "probe completed while the placement lock was held (status {status}) — \
             out-of-loop allocator {paths} bypasses the lock (RED)"
        );
    }
    // Release: the blocked child must now complete promptly.
    drop(placement_lock);
    let end = Instant::now() + Duration::from_secs(10);
    let (status, stderr) = loop {
        if let Some(status) = child.try_wait().expect("probe wait") {
            let (_, err) = drain_exited_child_output(&child);
            break (status, err);
        }
        if Instant::now() >= end {
            retire_probe_tree(&mut child, staged);
            panic!("lock probe ({paths}) hung past release (deadlock?)");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = std::fs::remove_file(&ready);
    assert!(
        status.success(),
        "lock probe ({paths}) must exit success after release, got {status}"
    );
    let stderr_text = String::from_utf8_lossy(&stderr);
    assert!(
        stderr_text.contains("R13009 DONE"),
        "lock probe ({paths}) must run its write path after release: {stderr_text}"
    );
}

/// R14-015: the steer write path takes the placement lock
/// (steer-only control — a lock removal here must fail this
/// test while the restore-only control stays green).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn allocator_steer_excluded_during_placement() {
    allocator_path_excluded_during_placement("steer");
}

/// R14-015: the restore write path takes the placement lock
/// (restore-only control — a lock removal here must fail this
/// test while the steer-only control stays green).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn allocator_restore_excluded_during_placement() {
    allocator_path_excluded_during_placement("restore");
}

/// S128-round9: the pin must be acquired BEFORE custody evidence is
/// gathered. The opener simulates an acquisition-window replacement:
/// it retires the matched stray and returns a pin to a DIFFERENT
/// live task — exactly what exit+recycle between the checks and a
/// late open produces (a pin to the number's new holder while the
/// evidence described the original). A same-number recycle is
/// unconstructible without wrapping the pid space, so the spoofed
/// open is the structural proof: this test fails if the open moves
/// after the checks. Pre-fix the evidence matched the original, the
/// late open lands on the stand-in, and the sweep kills it (RED);
/// post-fix the open precedes the evidence, the evidence observes
/// the freed number, and the stand-in survives. Durations 881/882
/// are unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn hang_sweep_opens_before_evidence() {
    let start_tick = boot_ticks_now().expect("tick reads");
    let mut stray = std::process::Command::new("/bin/sleep")
        .arg("881")
        .spawn()
        .expect("stray spawns");
    let stray_pid = stray.id() as i32;
    let mut standin = std::process::Command::new("/bin/sleep")
        .arg("882")
        .spawn()
        .expect("stand-in spawns");
    let standin_pid = standin.id() as i32;
    let stray_tick = task_starttime_checked(stray_pid)
        .expect("stray stat readable")
        .expect("stray visible");
    let standin_live = task_starttime_checked(standin_pid)
        .expect("stand-in stat readable")
        .expect("stand-in visible");
    // Pin the stand-in up front: the spoofed open hands a dup of
    // this pin over no matter which number it is asked to pin — the
    // observable shape of a late open after a recycle.
    let standin_pin = pidfd_open_task(standin_pid).expect("stand-in pinnable");
    let swept = hang_sweep_with_hooks(
        &[("/bin/sleep", &["881"])],
        Some(start_tick),
        &|pid| {
            if pid == stray_pid {
                // SAFETY: retiring our own stray: kill + REAP so
                // the number is free (not zombie) at evidence time.
                unsafe {
                    libc::kill(stray_pid, libc::SIGKILL);
                }
                let mut status = 0;
                // SAFETY: valid status out-pointer for an owned child.
                unsafe { libc::waitpid(stray_pid, &mut status, 0) };
                // SAFETY: dup of an owned pin; the sweep owns the copy.
                let dup = unsafe { libc::fcntl(standin_pin, libc::F_DUPFD_CLOEXEC, 0) };
                assert!(dup >= 0, "stand-in pin dups");
                return Some(dup);
            }
            pidfd_open_task(pid)
        },
        None,
    );
    // SAFETY: pin owned by this scope.
    unsafe { libc::close(standin_pin) };
    assert!(
        swept.is_empty(),
        "freed number must be spared, got: {swept:?}"
    );
    assert_eq!(
        task_retired_checked(standin_pid),
        Ok(false),
        "the replacement stand-in must survive the sweep"
    );
    assert_eq!(
        task_starttime_checked(standin_pid),
        Ok(Some(standin_live)),
        "same stand-in, not a replacement"
    );
    // SAFETY: retiring our own stand-in (the stray is already reaped).
    unsafe {
        libc::kill(standin_pid, libc::SIGKILL);
    }
    let _ = standin.wait();
    // R12-003: the opener reaped the stray — reap only while the
    // number still names it (never a recycled holder's status).
    wait_child_unless_reaped(&mut stray, stray_pid, stray_tick);
}

/// S128-round9: a candidate that exits between re-verification and
/// the signal (hook-injected deterministically — no pid race
/// needed) retires quietly through its pin with no signal delivered
/// anywhere. This locks the post-fix window behavior (a numeric
/// signal, or an over-strict ESRCH panic, would fail it); the spoof
/// test above is the RED proving the open precedes the evidence.
/// Durations 883/884 are unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn hang_sweep_window_exit_retires_quietly() {
    let start_tick = boot_ticks_now().expect("tick reads");
    let mut stray = std::process::Command::new("/bin/sleep")
        .arg("883")
        .spawn()
        .expect("stray spawns");
    let stray_pid = stray.id() as i32;
    let stray_tick = task_starttime_checked(stray_pid)
        .expect("stray stat readable")
        .expect("stray visible");
    let mut canary = std::process::Command::new("/bin/sleep")
        .arg("884")
        .spawn()
        .expect("canary spawns");
    let canary_pid = canary.id() as i32;
    let canary_live = task_starttime_checked(canary_pid)
        .expect("canary stat readable")
        .expect("canary visible");
    let swept = hang_sweep_with_hooks(
        &[("/bin/sleep", &["883"])],
        Some(start_tick),
        &pidfd_open_task,
        Some(&|pid| {
            assert_eq!(pid, stray_pid, "hook fires for the matched stray");
            // SAFETY: retiring our own stray: kill + REAP so the
            // number is free (not zombie) at signal time.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            let mut status = 0;
            // SAFETY: valid status out-pointer for an owned child.
            unsafe { libc::waitpid(pid, &mut status, 0) };
        }),
    );
    assert_eq!(
        swept,
        vec![stray_pid as u32],
        "a window exit retires through its pin (ESRCH), still recorded"
    );
    assert_eq!(
        task_retired_checked(canary_pid),
        Ok(false),
        "window exit must signal nothing live"
    );
    assert_eq!(
        task_starttime_checked(canary_pid),
        Ok(Some(canary_live)),
        "same canary, not a replacement"
    );
    // SAFETY: retiring our own canary (the stray is already reaped).
    unsafe {
        libc::kill(canary_pid, libc::SIGKILL);
    }
    let _ = canary.wait();
    // R12-003: the hook reaped the stray — reap only while the
    // number still names it (never a recycled holder's status).
    wait_child_unless_reaped(&mut stray, stray_pid, stray_tick);
}

/// S138-round9: the fixture pipe hides from exec'd children: a
/// concurrently spawned command must not inherit the write end
/// (pre-fix plain `pipe` leaks it and the reader stalls to EOF).
/// Structural (CLOEXEC on both ends) plus behavioral (the exec'd
/// child's /proc fd table names no pipe with our write end's
/// inode — the kernel is the oracle).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn cloexec_pipe_hides_from_exec() {
    let pipe = cloexec_pipe();
    // Structural: both ends carry CLOEXEC.
    for fd in pipe {
        // SAFETY: fcntl read-back on an owned descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(
            flags >= 0 && flags & libc::FD_CLOEXEC != 0,
            "pipe end {fd} must be close-on-exec"
        );
    }
    // Behavioral: an exec'd child inherits neither end.
    let write_ino = {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: valid stat out-pointer for an owned descriptor.
        assert_eq!(unsafe { libc::fstat(pipe[1], &mut stat) }, 0);
        stat.st_ino
    };
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("inheritor probe spawns");
    let child_pid = child.id();
    let wanted = format!("pipe:[{write_ino}]");
    let mut leaked = Vec::new();
    let entries =
        std::fs::read_dir(format!("/proc/{child_pid}/fd")).expect("child fd table readable");
    for entry in entries.flatten() {
        if let Ok(target) = std::fs::read_link(entry.path()) {
            if target.to_string_lossy() == wanted {
                leaked.push(entry.file_name());
            }
        }
    }
    // SAFETY: retiring our own probe.
    unsafe {
        libc::kill(child_pid as i32, libc::SIGKILL);
    }
    let _ = child.wait();
    // SAFETY: ends owned by this scope.
    unsafe {
        libc::close(pipe[0]);
        libc::close(pipe[1]);
    }
    assert!(
        leaked.is_empty(),
        "exec'd child inherited the pipe: {leaked:?}"
    );
}

/// S138-round9: a fork-only inheritor (no exec — CLOEXEC cannot
/// help) holding the report write end must not stall the orphan
/// fixture: the newline-framed bounded read returns on the `pid\n`
/// line. Pre-fix the read waits for EOF until the holder exits
/// (RED: ~25s); post-fix it returns in milliseconds. Duration 94
/// is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn orphan_fixture_survives_concurrent_inheritor() {
    use std::sync::atomic::{AtomicI32, Ordering};
    let holder_pid = AtomicI32::new(-1);
    let start = Instant::now();
    let (pid, pinned) = spawn_orphan_sleeper_with_hook(
        "94",
        Some(&|read_fd, _write_fd| {
            // SAFETY: the holder keeps ONLY the write end open
            // across the orphan report, then exits;
            // async-signal-safe only.
            let holder = unsafe { libc::fork() };
            assert!(holder >= 0, "holder fork failed");
            if holder == 0 {
                unsafe {
                    libc::close(read_fd);
                    let mut remaining = 25u32;
                    while remaining > 0 {
                        remaining = libc::sleep(remaining);
                    }
                    libc::_exit(0);
                }
            }
            holder_pid.store(holder, Ordering::SeqCst);
            holder
        }),
        true,
    );
    let elapsed = start.elapsed();
    // Reap the holder first: it is our child, still sleeping.
    let holder = holder_pid.load(Ordering::SeqCst);
    assert!(holder > 0, "hook must report its holder");
    // SAFETY: retiring our own holder.
    unsafe {
        libc::kill(holder, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(holder, &mut status, 0);
    }
    // R10-013: observe BEFORE retiring, assert AFTER — no
    // assertion (including the elapsed bound on a slow return)
    // may precede orphan retirement, or its panic leaks the
    // 94s sleeper.
    let pinned_now = task_starttime_checked(pid);
    let retired_now = task_retired_checked(pid);
    retire_orphan(pid, pinned);
    assert!(
        elapsed < Duration::from_secs(20),
        "framed read must not wait for the inheritor, took: {elapsed:?}"
    );
    assert_eq!(pinned_now, Ok(Some(pinned)), "orphan pinned");
    assert_eq!(
        retired_now,
        Ok(false),
        "orphan alive after a held write end"
    );
}

/// R10-013: rendezvous — the unframed-expiry probe runs only
/// when set.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
const UNFRAMED_PROBE_ENV: &str = "SCOPEBASE_TT04_UNFRAMED_EXPIRY_PROBE";

/// R10-013: our own open pipe targets (`pipe:[ino]`) beyond
/// stdio, for exact report-descriptor accounting in the confined
/// probe. Fds 0/1/2 are the probe's own stdio pipes (owned by the
/// harness, not the helper) and excluded; a leaked report end
/// would allocate at fd 3+.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn own_pipe_targets() -> Vec<String> {
    let mut pipes = Vec::new();
    let entries = std::fs::read_dir("/proc/self/fd").expect("own fd table readable");
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "0" || name == "1" || name == "2" {
            continue;
        }
        if let Ok(target) = std::fs::read_link(entry.path()) {
            let text = target.to_string_lossy().into_owned();
            if text.starts_with("pipe:[") {
                pipes.push(text);
            }
        }
    }
    pipes.sort();
    pipes
}

/// R10-013: our own open fd count.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn own_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("own fd table readable")
        .flatten()
        .count()
}

/// R11-019: true when no live task in process group `pgid`
/// runs `sleep <duration>` — group-scoped (an unrelated
/// sleeper, or a concurrent probe's same-duration sleeper in
/// another group, must not fail us). Our own sleeper inherits
/// our group (no setsid/setpgid on the middle→sleeper path;
/// execlp preserves it), so a same-group match is
/// unambiguously ours. Membership via /proc/PID/stat pgrp; an
/// unreadable stat (exited mid-scan) skips like an unreadable
/// cmdline.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn no_sleep_duration_in_group(duration: &str, pgid: libc::pid_t) -> bool {
    let want = format!("sleep\0{duration}\0").into_bytes();
    let procs = match std::fs::read_dir("/proc") {
        Ok(dirs) => dirs,
        Err(_) => return false,
    };
    for entry in procs.flatten() {
        let text = entry.file_name().to_string_lossy().into_owned();
        if !text.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Ok(cmdline) = std::fs::read(format!("/proc/{text}/cmdline")) {
            if cmdline == want && task_pgrp_matches(&text, pgid) {
                return false;
            }
        }
    }
    true
}

/// R11-019: true when /proc/`pid`/stat names process group
/// `pgid` (fields after `) `: state ppid PGRP ...). False on
/// any read/parse failure (exited mid-scan — retired or
/// retiring, never a live leak we can still name).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn task_pgrp_matches(pid: &str, pgid: libc::pid_t) -> bool {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let after = match stat.rsplit_once(") ") {
        Some((_, rest)) => rest,
        None => return false,
    };
    match after.split_whitespace().nth(2) {
        Some(pgrp) => pgrp.parse::<libc::pid_t>().is_ok_and(|g| g == pgid),
        None => false,
    }
}

/// R11-019: the group scan DETECTS a same-group sleeper
/// (sensitivity — a broken pgrp parse must not pass
/// silently) and reports clean after it is reaped.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn group_scan_detects_own_sleep() {
    // Duration 9.51: unique to this unit test (sibling tests
    // park their own sleepers in our shared test-binary
    // group; the scan mechanism is duration-agnostic) and
    // fractional (a RED run strands at most seconds, not
    // minutes — retire-before-assert cannot apply here: the
    // sleeper must be alive for the detection assert).
    let mut sleeper = std::process::Command::new("sleep")
        .arg("9.51")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn own sleep 95");
    // SAFETY: getpgrp reads our own group only.
    let our_group = unsafe { libc::getpgrp() };
    assert!(
        !no_sleep_duration_in_group("9.51", our_group),
        "same-group sleep 9.51 must be detected"
    );
    // SAFETY: our own child (kill + blocking reap).
    unsafe {
        libc::kill(sleeper.id() as libc::pid_t, libc::SIGKILL);
    }
    let _ = sleeper.wait();
    assert!(
        no_sleep_duration_in_group("9.51", our_group),
        "reaped sleeper must read clean"
    );
}

/// R11-019: the group scan IGNORES a live sleeper in a
/// foreign group (unit-level specificity — the probe-level
/// regressions prove the end-to-end wiring).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn group_scan_ignores_foreign_group() {
    // Duration 9.52: unique to this unit test (see above).
    let mut sleeper = std::process::Command::new("sleep")
        .arg("9.52")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn sleep 95");
    assert!(
        no_sleep_duration_in_group("9.52", i32::MAX),
        "foreign-group sleep 9.52 must be ignored"
    );
    // SAFETY: our own child (kill + blocking reap).
    unsafe {
        libc::kill(sleeper.id() as libc::pid_t, libc::SIGKILL);
    }
    let _ = sleeper.wait();
}

/// R11-019: the pgrp parser names our own group for self and
/// rejects an impossible one (positive + negative control).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn task_pgrp_matches_self_and_bogus() {
    // SAFETY: getpgrp reads our own group only.
    let our_group = unsafe { libc::getpgrp() };
    let me = std::process::id().to_string();
    assert!(
        task_pgrp_matches(&me, our_group),
        "self must match our own group"
    );
    assert!(
        !task_pgrp_matches(&me, i32::MAX),
        "self must not match an impossible group"
    );
}

/// R11-016(b1): retire-before-assert for the unframed probe's
/// unexpected-Ok path: an Ok identity must be retired (not
/// dropped) and the holder killed — only then may the caller
/// fail loud on the unexpected success. The holder kill runs
/// FIRST and cannot panic, so it holds on every path including
/// a panicking sleeper retirement. On Err (the expected
/// expiry) the helper already retired its owned; the holder
/// kill is belt-and-braces.
/// R12-004: the kill+reap run ONLY while the holder's number
/// still names `holder_tick` — the expiry path reaps the
/// holder, and "already reaped" does not guarantee ESRCH: the
/// number may now name an unrelated task. A freed number skips
/// quietly (the normal post-expiry shape); a live impostor, an
/// unknown tick, or an unresolvable stat skips LOUD (spare,
/// don't hazard). The reap is a bounded WNOHANG poll, never a
/// blocking wait on a recycled lifetime. Contract: `holder` is
/// our own (possibly already reaped) child — never a foreign
/// pid. Residual: a same-tick recycle is still killed+reaped
/// as ours (S100-class exotic).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn retire_unexpected_orphan(
    outcome: &std::thread::Result<(i32, u64)>,
    holder: i32,
    holder_tick: Option<u64>,
) {
    if holder > 0 {
        let ours = match (holder_tick, task_starttime_checked(holder)) {
            (Some(want), Ok(Some(now))) if now == want => true,
            (Some(_), Ok(None)) => false,
            (Some(_), Ok(Some(_))) => {
                eprintln!("holder {holder} recycled under cleanup; skipped");
                false
            }
            (Some(_), Err(error)) => {
                eprintln!("holder {holder} unresolved under cleanup ({error}); skipped");
                false
            }
            (None, _) => {
                eprintln!("holder {holder} tick unknown; skipped (leaks to process exit)");
                false
            }
        };
        if ours {
            // SAFETY: the number still names our holder.
            unsafe {
                libc::kill(holder, libc::SIGKILL);
            }
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                let mut status = 0;
                // SAFETY: WNOHANG reap of our own child.
                let got = unsafe { libc::waitpid(holder, &mut status, libc::WNOHANG) };
                if got == holder || got < 0 {
                    break;
                }
                if Instant::now() >= end {
                    eprintln!("holder {holder} unreaped past 5s; leaking to process exit");
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    if let Ok((pid, pinned)) = outcome {
        retire_orphan(*pid, *pinned);
    }
}

/// R10-013: the framing bad control, confined in a fresh probe
/// process (single-threaded — exact fd accounting is sound
/// here, unlike in the parallel suite binary). WITHOUT the
/// newline-frame break the held write end stalls the orphan
/// report to the 10s bound; the expiry must fail bounded with
/// NO leaks: no holder, no sleeper, no zombie middleman, no
/// report descriptor. Pre-fix the 10s panic unwinds past the
/// pipe close, the middle reap, and the orphan retirement
/// (RED: the 95s sleeper survives); post-fix the expiry path
/// retires everything it owns before failing loud. Duration 95
/// is unique to this test; the leak scan is group-scoped
/// (R11-019), so uniqueness is belt-and-braces, not
/// load-bearing.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn tt04_orphan_unframed_expiry_probe() {
    use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
    if std::env::var(UNFRAMED_PROBE_ENV).is_err() {
        return;
    }
    // SAFETY: setpgid on self, no userspace state.
    unsafe {
        libc::setpgid(0, 0);
    }
    let fds_before = own_fd_count();
    let holder_pid = AtomicI32::new(-1);
    // R12-004: the holder's birth tick, read parent-side the
    // instant it forks (u64::MAX = unreadable — the repeated
    // cleanup then skips rather than killing blind).
    let holder_tick = AtomicU64::new(u64::MAX);
    let start = Instant::now();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        spawn_orphan_sleeper_with_hook(
            "95",
            Some(&|read_fd, _write_fd| {
                // SAFETY: the holder keeps ONLY the write end
                // open 25s, then exits; async-signal-safe only.
                let holder = unsafe { libc::fork() };
                assert!(holder >= 0, "holder fork failed");
                if holder == 0 {
                    unsafe {
                        libc::close(read_fd);
                        let mut remaining = 25u32;
                        while remaining > 0 {
                            remaining = libc::sleep(remaining);
                        }
                        libc::_exit(0);
                    }
                }
                holder_pid.store(holder, Ordering::SeqCst);
                if let Ok(Some(tick)) = task_starttime_checked(holder) {
                    holder_tick.store(tick, Ordering::SeqCst);
                }
                holder
            }),
            false,
        )
    }));
    let elapsed = start.elapsed();
    // The holder is OURS (and, since R11-016, the helper's
    // too — it retires it on expiry): the hook must have
    // reported it (fork failure would otherwise pass
    // vacuously below).
    let holder = holder_pid.load(Ordering::SeqCst);
    assert!(holder > 0, "hook must report its holder");
    if outcome.is_err() {
        // R11-016(a1): the expiry path received the holder
        // through the hook's return and retired it BEFORE
        // failing loud — prove it before our own (belt-and-
        // braces) kill: signal-0 must ESRCH and no zombie may
        // remain for us to reap. (Skipped on Ok: no expiry ran,
        // so the holder is legitimately alive there.) Pre-fix
        // the holder still sleeps here (RED) and our kill
        // below doubles as RED-run hygiene.
        // SAFETY: signal 0 probes existence only.
        assert_eq!(
            unsafe { libc::kill(holder, 0) },
            -1,
            "expiry must have retired the holder"
        );
        // SAFETY: errno location for this thread.
        assert_eq!(
            unsafe { libc::__errno_location().read() },
            libc::ESRCH,
            "holder probe must fail ESRCH-only"
        );
        let mut status = 0;
        // SAFETY: WNOHANG reap probe of our own child.
        assert!(
            unsafe { libc::waitpid(holder, &mut status, libc::WNOHANG) } < 0,
            "expiry must have reaped the holder"
        );
    }
    // R11-016(b1): retire-before-assert — an unexpected Ok
    // identity is retired here (not dropped below) and the
    // holder killed on every path; only then may the success
    // assertion fail loud.
    let tick = holder_tick.load(Ordering::SeqCst);
    retire_unexpected_orphan(
        &outcome,
        holder,
        if tick == u64::MAX { None } else { Some(tick) },
    );
    assert!(outcome.is_err(), "unframed held read must expire");
    assert!(
        elapsed < Duration::from_secs(60),
        "expiry must stay bounded, took {elapsed:?}"
    );
    // No sleeper of OURS: nothing in our process group may
    // run our argv (a foreign sleep 95 — or a concurrent
    // probe's — lives in another group and must not fail us).
    // SAFETY: getpgrp reads our own group only.
    let our_group = unsafe { libc::getpgrp() };
    assert!(
        no_sleep_duration_in_group("95", our_group),
        "orphan sleeper 95 leaked in our process group"
    );
    // No zombie middleman (or anything else of ours): reap
    // stragglers so RED runs stay clean, then require zero.
    let mut stragglers = 0;
    loop {
        let mut status = 0;
        // SAFETY: waitpid(-1) reaps any owned child.
        let got = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if got > 0 {
            stragglers += 1;
            continue;
        }
        if got < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
        }
        break;
    }
    assert_eq!(stragglers, 0, "expiry must leave no zombie middle child");
    // No report descriptor: no pipe ends survive, and the fd
    // count is back at baseline.
    assert!(
        own_pipe_targets().is_empty(),
        "report pipe ends leaked: {:?}",
        own_pipe_targets()
    );
    assert_eq!(
        own_fd_count(),
        fds_before,
        "fd count must return to baseline"
    );
}

/// R11-016(b1): an unexpected Ok identity is retired (not
/// dropped) and the holder killed.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn unexpected_ok_retires_orphan_and_holder() {
    let holder = std::process::Command::new("sleep")
        .arg("98")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn holder")
        .id() as i32;
    let sleeper = std::process::Command::new("sleep")
        .arg("99")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn sleeper")
        .id() as i32;
    let pinned = task_starttime_checked(sleeper)
        .expect("sleeper stat readable")
        .expect("sleeper alive");
    let holder_live = task_starttime_checked(holder)
        .expect("holder stat readable")
        .expect("holder alive");
    retire_unexpected_orphan(&Ok((sleeper, pinned)), holder, Some(holder_live));
    // The holder is reaped by the helper (ECHILD now).
    let mut status = 0;
    // SAFETY: WNOHANG probe of our own child.
    assert!(
        unsafe { libc::waitpid(holder, &mut status, libc::WNOHANG) } < 0,
        "holder must be reaped"
    );
    // The sleeper is retired (zombie-or-gone proves it).
    assert_eq!(
        task_retired_checked(sleeper),
        Ok(true),
        "orphan must be retired"
    );
    // Reap our sleeper zombie (retirement proves
    // disappearance, not the reap).
    // SAFETY: our own dead child.
    assert_eq!(
        unsafe { libc::waitpid(sleeper, &mut status, 0) },
        sleeper,
        "test must reap the sleeper"
    );
}

/// R11-016(b1): on Err the holder is still killed and no
/// sleeper is touched.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn unexpected_ok_skips_sleeper_on_err() {
    let holder = std::process::Command::new("sleep")
        .arg("98")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn holder")
        .id() as i32;
    let other = std::process::Command::new("sleep")
        .arg("99")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn unrelated")
        .id() as i32;
    let err: std::thread::Result<(i32, u64)> =
        Err(Box::new("synthetic expiry") as Box<dyn std::any::Any + Send>);
    let holder_live = task_starttime_checked(holder)
        .expect("holder stat readable")
        .expect("holder alive");
    retire_unexpected_orphan(&err, holder, Some(holder_live));
    // Holder reaped; the unrelated sleeper never addressed.
    let mut status = 0;
    // SAFETY: WNOHANG probe of our own child.
    assert!(
        unsafe { libc::waitpid(holder, &mut status, libc::WNOHANG) } < 0,
        "holder must be reaped"
    );
    let cmdline =
        std::fs::read(format!("/proc/{other}/cmdline")).expect("unrelated cmdline readable");
    assert_eq!(cmdline, b"sleep\x0099\x00");
    let other_start = task_starttime_checked(other)
        .expect("unrelated stat readable")
        .expect("unrelated alive");
    retire_orphan(other, other_start);
    // SAFETY: our own dead child.
    assert_eq!(
        unsafe { libc::waitpid(other, &mut status, 0) },
        other,
        "test must reap the unrelated"
    );
}

/// R12-004: the expiry path retires AND reaps the holder,
/// freeing its number — the repeated cleanup must not send a
/// NUMERIC SIGKILL plus waitpid to that same number. The
/// tick-gated cleanup skips (a live replacement at a different
/// birth tick is none of its business) and the replacement
/// survives for its owner. Pre-fix the kill murders the
/// replacement and the wait steals its status (RED). Durations
/// 889/890 are unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn repeated_holder_cleanup_spares_recycled_number() {
    // R12-002: serialize steerers (whole-test hold).
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let last_path = "/proc/sys/kernel/ns_last_pid";
    let last_before = match std::fs::read_to_string(last_path) {
        Ok(text) => text.trim().to_string(),
        Err(_) => {
            eprintln!("skip: ns_last_pid unreadable (no reuse control)");
            return;
        }
    };
    if !locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
        eprintln!("skip: ns_last_pid unwritable (no reuse control)");
        return;
    }
    let holder = std::process::Command::new("sleep")
        .arg("889")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn holder")
        .id() as i32;
    let holder_tick = task_starttime_checked(holder)
        .expect("holder stat readable")
        .expect("holder alive");
    // Simulate the expiry path: retire AND reap the holder, so
    // its number is free (not zombie) at cleanup time.
    // SAFETY: retiring our own holder.
    unsafe {
        libc::kill(holder, libc::SIGKILL);
    }
    let mut status = 0;
    // SAFETY: blocking reap of our own dead child.
    assert_eq!(
        unsafe { libc::waitpid(holder, &mut status, 0) },
        holder,
        "expiry simulation reaps the holder"
    );
    // Controlled reuse: a LIVE replacement on the holder's
    // number at a DIFFERENT birth tick.
    let mut replacement = None;
    // R12-005: cross-process placement lock (lib tests steer
    // concurrently in another process).
    let _nsflock = ns_last_pid_flock();
    for _ in 0..100 {
        if !steer_next_pid_unlocked(holder) {
            break;
        }
        let mut cand = std::process::Command::new("sleep")
            .arg("890")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("replacement spawns");
        if cand.id() as i32 != holder {
            let _ = cand.kill();
            let _ = cand.wait();
            continue;
        }
        let placed_different = match task_starttime_checked(holder) {
            Ok(Some(tick)) => tick != holder_tick,
            _ => false,
        };
        if !placed_different {
            let _ = cand.kill();
            let _ = cand.wait();
            continue;
        }
        replacement = Some(cand);
        break;
    }
    // R13-009: placement done — release the cross-process lock
    // BEFORE any locked_* call below (same-process POSIX locks
    // merge: a nested locked_* drop would release this guard).
    drop(_nsflock);
    let mut replacement = replacement.expect("replacement placed on holder's number");
    // R12-004: the repeated cleanup, tick-gated (the
    // holder's number now names a live replacement).
    let err: std::thread::Result<(i32, u64)> =
        Err(Box::new("synthetic expiry") as Box<dyn std::any::Any + Send>);
    retire_unexpected_orphan(&err, holder, Some(holder_tick));
    // The replacement must survive the repeated cleanup, and
    // its status must stay with its owner.
    assert_eq!(
        task_retired_checked(holder),
        Ok(false),
        "recycled holder number must survive repeated cleanup"
    );
    // SAFETY: retiring our own live replacement.
    unsafe {
        libc::kill(holder, libc::SIGKILL);
    }
    let status = replacement
        .wait()
        .expect("replacement owner keeps its status");
    assert!(!status.success(), "killed replacement reports signal death");
    locked_restore_hint(&last_before);
}

/// R12-005: settle whether `pid` survived a strike (twin of
/// the audit lib-tests' helper — death is async, so an
/// instant aliveness read after a strike misreads murder as
/// survival, and even the first post-strike sample can show
/// empty-pending-live). Poll the FULL 500ms window: spared
/// only if EVERY sample shows a live task with an empty
/// pending mask (our sleepers receive no other signals).
/// Gone/Z/parse-failure, or any pending at any sample, means
/// struck (false — conservative).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn settle_spared(pid: i32) -> bool {
    let end = Instant::now() + Duration::from_millis(500);
    loop {
        let row = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(row) => row,
            Err(_) => return false,
        };
        let observed = (|| {
            let after = row.rsplit_once(") ")?.1;
            let mut words = after.split_whitespace();
            let state = words.next()?.chars().next()?;
            let pending = words.nth(27)?.parse::<u64>().ok()?;
            Some((state, pending))
        })();
        match observed {
            Some(('Z', _)) | None => return false,
            Some((_, 0)) => {}
            Some((_, _)) => return false,
        }
        if Instant::now() >= end {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// R12-005: reap a self-grouped probe, stage identity
/// reuse on its freed number, then invoke the REPEATED probe
/// retirement. The tick gate skips the direct kill (and the
/// wait) while the group signal still fires for genuinely
/// stranded strays. Pre-fix the blind numeric kill murders
/// the replacement (RED). The replacement's survival is
/// SETTLED (death is async — an instant read misreads a
/// mid-death task as live). Durations 891/892 are unique to
/// this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn repeated_probe_retirement_spares_recycled_number() {
    use std::os::unix::process::CommandExt as _;
    // R12-002: serialize steerers (whole-test hold).
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let last_path = "/proc/sys/kernel/ns_last_pid";
    let last_before = match std::fs::read_to_string(last_path) {
        Ok(text) => text.trim().to_string(),
        Err(_) => {
            eprintln!("skip: ns_last_pid unreadable (no reuse control)");
            return;
        }
    };
    if !locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
        eprintln!("skip: ns_last_pid unwritable (no reuse control)");
        return;
    }
    // The probe: self-grouped (every retire_probe_tree caller
    // self-groups — a test-group probe would make the group
    // signal suite-suicidal).
    let mut probe = std::process::Command::new("/bin/sleep");
    probe
        .arg("891")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: setpgid on self pre-exec, no userspace state.
    unsafe {
        probe.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let mut probe = probe.spawn().expect("probe spawns");
    let id = probe.id() as i32;
    let probe_tick = task_starttime_checked(id)
        .expect("probe stat readable")
        .expect("probe visible");
    // Reap through the handle (the caller shape the finding
    // names: try_wait reaps, THEN retirement runs blind).
    // SAFETY: retiring our own probe.
    unsafe {
        libc::kill(id, libc::SIGKILL);
    }
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = probe.try_wait().expect("probe wait") {
            assert!(!status.success());
            break;
        }
        assert!(Instant::now() < end, "probe never reaped");
        std::thread::sleep(Duration::from_millis(10));
    }
    // Controlled reuse: a LIVE replacement on the probe's
    // number at a DIFFERENT birth tick (same-tick is the
    // exotic accepted residual, not this finding).
    let mut replacement = None;
    {
        // R12-005: cross-process placement lock.
        let _nsflock = ns_last_pid_flock();
        for _ in 0..100 {
            if !steer_next_pid_unlocked(id) {
                break;
            }
            let mut cand = std::process::Command::new("/bin/sleep")
                .arg("892")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("replacement spawns");
            if cand.id() as i32 != id {
                let _ = cand.kill();
                let _ = cand.wait();
                continue;
            }
            let placed_different = match task_starttime_checked(id) {
                Ok(Some(tick)) => tick != probe_tick,
                _ => false,
            };
            if !placed_different {
                let _ = cand.kill();
                let _ = cand.wait();
                continue;
            }
            replacement = Some(cand);
            break;
        }
    }
    let mut replacement = replacement.expect("replacement placed on probe's number");
    let revived_tick = task_starttime_checked(id)
        .expect("replacement stat readable")
        .expect("replacement visible");
    // R12-005: the repeated retirement (tick-gated — the
    // probe's number now names a live replacement, so the
    // direct kill must skip twice).
    retire_probe_tree(&mut probe, probe_tick);
    retire_probe_tree(&mut probe, probe_tick);
    // Observe before cleanup (R12-014): identity now, then
    // SETTLED aliveness, then retire.
    let revived_now = task_starttime_checked(id);
    let revived_spared = settle_spared(id);
    // SAFETY: retiring our own replacement.
    unsafe {
        libc::kill(id, libc::SIGKILL);
    }
    let owned = replacement.wait();
    locked_restore_hint(&last_before);
    assert_eq!(
        revived_now,
        Ok(Some(revived_tick)),
        "recycled probe number keeps its holder"
    );
    assert!(
        revived_spared,
        "recycled probe number must hold a LIVE task (settled)"
    );
    let status = owned.expect("replacement owner keeps its status");
    assert!(!status.success(), "killed replacement reports signal death");
}

/// R13-003: the group signal needs the same identity gate as
/// the direct kill. This test recycles the probe's number into
/// a SELF-GROUPED replacement (pgid == id): repeated
/// retirement must spare it (pre-fix the blind killpg murders
/// it — RED). Survival is SETTLED (a zombie keeps its
/// starttime — the instant tick read passes on a corpse; only
/// the settle catches the kill). The probe number must differ
/// from the test's own group or the test fails closed instead
/// of suite-suiciding. The ungrouped-stray twin lives in
/// `freed_probe_group_still_reaps_strays` (no steering: a live
/// group-mate shifts steered allocation by a fixed +2 here,
/// mechanism unknown, so placement beside one never lands).
/// Durations 893/894 are unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn repeated_group_retirement_spares_grouped_stranger() {
    use std::os::unix::process::CommandExt as _;
    use std::time::{Duration, Instant};
    // R12-002: serialize steerers (whole-test hold).
    let _steer = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let last_path = "/proc/sys/kernel/ns_last_pid";
    let last_before = match std::fs::read_to_string(last_path) {
        Ok(text) => text.trim().to_string(),
        Err(_) => {
            eprintln!("skip: ns_last_pid unreadable (no reuse control)");
            return;
        }
    };
    if !locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
        eprintln!("skip: ns_last_pid unwritable (no reuse control)");
        return;
    }
    // Self-grouped stranger on the probe's number.
    let mut probe = std::process::Command::new("/bin/sleep");
    probe
        .arg("893")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: setpgid on self pre-exec, no userspace state.
    unsafe {
        probe.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let mut probe = probe.spawn().expect("probe spawns");
    let id = probe.id() as i32;
    // SAFETY: getpgid queries only.
    assert_ne!(
        unsafe { libc::getpgid(0) },
        id,
        "probe number must differ from the test group (fail closed)"
    );
    let probe_tick = task_starttime_checked(id)
        .expect("probe stat readable")
        .expect("probe visible");
    // SAFETY: retiring our own probe.
    unsafe {
        libc::kill(id, libc::SIGKILL);
    }
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = probe.try_wait().expect("probe wait") {
            assert!(!status.success());
            break;
        }
        assert!(Instant::now() < end, "probe never reaped");
        std::thread::sleep(Duration::from_millis(10));
    }
    // Controlled reuse: a LIVE SELF-GROUPED replacement on
    // the probe's number at a different birth tick.
    let mut replacement = None;
    {
        // R12-005: cross-process placement lock.
        let _nsflock = ns_last_pid_flock();
        for _ in 0..100 {
            if !steer_next_pid_unlocked(id) {
                break;
            }
            let mut cand = std::process::Command::new("/bin/sleep");
            cand.arg("894")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            // SAFETY: setpgid on self pre-exec, no userspace state.
            unsafe {
                cand.pre_exec(|| {
                    libc::setpgid(0, 0);
                    Ok(())
                });
            }
            let mut cand = cand.spawn().expect("replacement spawns");
            if cand.id() as i32 != id {
                let _ = cand.kill();
                let _ = cand.wait();
                continue;
            }
            let placed_different = match task_starttime_checked(id) {
                Ok(Some(tick)) => tick != probe_tick,
                _ => false,
            };
            // SAFETY: getpgid queries only.
            let placed_grouped = unsafe { libc::getpgid(id) } == id;
            if !placed_different || !placed_grouped {
                let _ = cand.kill();
                let _ = cand.wait();
                continue;
            }
            replacement = Some(cand);
            break;
        }
    }
    let mut replacement = replacement.expect("grouped replacement placed on probe's number");
    let revived_tick = task_starttime_checked(id)
        .expect("replacement stat readable")
        .expect("replacement visible");
    // R13-003: repeated retirement must spare the grouped
    // stranger (pre-fix the blind killpg murders it).
    retire_probe_tree(&mut probe, probe_tick);
    retire_probe_tree(&mut probe, probe_tick);
    // Observe before cleanup (R12-014): identity now, then
    // SETTLED aliveness, then retire.
    let revived_now = task_starttime_checked(id);
    let revived_spared = settle_spared(id);
    // SAFETY: retiring our own replacement.
    unsafe {
        libc::kill(id, libc::SIGKILL);
    }
    let owned = replacement.wait();
    locked_restore_hint(&last_before);
    assert_eq!(
        revived_now,
        Ok(Some(revived_tick)),
        "recycled probe number keeps its holder"
    );
    assert!(
        revived_spared,
        "grouped stranger must survive repeated retirement (settled)"
    );
    let status = owned.expect("replacement owner keeps its status");
    assert!(!status.success(), "killed replacement reports signal death");
}

/// R13-003 positive twin (no steering): a freed probe number
/// with one of OUR strays in the group still fires the group
/// signal — the stray dies by it. Durations 895/897 are unique
/// to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn freed_probe_group_still_reaps_strays() {
    use std::os::unix::process::CommandExt as _;
    use std::time::{Duration, Instant};
    let mut probe = std::process::Command::new("/bin/sleep");
    probe
        .arg("895")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: setpgid on self pre-exec, no userspace state.
    unsafe {
        probe.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let mut probe = probe.spawn().expect("probe spawns");
    let id = probe.id() as i32;
    let probe_tick = task_starttime_checked(id)
        .expect("probe stat readable")
        .expect("probe visible");
    // Our stray joins the probe's group while it is alive.
    let mut stray = std::process::Command::new("/bin/sleep");
    stray
        .arg("897")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: setpgid into our live probe group pre-exec, no
    // userspace state (id copied — 'static satisfied).
    unsafe {
        stray.pre_exec(move || {
            libc::setpgid(0, id);
            Ok(())
        });
    }
    let mut stray = stray.spawn().expect("stray spawns");
    let stray_id = stray.id() as i32;
    // SAFETY: getpgid queries only.
    assert_eq!(
        unsafe { libc::getpgid(stray_id) },
        id,
        "stray must sit in the probe's group"
    );
    // SAFETY: retiring our own probe.
    unsafe {
        libc::kill(id, libc::SIGKILL);
    }
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = probe.try_wait().expect("probe wait") {
            assert!(!status.success());
            break;
        }
        assert!(Instant::now() < end, "probe never reaped");
        std::thread::sleep(Duration::from_millis(10));
    }
    // The number is freed (no recycle): the group signal fires
    // for the stray.
    retire_probe_tree(&mut probe, probe_tick);
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(stray_status) = stray.try_wait().expect("stray wait") {
            assert!(
                !stray_status.success(),
                "stray must die by signal (the group signal got it)"
            );
            break;
        }
        assert!(Instant::now() < end, "stray never died");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// R13-003: `probe_group_kill_allowed` over every plantable
/// state — no steering (each state holds right now). Ours →
/// true; freed → true; live foreign outside the group →
/// true; live foreign self-grouped → false. Panic-safe:
/// both fixtures die with the test. Durations 885/886 are
/// unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn probe_group_kill_decision_states() {
    use std::os::unix::process::CommandExt as _;
    // R14-001: tick-gated disarmable guards (the old local
    // KillOnDrop double-retired: explicit kill_wait below plus
    // an ungated drop, SIGKILLing whoever recycled the number).
    // Ours, live and self-grouped.
    let mut ours = std::process::Command::new("/bin/sleep");
    ours.arg("885")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: setpgid on self pre-exec, no userspace state.
    unsafe {
        ours.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let ours_id = ours.spawn().expect("ours spawns").id() as i32;
    // R14-012: custody AT birth (auto-pins) — the reads below
    // panic safe.
    let mut ours_guard = SilentChildGuard::new(ours_id);
    let ours_tick = task_starttime_checked(ours_id)
        .expect("ours stat readable")
        .expect("ours visible");
    // R15-004: late-pin the observed live tick.
    ours_guard.pin(ours_tick);
    assert!(
        probe_group_kill_allowed(ours_id, ours_tick),
        "ours must allow the group signal"
    );
    // Foreign live OUTSIDE the group: plain child (test group
    // inherited) under a bogus tick.
    let mut plain = std::process::Command::new("/bin/sleep");
    plain
        .arg("886")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let plain_id = plain.spawn().expect("plain spawns").id() as i32;
    // R14-012: custody AT birth (auto-pins) — the reads below
    // panic safe.
    let mut plain_guard = SilentChildGuard::new(plain_id);
    let plain_tick = task_starttime_checked(plain_id)
        .expect("plain stat readable")
        .expect("plain visible");
    // R15-004: late-pin the observed live tick.
    plain_guard.pin(plain_tick);
    // SAFETY: getpgid queries only.
    assert_ne!(
        unsafe { libc::getpgid(plain_id) },
        plain_id,
        "plain child must not self-group"
    );
    assert!(
        probe_group_kill_allowed(plain_id, plain_tick.wrapping_add(1)),
        "ungrouped foreigner must allow the group signal"
    );
    // Foreign live SELF-GROUPED: ours under a bogus tick.
    assert!(
        !probe_group_kill_allowed(ours_id, ours_tick.wrapping_add(1)),
        "grouped stranger must refuse the group signal"
    );
    // Freed: retire ours, then the number names nothing.
    kill_wait_child(ours_id);
    ours_guard.disarm();
    assert!(
        probe_group_kill_allowed(ours_id, ours_tick),
        "freed number must allow the group signal"
    );
    kill_wait_child(plain_id);
    plain_guard.disarm();
}

/// R10-013: drain an exited probe child's piped output WITHOUT
/// waiting for EOF. A RED-run live grandchild (the leaked
/// sleeper) holds the stdio pipes across fork, and
/// `wait_with_output` would stall to the parent timeout instead
/// of reporting the probe's fast failure. All probe bytes
/// precede its exit, so a nonblocking drain after the reap is
/// complete.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn drain_exited_child_output(child: &std::process::Child) -> (Vec<u8>, Vec<u8>) {
    use std::os::unix::io::AsRawFd;
    fn drain(fd: i32) -> Vec<u8> {
        // SAFETY: flag-set + bounded reads on an owned pipe end.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            // SAFETY: bounded read into a stack buffer.
            let got =
                unsafe { libc::read(fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len()) };
            if got > 0 {
                bytes.extend_from_slice(&chunk[..got as usize]);
                continue;
            }
            break;
        }
        bytes
    }
    let out = child
        .stdout
        .as_ref()
        .map(AsRawFd::as_raw_fd)
        .map(drain)
        .unwrap_or_default();
    let err = child
        .stderr
        .as_ref()
        .map(AsRawFd::as_raw_fd)
        .map(drain)
        .unwrap_or_default();
    (out, err)
}

/// IR1 (internal review round 1): best-effort group kill
/// on drop — the 31s sleeper must not outlive a failed
/// assertion by 26s. R14-001: disarms after the group is
/// proven dead (a bare drop would re-signal the pgid number,
/// which a steered stranger may have self-grouped onto).
/// R14-006: the armed drop re-decides through
/// `probe_group_kill_allowed` (a stranger-reformed group is
/// spared even on panic paths).
/// R15-006: constructed via `new` (auto-pins the leader tick;
/// None when the read fails) — guard FIRST, before any
/// fallible staging read, so a staging panic never leaks
/// silently. The unpinned drop retires the leader by
/// waitpid-probe and caveats a possibly-live group (never a
/// blind killpg — the group is unverified without a pin).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct KillGroupOnDrop {
    group: libc::pid_t,
    tick: Option<u64>,
    disarmed: bool,
}

/// R15-006: unpinned-drop loudness decision — silent ONLY when
/// killpg-0 proves the group gone (a nonzero return with
/// ESRCH); any present-or-unknown outcome yells. The leader is
/// discharged first either way, so only the group's fate is in
/// doubt — and doubt is loud (unit-pinned below).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn unpinned_group_drop_loud(killpg_ret: libc::c_int, killpg_errno: libc::c_int) -> bool {
    !(killpg_ret != 0 && killpg_errno == libc::ESRCH)
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl KillGroupOnDrop {
    /// R15-006: guard FIRST — auto-pins the leader's birth tick
    /// (the group number doubles as the self-grouped leader's
    /// pid; 100ms retry per R15-004). None when the read fails:
    /// the drop takes the unpinned fallback (leader retired,
    /// loud caveat, never a blind killpg).
    fn new(group: libc::pid_t) -> Self {
        Self {
            group,
            tick: pin_birth_tick(group),
            disarmed: false,
        }
    }

    /// R16-008: late-pin a recovered tick (mirror of
    /// SilentChildGuard::pin — same caller obligation: only
    /// ticks read while the leader is known-ours and alive,
    /// never a post-retire re-read).
    fn pin(&mut self, tick: u64) {
        self.tick = Some(tick);
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl Drop for KillGroupOnDrop {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        match self.tick {
            Some(tick) => {
                // R14-006: re-decide at drop — after our probe
                // retired, a stranger may have reformed the
                // group (self-grouped onto the freed pgid); fire
                // only while the decision still allows it.
                // R16-007: tri-state (was: gate-bool — the
                // unreadable arm returned silently). Best-effort
                // (never panics).
                match task_starttime_checked(self.group) {
                    Ok(Some(now)) if now == tick => {
                        // Proven ours: kill the group, discharge
                        // the leader (a zombie must not leak to
                        // process exit), verify the group gone
                        // (bounded — members die async).
                        // SAFETY: signal-only to the test's own
                        // group; best-effort (never panics).
                        unsafe {
                            libc::killpg(self.group, libc::SIGKILL);
                        }
                        retire_child_silent(self.group);
                        let end = Instant::now() + Duration::from_secs(5);
                        loop {
                            // SAFETY: signal 0 probes existence only.
                            let probed = unsafe { libc::killpg(self.group, 0) };
                            // SAFETY: errno location for this thread.
                            let errno = unsafe { libc::__errno_location().read() };
                            if probed != 0 && errno == libc::ESRCH {
                                return; // Proven dead: silent.
                            }
                            if Instant::now() >= end {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        // Members survived killpg: loud with the
                        // pinned identity cited.
                        use std::io::Write as _;
                        let _ = writeln!(
                            std::io::stderr(),
                            "scopebase unresolved-group pgid={} tick={tick} members=survived",
                            self.group
                        );
                    }
                    Ok(_) => {
                        // Gone or recycled: nothing of ours — silent.
                    }
                    Err(read_err) => {
                        // R16-007: unreadable (persistent EMFILE)
                        // — no signal without identity (R15-003),
                        // no waitpid without identity (R16-004) —
                        // loud unresolved with the pinned
                        // identity cited (the owner retires
                        // through it post-restore).
                        use std::io::Write as _;
                        let _ = writeln!(
                            std::io::stderr(),
                            "scopebase unresolved-group pgid={} tick={tick} read_err={read_err} leader=unverified",
                            self.group
                        );
                    }
                }
            }
            // R15-006: unpinned (the construction read failed) —
            // retire the leader by waitpid-probe (verified own
            // child or reaped/ECHILD — never a tick gate we
            // don't have), then probe the GROUP: ESRCH-gone
            // discharges silently, anything else yells an
            // actionable caveat (pgid + leader outcome — the
            // owner retires through it). Never killpgs: without
            // a pin the group is unverified (a stranger may have
            // self-grouped onto the number); the staged
            // sleeper's own clock bounds the leak (31s in the
            // canonical stage). R16-008: reachable only when
            // unwind precedes the staged late-pin with
            // persistent failure (a recovered read pins Some) —
            // residual: leader-number recycle by our own fork
            // (R14-001-class, same as the silent-guard None arm).
            None => {
                retire_child_silent(self.group);
                // Re-probe: discharged (reaped/ECHILD) or
                // stuck-live?
                let mut status = 0;
                // SAFETY: WNOHANG probe; never blocks.
                let got = unsafe { libc::waitpid(self.group, &mut status, libc::WNOHANG) };
                let leader = if got == 0 { "live" } else { "discharged" };
                // SAFETY: signal 0 probes existence only.
                let probed = unsafe { libc::killpg(self.group, 0) };
                // SAFETY: errno location for this thread.
                let errno = unsafe { libc::__errno_location().read() };
                if !unpinned_group_drop_loud(probed, errno) {
                    return;
                }
                use std::io::Write as _;
                let _ = writeln!(
                    std::io::stderr(),
                    "scopebase unresolved-group pgid={} tick=none leader={leader}",
                    self.group
                );
            }
        }
    }
}

/// R15-006: unpinned-drop loudness decision matrix — silent
/// ONLY when killpg-0 proves the group gone (ESRCH); any
/// present-or-unknown group yells. The leader outcome is not an
/// input (the leader is discharged first either way).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn unpinned_group_drop_decisions() {
    // ESRCH-proven gone: silent.
    assert!(!unpinned_group_drop_loud(-1, libc::ESRCH));
    // Present (signalable or foreign): loud.
    assert!(unpinned_group_drop_loud(0, 0));
    assert!(unpinned_group_drop_loud(-1, libc::EPERM));
    // Unknown errors: loud (fail-loud direction).
    assert!(unpinned_group_drop_loud(-1, libc::EINVAL));
    assert!(unpinned_group_drop_loud(-1, libc::EINTR));
}

/// R11-016(b2): retiring a failed probe's tree kills the
/// stranded group (not just the exited probe): a child in its
/// own group forks a 31s sleeper and exits 3 at once — the
/// helper must leave the group ESRCH-dead (far ahead of the
/// sleeper's own clock) and preserve the observed status.
/// Idempotent: a second call over the empty group is a silent
/// no-op (ESRCH/ECHILD, never a hang).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn probe_tree_retirement_kills_stranded_group() {
    use std::os::unix::process::CommandExt as _;
    let mut child = std::process::Command::new("/bin/sh");
    child
        .arg("-c")
        .arg("sleep 31 & exit 3")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // SAFETY: setpgid on self pre-exec, no userspace state
    // (the probes group themselves the same way on entry).
    unsafe {
        child.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let mut child = child.spawn().expect("spawn failing stage");
    let group = child.id() as libc::pid_t;
    // R15-006: fault injection — exhaust fds BEFORE any read so
    // the staging reads fail (the read-failure probe runs this
    // body in a fresh image and requires retirement-before-
    // report). Declared BEFORE the guard: unwind drops the guard
    // first (still exhausted), restoring fds only after.
    let mut _emfile_held = Vec::new();
    if std::env::var("SCOPEBASE_R15006_EMFILE").is_ok() {
        while let Ok(file) = std::fs::File::open("/dev/null") {
            _emfile_held.push(file);
        }
    }
    // IR1: the 31s sleeper dies with the test on every path
    // (failed asserts unwind through this guard).
    // R14-012: custody BEFORE the wait+asserts (a staging panic
    // must still retire the group; disarmed once proven dead).
    // R15-006: guard FIRST (auto-pins; a raced/absent read leaves
    // None for the unpinned fallback — the tick read below must
    // never precede custody).
    let mut guard = KillGroupOnDrop::new(group);
    // R12-005: pin before any wait (retirement identity gate).
    let staged = task_starttime_checked(child.id() as i32)
        .expect("stage stat readable")
        .expect("stage visible");
    // R16-008: late-pin the recovered tick (construction may
    // have failed while this read succeeded — without it the
    // drop takes the unpinned fallback against a possibly
    // reformed number).
    guard.pin(staged);
    let status = child.wait().expect("stage exit");
    assert!(!status.success());
    assert_eq!(status.code(), Some(3));
    retire_probe_tree(&mut child, staged);
    retire_probe_tree(&mut child, staged);
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        // SAFETY: signal 0 probes existence only.
        if unsafe { libc::killpg(group, 0) } < 0 {
            // SAFETY: errno location for this thread.
            let errno = unsafe { libc::__errno_location().read() };
            assert_eq!(
                errno,
                libc::ESRCH,
                "group probe must fail ESRCH-only, got {errno}"
            );
            guard.disarm();
            return;
        }
        assert!(
            Instant::now() < end,
            "stranded group {group} survived retirement"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// R15-006: inject the initial read failure (EMFILE before any
/// read) into the REAL stranded-group stage and require
/// retirement-before-report: the staging panic must name the
/// read site, the unpinned drop must discharge the shell leader
/// and caveat the possibly-live group (never a blind killpg),
/// and the caveat's pgid must be actionable (the parent retires
/// the group through it — no leak even on this path). Pre-fix
/// the read-first order panics with no guard and no caveat
/// (RED); post-fix the guard-first order yells (GREEN).
/// RED runs strand a 31s sleeper + shell zombie — the leak
/// under test, cleaned on GREEN runs via the caveat.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn stranded_group_read_failure_retires_before_report() {
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("probe_tree_retirement_kills_stranded_group")
        .arg("--nocapture")
        .env("SCOPEBASE_R15006_EMFILE", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    // Fail-safe: a filter miss exits 0 — the staging panic must
    // fail the child.
    assert!(
        !out.status.success(),
        "child must fail at the staging read\n{stderr}"
    );
    assert!(
        stderr.contains("stage stat readable"),
        "panic must name the read site\n{stderr}"
    );
    // The caveat cites the group + leader outcome; parse the
    // pgid for the functional cleanup below.
    let mut pgid = None;
    let mut leader_discharged = false;
    for line in stderr.lines() {
        if let Some(rest) = line.strip_prefix("scopebase unresolved-group ") {
            for word in rest.split_whitespace() {
                if let Some(value) = word.strip_prefix("pgid=") {
                    pgid = value.parse::<i32>().ok();
                }
                if word == "leader=discharged" {
                    leader_discharged = true;
                }
            }
        }
    }
    let pgid = pgid.expect("caveat must cite the pgid");
    assert!(
        leader_discharged,
        "leader must discharge before report\n{stderr}"
    );
    // The group is still alive here (the fallback never killpgs
    // blind) — then retire it THROUGH the caveat.
    // SAFETY: signal 0 probes existence only.
    assert_eq!(
        unsafe { libc::killpg(pgid, 0) },
        0,
        "stranded group must outlive the unresolved drop\n{stderr}"
    );
    // SAFETY: signal-only to the staged group whose pgid the
    // caveat cited (its sleeper is ours — alive from the caveat
    // through the probe above, so the number cannot have
    // recycled).
    unsafe {
        libc::killpg(pgid, libc::SIGKILL);
    }
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        // SAFETY: signal 0 probes existence only.
        if unsafe { libc::killpg(pgid, 0) } < 0 {
            break;
        }
        assert!(Instant::now() < end, "caveat group {pgid} must die");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// R16-007: a pinned guard dropped with working reads must
/// discharge the leader (not just killpg the group) — the shell
/// zombie must not leak to process exit, and the group must be
/// proven dead. RED: the drop killpgs but never reaps (leader
/// try_wait stays Some); GREEN: the drop reaps and the owner
/// observes ECHILD, with the group ESRCH-dead as retirement
/// evidence.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn pinned_group_drop_discharges_leader() {
    use std::os::unix::process::CommandExt as _;
    // Parked stage: self-grouped sh (leader LIVE) + sleepers.
    let mut stage = std::process::Command::new("/bin/sh");
    stage
        .arg("-c")
        .arg("sleep 31 & sleep 31")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: setpgid on self pre-exec, no userspace state.
    unsafe {
        stage.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let mut leader = stage.spawn().expect("spawn parked stage");
    let group = leader.id() as libc::pid_t;
    // Injected staging failure AFTER successful pin: the guard
    // drops during unwinding with reads working (recovered arm).
    let fired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let guard = KillGroupOnDrop::new(group);
        assert!(
            guard.tick.is_some(),
            "construction must pin (stage broken otherwise)"
        );
        panic!("r16007 injected staging failure");
    }));
    assert!(fired.is_err(), "injection must unwind");
    // Leader discharged: our handle observes ECHILD (reaped by
    // the guard — RED: zombie, Some).
    assert!(
        leader.try_wait().is_err(),
        "leader must be discharged by the pinned drop"
    );
    // Retirement evidence: group ESRCH-dead.
    // SAFETY: signal 0 probes existence only.
    let probed = unsafe { libc::killpg(group, 0) };
    // SAFETY: errno location for this thread.
    let errno = unsafe { libc::__errno_location().read() };
    assert_eq!(probed, -1, "group must be gone after the pinned drop");
    assert_eq!(errno, libc::ESRCH, "group probe must fail ESRCH-only");
}

/// R16-007: probe body (fresh image, SCOPEBASE_R16007_EMFILE) —
/// pin the guard with working reads, exhaust, force unwind so
/// the guard drops under EMFILE (persistent arm), restore,
/// verify-cleanup in-probe (no leak, no parent coupling), then
/// re-panic to fail the child.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn group_guard_persistent_probe() {
    use std::os::unix::process::CommandExt as _;
    let mut stage = std::process::Command::new("/bin/sh");
    stage
        .arg("-c")
        .arg("sleep 31 & sleep 31")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: setpgid on self pre-exec, no userspace state.
    unsafe {
        stage.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let mut leader = stage.spawn().expect("spawn parked stage");
    let group = leader.id() as libc::pid_t;
    let staged = task_starttime_checked(group)
        .expect("stage stat readable")
        .expect("stage visible");
    let guard = KillGroupOnDrop::new(group);
    assert!(
        guard.tick.is_some(),
        "construction must pin (stage broken otherwise)"
    );
    eprintln!("R16007-PINNED group={group} tick={staged}");
    let fired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Declared FIRST inside: unwind drops the guard first
        // (still exhausted → loud), restoring fds only after.
        let mut held = Vec::new();
        let mut guard = guard;
        while let Ok(file) = std::fs::File::open("/dev/null") {
            held.push(file);
        }
        assert!(!held.is_empty(), "exhaustion must consume fds");
        let _ = &mut guard;
        panic!("r16007 injected staging failure");
    }));
    assert!(fired.is_err(), "injection must unwind");
    // Post-restore verified cleanup (tick-verified, fds fine —
    // the loud arm retires nothing itself).
    retire_probe_tree(&mut leader, staged);
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        // SAFETY: signal 0 probes existence only.
        if unsafe { libc::killpg(group, 0) } < 0 {
            break;
        }
        assert!(
            Instant::now() < end,
            "cleanup group {group} must die post-restore"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("r16007 injected staging failure (verified)");
}

/// R16-007: a pinned guard dropped with persistently failing
/// reads must report explicit unresolved group custody (never
/// silent, never a signal without identity). RED: the gate
/// returns false and the drop returns silently; GREEN: the loud
/// line cites the pinned identity.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn group_guard_persistent_drop_reports_unresolved() {
    if std::env::var("SCOPEBASE_R16007_EMFILE").is_ok() {
        group_guard_persistent_probe();
        return;
    }
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("group_guard_persistent_drop_reports_unresolved")
        .arg("--nocapture")
        .env("SCOPEBASE_R16007_EMFILE", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "child must fail at the injected staging panic\n{stderr}"
    );
    assert!(
        stderr.contains("r16007 injected"),
        "panic must name the injection\n{stderr}"
    );
    let mut pinned = None;
    let mut cited = None;
    for line in stderr.lines() {
        if let Some(rest) = line.strip_prefix("R16007-PINNED ") {
            let mut group = None;
            let mut tick = None;
            for word in rest.split_whitespace() {
                if let Some(value) = word.strip_prefix("group=") {
                    group = value.parse::<i32>().ok();
                }
                if let Some(value) = word.strip_prefix("tick=") {
                    tick = value.parse::<u64>().ok();
                }
            }
            pinned = group.zip(tick);
        }
        if let Some(rest) = line.strip_prefix("scopebase unresolved-group ") {
            let mut pgid = None;
            let mut tick = None;
            for word in rest.split_whitespace() {
                if let Some(value) = word.strip_prefix("pgid=") {
                    pgid = value.parse::<i32>().ok();
                }
                if let Some(value) = word.strip_prefix("tick=") {
                    tick = value.parse::<u64>().ok();
                }
            }
            cited = pgid.zip(tick);
        }
    }
    let pinned = pinned.expect("probe must print the pinned identity");
    let cited = cited.expect("drop must print unresolved-group custody");
    assert_eq!(cited, pinned, "custody line must cite the pinned identity");
}

/// R16-008: probe body (fresh image, SCOPEBASE_R16008_REFORM) —
/// fail construction reads (EMFILE through construction), let
/// the explicit read succeed, retire the original, reform the
/// number with another owned group, drop the guard: the reformed
/// group must survive. RED (no pin call): the unpinned fallback
/// waitpid-probes the live reformed leader and SIGKILLs it;
/// GREEN (late pin): the tick mismatch stands down.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn group_guard_reform_probe() {
    use std::os::unix::process::CommandExt as _;
    let mut stage = std::process::Command::new("/bin/sh");
    stage
        .arg("-c")
        .arg("sleep 31 & sleep 31")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: setpgid on self pre-exec, no userspace state.
    unsafe {
        stage.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let mut leader = stage.spawn().expect("spawn parked stage");
    let group = leader.id() as libc::pid_t;
    // Fail construction reads: exhaust through construction.
    let mut held = Vec::new();
    while let Ok(file) = std::fs::File::open("/dev/null") {
        held.push(file);
    }
    assert!(!held.is_empty(), "exhaustion must consume fds");
    let mut guard = KillGroupOnDrop::new(group);
    assert!(
        guard.tick.is_none(),
        "construction must fail under EMFILE (stage broken otherwise)"
    );
    drop(held);
    // The explicit read SUCCEEDS (recovered identity).
    let staged = task_starttime_checked(group)
        .expect("stage stat readable")
        .expect("stage visible");
    // GREEN: the recovered tick reaches the guard (RED had no
    // pin call — the unpinned fallback murdered the reform).
    guard.pin(staged);
    // Retire the original (verified, fds fine).
    retire_probe_tree(&mut leader, staged);
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        // SAFETY: signal 0 probes existence only.
        if unsafe { libc::killpg(group, 0) } < 0 {
            break;
        }
        assert!(
            Instant::now() < end,
            "original group {group} must die before reform"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // Reform the number with another owned group.
    // Single-threaded probe: serial exemption (see helper doc).
    let mut reformed = match steer_sleep_onto(group, true) {
        Some(kid) => kid,
        None => {
            eprintln!("R16008-SKIP reform contended");
            eprintln!("R16008-DONE");
            return;
        }
    };
    let rtick = task_starttime_checked(group)
        .expect("reformed stat readable")
        .expect("reformed visible");
    if rtick == staged {
        let _ = reformed.kill();
        let _ = reformed.wait();
        eprintln!("R16008-SKIP same-tick retake (S100 — untestable this run)");
        eprintln!("R16008-DONE");
        return;
    }
    // R16-011: unwind safety — a failure below must retire the
    // reformed sleeper, never leak it.
    let mut reform_guard = SilentChildGuard::new(group);
    drop(guard);
    // SAFETY: signal 0 probes existence only.
    assert_eq!(
        unsafe { libc::killpg(group, 0) },
        0,
        "reformed group must survive guard drop"
    );
    assert_eq!(
        task_starttime_checked(group),
        Ok(Some(rtick)),
        "reformed tick unchanged"
    );
    eprintln!("R16008-SURVIVED group={group}");
    // Loud cleanup (verified, ours).
    // SAFETY: signal-only to the staged reformed group.
    unsafe {
        libc::killpg(group, libc::SIGKILL);
    }
    let _ = reformed.wait();
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        // SAFETY: signal 0 probes existence only.
        if unsafe { libc::killpg(group, 0) } < 0 {
            break;
        }
        assert!(
            Instant::now() < end,
            "reformed group {group} must die in cleanup"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    reform_guard.disarm();
    eprintln!("R16008-DONE");
}

/// R16-008: a recovered explicit read must reach the guard —
/// after the original retires and another owned group reforms
/// the number, guard drop must spare it. RED: without the pin
/// the unpinned fallback murders the reformed leader; GREEN:
/// the late pin's tick mismatch stands down.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn group_guard_recovered_pin_spares_reformed_group() {
    if std::env::var("SCOPEBASE_R16008_REFORM").is_ok() {
        group_guard_reform_probe();
        return;
    }
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("group_guard_recovered_pin_spares_reformed_group")
        .arg("--nocapture")
        .env("SCOPEBASE_R16008_REFORM", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "probe child must exit 0\n{stderr}");
    assert!(
        stderr.contains("R16008-DONE"),
        "completion marker missing\n{stderr}"
    );
    if stderr.contains("R16008-SKIP") {
        eprintln!("skip: reform stage contended (see probe stderr)");
        return;
    }
    assert!(
        stderr.contains("R16008-SURVIVED"),
        "reformed group must survive guard drop\n{stderr}"
    );
}

/// R14-006: an armed group guard must not signal a reformed
/// stranger group. Plant a live foreign self-grouped sleeper
/// and arm a guard over its number with a mismatched probe
/// tick (the post-retirement reformed state — planted directly
/// as a current state); dropping the guard must spare it.
/// Pre-fix the armed drop killpgs blind (RED); post-fix the
/// drop reuses the group-signal decision (GREEN). Duration 896
/// is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn group_guard_drop_spares_reformed_stranger() {
    use std::os::unix::process::CommandExt as _;
    let mut stranger = std::process::Command::new("/bin/sleep");
    stranger
        .arg("896")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: setpgid on self pre-exec, no userspace state.
    unsafe {
        stranger.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let mut stranger = stranger.spawn().expect("stranger spawns");
    let id = stranger.id() as i32;
    // R14-012: custody AT birth (auto-pins) — the reads below
    // panic safe; disarmed after the owner cleanup.
    let mut stranger_guard = SilentChildGuard::new(id);
    let stranger_tick = task_starttime_checked(id)
        .expect("stranger stat readable")
        .expect("stranger visible");
    // R15-004: late-pin the observed live tick.
    stranger_guard.pin(stranger_tick);
    // SAFETY: getpgid queries only.
    assert_eq!(unsafe { libc::getpgid(id) }, id, "stranger must self-group");
    // Mismatched probe tick: the guard believes the group is
    // our retired probe's; the live holder is a stranger.
    let guard = KillGroupOnDrop {
        group: id as libc::pid_t,
        // R15-006: white-box the Some arm (a mismatched pin the
        // auto-pin constructor would never produce).
        tick: Some(0xDEAD_BEEF_DEAD_BEEF),
        disarmed: false,
    };
    drop(guard);
    // Settle, then proven-live (not just present — a zombie
    // keeps its starttime), then loud owner cleanup (the
    // handle-bound wait reaps OUR child, never a replacement).
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        task_retired_checked(id),
        Ok(false),
        "reformed stranger must survive the armed drop"
    );
    // SAFETY: retiring our own stranger.
    unsafe {
        libc::kill(id, libc::SIGKILL);
    }
    let status = stranger.wait().expect("owner keeps its status");
    stranger_guard.disarm();
    assert!(!status.success(), "killed stranger reports signal death");
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
/// IR-005: the cfg gate rides ABOVE the doc block (a gate
/// buried mid-block re-breaks on the next doc reflow).
/// R11-016(b2): retire a probe's whole process group plus
/// the probe itself, then reap. The probe's pgid is its pid
/// (every probe groups itself on entry), so stranded
/// group-mates (a live holder) die with it. Best-effort and
/// idempotent: ESRCH/ECHILD mean already gone, never a hang.
/// Used on timeout AND on failure exit (a failed probe may
/// strand its group) — always before reporting failure.
/// R12-005: `expected` is the probe's birth tick pinned at
/// spawn — the direct kill and the wait run ONLY while the
/// number still names it (reaped-and-freed is the normal
/// post-call shape: signal nothing, wait nothing).
/// R13-003: the group signal carries its own gate now — a
/// blind killpg murders a recycled self-grouped replacement
/// (pgid == id). killpg fires while the number names our
/// probe, names nothing (our strays alone in the group), or
/// names a live foreigner OUTSIDE the group (getpgid proves
/// the signal cannot reach it while still retiring our
/// strays). Only a live foreign SELF-GROUPED holder skips —
/// loud (a mixed group then leaks our strays; a loud leak
/// beats a silent stranger-kill). Residuals: a regroup in
/// the µs read→signal window (no atomic check-and-killpg
/// exists); a same-tick recycle reads as ours (S100-class).
fn retire_probe_tree(child: &mut std::process::Child, expected: u64) {
    // SAFETY: signal-only to the probe's own group, then the
    // probe itself; errors ignored (house discipline).
    let id = child.id() as libc::pid_t;
    // R12-003: the probe may be reaped already (a second call,
    // or the caller reaped it reporting failure) — the wait
    // below never addresses a recycled holder.
    let ours = task_starttime_checked(id) == Ok(Some(expected));
    if !probe_group_kill_allowed(id, expected) {
        eprintln!(
            "retire_probe_tree: pid {id} names a live foreign self-grouped task; \
             NOT signaling the group (strays, if any, leak loud)"
        );
    } else {
        unsafe {
            libc::killpg(id, libc::SIGKILL);
        }
    }
    if ours {
        // SAFETY: the number still names our probe.
        unsafe {
            libc::kill(id, libc::SIGKILL);
        }
        wait_child_unless_reaped(child, id, expected);
    }
}

/// R14-005: an UNREADABLE holder must refuse the group
/// signal (non-UTF8 comm, EMFILE, EPERM — unreadable is never
/// absence and never proof of ours). A live foreign
/// self-grouped task with non-UTF8 identity text: the decision
/// must be false. Pre-fix unreadable collapses into the freed
/// arm and fires (RED); post-fix it fails closed (GREEN).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn probe_group_kill_refuses_unreadable_identity() {
    // SAFETY: fork; the child only calls prctl/setpgid/pause
    // (async-signal-safe, no locks, no allocation).
    let me = std::process::id() as libc::pid_t;
    let id = unsafe { libc::fork() };
    assert!(id >= 0, "foreigner fork failed");
    if id == 0 {
        unsafe {
            // Die with the parent (never a pipe-holding orphan
            // that hangs the harness past a setup failure).
            libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0,
                0,
                0,
            );
            if libc::getppid() != me {
                libc::_exit(0);
            }
            libc::setpgid(0, 0);
            let name = b"\xff\xfeforeign\x00";
            libc::prctl(libc::PR_SET_NAME, name.as_ptr() as libc::c_ulong, 0, 0, 0);
            loop {
                libc::pause();
            }
        }
    }
    // Setup gate: the child sets group-then-name after the
    // fork — poll for BOTH (an immediate read races the child
    // and panics past cleanup, orphaning the pauser). Timeout
    // retires before failing loud.
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let unreadable = task_starttime_checked(id).is_err();
        // SAFETY: getpgid queries only.
        let grouped = unsafe { libc::getpgid(id) } == id;
        if unreadable && grouped {
            break;
        }
        if Instant::now() >= end {
            // SAFETY: retiring our own unsettled foreigner.
            unsafe {
                libc::kill(id, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(id, &mut status, 0);
            }
            panic!("foreigner never set group+non-UTF8 name");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let bogus = 0xDEAD_BEEF_DEAD_BEEF;
    let allowed = probe_group_kill_allowed(id, bogus);
    // Loud cleanup either way, then the verdict.
    // SAFETY: retiring our own foreigner.
    unsafe {
        libc::kill(id, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(id, &mut status, 0);
    }
    assert!(!allowed, "unreadable holder must refuse the group signal");
}

/// R13-003: group-signal decision for `retire_probe_tree`,
/// extracted for direct unit coverage (a mid-call recycle is
/// unplantable without steering, but every decision state is
/// plantable as a current state). True while the number names
/// our probe, names nothing (freed — our strays alone in the
/// group), or names a live foreigner OUTSIDE the group
/// (getpgid proves the signal cannot reach it). False for a
/// live foreign SELF-GROUPED holder and for UNREADABLE identity
/// (R14-005: fail closed — unreadable is never absence).
/// R14-004: each helper keeps its own gate (sharing one
/// attribute left `retire_probe_tree` compiling ungated;
/// verify: cargo test -p scopebase-testkit --features toolchain
/// --test toolchain_invoke --no-run).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn probe_group_kill_allowed(id: i32, expected: u64) -> bool {
    // R14-005: unreadable is NEVER absence and never proof of
    // ours (non-UTF8 comm, EMFILE, EPERM) — fail closed and
    // skip the signal. Only a PROVEN-absent number fires for
    // our strays. Residual: our strays leak loud (the caller
    // reports the refusal) when our own probe's stat is
    // unreadable — a loud leak beats a silent stranger-kill.
    let holder_tick = match task_starttime_checked(id) {
        Ok(tick) => tick,
        Err(_) => return false,
    };
    if holder_tick == Some(expected) {
        return true;
    }
    if holder_tick.is_none() {
        return true;
    }
    // SAFETY: getpgid queries only. ESRCH (died between the
    // reads) is freed-equivalent: a dead task cannot be hit
    // and the group signal only reaches live members.
    (unsafe { libc::getpgid(id) }) != id
}

/// R10-013: run the framing bad control confined in a fresh
/// probe process and require bounded failure with no remaining
/// holder, sleeper, zombie middleman, or report descriptor (all
/// proven inside the probe). On timeout the parent retires the
/// probe's whole process group before failing loud. The probe
/// output must name one passed test — a renamed probe path
/// fails here instead of passing vacuously on zero tests.
/// R11-016(b2): the group is retired on failure exit too (not
/// just on timeout) — all fixture processes are dead before
/// the parent reports failure.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn unframed_report_expiry_retires_everything() {
    let exe = std::env::current_exe().expect("probe test binary path");
    let mut child = std::process::Command::new(exe)
        .arg("tt04_orphan_unframed_expiry_probe")
        .arg("--exact")
        .env(UNFRAMED_PROBE_ENV, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn unframed-expiry probe");
    // R12-005: pin before any wait (retirement identity gate).
    let staged = task_starttime_checked(child.id() as i32)
        .expect("probe stat readable")
        .expect("probe visible");
    let end = Instant::now() + Duration::from_secs(90);
    loop {
        match child.try_wait().expect("probe wait") {
            Some(status) => {
                // Drained, never EOF-waited: a RED-run sleeper
                // holds the pipes (see drain_exited_child_output).
                let (stdout, stderr) = drain_exited_child_output(&child);
                if !status.success() {
                    // R11-016(b2): a failed probe may strand
                    // its group — retire before reporting.
                    retire_probe_tree(&mut child, staged);
                }
                assert!(
                    status.success(),
                    "unframed-expiry probe must exit success, got {status}: {}",
                    String::from_utf8_lossy(&stdout)
                );
                assert!(
                    String::from_utf8_lossy(&stdout).contains("1 passed"),
                    "probe must run its one test (path exact): {}",
                    String::from_utf8_lossy(&stderr)
                );
                return;
            }
            None => {}
        }
        if Instant::now() >= end {
            retire_probe_tree(&mut child, staged);
            panic!("unframed-expiry probe hung past 90s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// R11-019: spawn one unframed-expiry probe (the probe
/// self-groups on entry, so each probe's fixture lives in a
/// distinct process group).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn spawn_unframed_probe() -> std::process::Child {
    let exe = std::env::current_exe().expect("probe test binary path");
    std::process::Command::new(exe)
        .arg("tt04_orphan_unframed_expiry_probe")
        .arg("--exact")
        .env(UNFRAMED_PROBE_ENV, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn unframed-expiry probe")
}

/// R11-019: await one probe (90s bound): timeout retires the
/// probe tree and panics; failure exit retires the tree and
/// returns the status plus output for the caller to report.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn await_unframed_probe(
    child: &mut std::process::Child,
    expected: u64,
) -> (std::process::ExitStatus, Vec<u8>, Vec<u8>) {
    let end = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(status) = child.try_wait().expect("probe wait") {
            let (stdout, stderr) = drain_exited_child_output(child);
            if !status.success() {
                retire_probe_tree(child, expected);
            }
            return (status, stdout, stderr);
        }
        if Instant::now() >= end {
            retire_probe_tree(child, expected);
            panic!("unframed-expiry probe hung past 90s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// R11-019: an unrelated `sleep 95` (foreign group) must not
/// fail the probe, and the probe must not touch it. Pre-fix
/// the probe's host-global argv scan fails here (RED).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn unframed_probe_ignores_foreign_sleep_95() {
    let mut foreign = std::process::Command::new("sleep")
        .arg("95")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn foreign sleep 95");
    let mut probe = spawn_unframed_probe();
    // R12-005: pin before any wait (retirement identity gate).
    let staged = task_starttime_checked(probe.id() as i32)
        .expect("probe stat readable")
        .expect("probe visible");
    // The foreign sleeper inherits OUR group; the probe
    // self-groups to its own pid — distinct by construction
    // (fail loud on a cosmic pid collision, not mysteriously).
    // SAFETY: getpgrp reads our own group only.
    let our_group = unsafe { libc::getpgrp() };
    assert_ne!(
        our_group,
        probe.id() as libc::pid_t,
        "probe pid collides with our process group; rerun"
    );
    let (status, stdout, stderr) = await_unframed_probe(&mut probe, staged);
    // Retire-before-assert: the foreign sleeper must be alive
    // here (the probe never touches foreign processes)...
    let alive = foreign.try_wait().expect("foreign wait").is_none();
    // SAFETY: our own child (kill + blocking reap).
    unsafe {
        libc::kill(foreign.id() as libc::pid_t, libc::SIGKILL);
    }
    let _ = foreign.wait();
    assert!(alive, "probe run must not kill the foreign sleeper");
    assert!(
        status.success(),
        "probe must ignore foreign sleep 95, got {status}: {}",
        String::from_utf8_lossy(&stdout)
    );
    assert!(
        String::from_utf8_lossy(&stdout).contains("1 passed"),
        "probe must run its one test: {}",
        String::from_utf8_lossy(&stderr)
    );
}

/// R11-019: two concurrent probes must both pass — each
/// probe's same-duration sleeper is foreign to the other.
/// Pre-fix both fail (each sees the other's sleeper) (RED).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn concurrent_unframed_probes_ignore_each_other() {
    let mut first = spawn_unframed_probe();
    let mut second = spawn_unframed_probe();
    // R12-005: pin before any wait (retirement identity gate).
    let staged_a = task_starttime_checked(first.id() as i32)
        .expect("first probe stat readable")
        .expect("first probe visible");
    let staged_b = task_starttime_checked(second.id() as i32)
        .expect("second probe stat readable")
        .expect("second probe visible");
    // Distinct groups by construction (both live → distinct
    // pids → distinct self-groups).
    assert_ne!(first.id(), second.id(), "probe pids must differ");
    let (status_a, stdout_a, stderr_a) = await_unframed_probe(&mut first, staged_a);
    let (status_b, stdout_b, stderr_b) = await_unframed_probe(&mut second, staged_b);
    assert!(
        status_a.success(),
        "first probe must pass alongside a concurrent probe, got {status_a}: {}",
        String::from_utf8_lossy(&stdout_a)
    );
    assert!(
        String::from_utf8_lossy(&stdout_a).contains("1 passed"),
        "first probe must run its one test: {}",
        String::from_utf8_lossy(&stderr_a)
    );
    assert!(
        status_b.success(),
        "second probe must pass alongside a concurrent probe, got {status_b}: {}",
        String::from_utf8_lossy(&stdout_b)
    );
    assert!(
        String::from_utf8_lossy(&stdout_b).contains("1 passed"),
        "second probe must run its one test: {}",
        String::from_utf8_lossy(&stderr_b)
    );
}

/// S129-round9: retirement polling must never issue a numeric
/// wait: the probe pins a live NON-child orphan and polls under a
/// filter that kills on `wait4` (the syscall behind every numeric
/// waitpid). Pre-fix the first poll iteration dies by SIGSYS (RED);
/// post-fix the pin-authorized waitid + ESRCH probe never touch
/// wait4 and the poll times out with the orphan alive — so a
/// replacement child's status can never be consumed here (only the
/// pinned task is reaped, through the pin). The orphan-alive
/// assertions also catch a naive ECHILD-means-retired read. The
/// manual wait loop retires the orphan on every failure path so RED
/// runs stay clean. Duration 93 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn poll_pin_retired_issues_no_numeric_wait() {
    use scopebase_testkit::fixture::linux::seccomp::{install_deny_one, DenyAction};
    let (pid, pinned) = spawn_orphan_sleeper("93");
    // Pin in the parent (asserting pinnability up front); the forked
    // probe inherits the pin across the fork.
    let pin = pidfd_open_task(pid).expect("orphan pinnable while live");
    // SAFETY: the probe installs a wait4 trap, polls a live
    // non-child pin, and reports via _exit.
    let probe = unsafe { libc::fork() };
    assert!(probe >= 0, "trap fork failed");
    if probe == 0 {
        if install_deny_one(libc::SYS_wait4, DenyAction::Kill).is_err() {
            unsafe { libc::_exit(3) };
        }
        let retired = poll_pin_retired(pin);
        // SAFETY: inherited pin owned by this scope.
        unsafe { libc::close(pin) };
        unsafe { libc::_exit(if retired { 11 } else { 10 }) };
    }
    // SAFETY: parent copy of the probed pin.
    unsafe { libc::close(pin) };
    let deadline = Instant::now() + Duration::from_secs(30);
    let code = loop {
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let got = unsafe { libc::waitpid(probe, &mut status, libc::WNOHANG) };
        if got == probe {
            if !libc::WIFEXITED(status) {
                // Pre-fix RED path: SIGSYS. Retire the surviving
                // orphan before failing so RED runs stay clean.
                retire_orphan(pid, pinned);
                panic!(
                    "retirement poll issued a numeric wait under trap (signal {})",
                    libc::WTERMSIG(status)
                );
            }
            break libc::WEXITSTATUS(status);
        }
        if got < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            retire_orphan(pid, pinned);
            panic!("trap probe wait failed: {error}");
        }
        if Instant::now() >= deadline {
            // SAFETY: retiring our own hung probe.
            unsafe {
                libc::kill(probe, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(probe, &mut status, 0);
            }
            retire_orphan(pid, pinned);
            panic!("trap probe hung");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if code == 3 {
        retire_orphan(pid, pinned);
        eprintln!("skip: seccomp unavailable for the wait4 trap");
        return;
    }
    assert_eq!(
        code, 10,
        "trapped poll must time out with the orphan alive (11 would mean ECHILD misread as retired)"
    );
    assert_eq!(
        task_retired_checked(pid),
        Ok(false),
        "polled orphan must survive"
    );
    assert_eq!(
        task_starttime_checked(pid),
        Ok(Some(pinned)),
        "same orphan, not a replacement"
    );
    retire_orphan(pid, pinned);
}

/// S129-round9 control: pin-authorized polling still reaps an owned
/// zombie through the pin — the `waitid(P_PIDFD, …)` reap, not the
/// ESRCH probe, proves it (a zombie answers the pin). Guards
/// against an over-strict fix that drops reaping: without the reap
/// this polls to the bound and fails.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
// R12-003: the child IS reaped — through the pin's P_PIDFD
// waitid, proven by the ECHILD assert below — so no numeric
// `Child::wait` follows (any would risk a recycled holder).
#[allow(clippy::zombie_processes)]
fn poll_pin_retired_reaps_owned_zombie() {
    let child = std::process::Command::new("/bin/true")
        .spawn()
        .expect("probe child spawns");
    let pid = child.id() as i32;
    // Wait for the zombie: exit observed, status unreaped.
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        match task_retired_checked(pid) {
            Ok(true) => break,
            Ok(false) => {}
            Err(error) => panic!("probe child observation unresolved: {error}"),
        }
        assert!(Instant::now() < end, "probe child never exited");
        std::thread::sleep(Duration::from_millis(10));
    }
    let pin = pidfd_open_task(pid).expect("zombie pinnable while unreaped");
    assert!(
        poll_pin_retired(pin),
        "owned zombie must retire through the pin"
    );
    // SAFETY: pin owned by this scope.
    unsafe { libc::close(pin) };
    let mut status = 0;
    // SAFETY: valid status out-pointer for an owned child.
    let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    assert!(
        again < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD),
        "the poll must have reaped the zombie (no status left)"
    );
    // R12-003: no wait follows — ECHILD above proves the status
    // is gone, so any numeric wait could only steal a recycled
    // holder's status or block on its lifetime. The handle drops
    // unwaited (already reaped: nothing leaks).
}

/// S115-round8: survivor cleanup of a NON-child (the real
/// driver-survivor shape — an unreaped-child control cannot catch
/// the check/use race) must never invoke numeric kill(2): the
/// confined child traps kill with SIGSYS and retires an orphan
/// through pinned authority. Pre-fix the numeric kill dies by
/// SIGSYS (RED); post-fix the pin path retires it. Duration 92 is
/// unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn survivor_cleanup_uses_no_numeric_kill_on_nonchild() {
    use scopebase_testkit::fixture::linux::seccomp::{install_deny_one, DenyAction};
    let (pid, pinned) = spawn_orphan_sleeper("92");
    let report = format!("verdict=err survivors={pid}:{pinned} children_after=1");
    // SAFETY: the child traps kill, runs cleanup, reports via _exit.
    let probe = unsafe { libc::fork() };
    assert!(probe >= 0, "trap fork failed");
    if probe == 0 {
        if install_deny_one(libc::SYS_kill, DenyAction::Kill).is_err() {
            unsafe { libc::_exit(3) };
        }
        kill_survivors(&report);
        unsafe { libc::_exit(10) };
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    let code = loop {
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let got = unsafe { libc::waitpid(probe, &mut status, libc::WNOHANG) };
        if got == probe {
            if !libc::WIFEXITED(status) {
                // Pre-fix RED path: SIGSYS. Retire the surviving
                // orphan before failing so RED runs stay clean.
                retire_orphan(pid, pinned);
                panic!(
                    "cleanup invoked numeric kill under trap (signal {})",
                    libc::WTERMSIG(status)
                );
            }
            break libc::WEXITSTATUS(status);
        }
        if got < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            retire_orphan(pid, pinned);
            panic!("trap probe wait failed: {error}");
        }
        if Instant::now() >= deadline {
            // SAFETY: retiring our own hung probe.
            unsafe {
                libc::kill(probe, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(probe, &mut status, 0);
            }
            retire_orphan(pid, pinned);
            panic!("trap probe hung");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if code == 3 {
        retire_orphan(pid, pinned);
        eprintln!("skip: seccomp unavailable for the kill trap");
        return;
    }
    assert_eq!(code, 10, "trapped cleanup must retire via pins");
    assert_eq!(
        task_retired_checked(pid),
        Ok(true),
        "orphan survivor must be retired"
    );
}

/// S115-round8: a survivor that exits between verification and
/// signal (hook-injected deterministically — no pid race needed)
/// retires quietly with no signal delivered anywhere. This locks
/// the post-fix window behavior (an over-strict ESRCH panic would
/// fail it); the kill-trap test above is the RED proving the
/// numeric path is gone.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn survivor_cleanup_window_exit_retires_quietly() {
    let mut victim = std::process::Command::new("/bin/sleep")
        .arg("60")
        .spawn()
        .expect("victim spawns");
    let pid = victim.id() as i32;
    let pinned = task_starttime_checked(pid)
        .expect("victim stat readable")
        .expect("victim visible");
    let mut canary = std::process::Command::new("/bin/sleep")
        .arg("61")
        .spawn()
        .expect("canary spawns");
    let canary_pid = canary.id() as i32;
    kill_survivors_with_hook(
        &format!("verdict=err survivors={pid}:{pinned} children_after=1"),
        Some(&|vpid, _| {
            assert_eq!(vpid, pid, "hook fires for the reported survivor");
            // SAFETY: retiring our own victim: kill + REAP so the
            // number is free (not zombie) at signal time.
            unsafe {
                libc::kill(vpid, libc::SIGKILL);
            }
            let mut status = 0;
            // SAFETY: valid status out-pointer for an owned child.
            let _ = unsafe { libc::waitpid(vpid, &mut status, 0) };
        }),
    );
    assert_eq!(
        task_retired_checked(canary_pid),
        Ok(false),
        "window exit must signal nothing live"
    );
    // SAFETY: retiring our own canary.
    unsafe {
        libc::kill(canary_pid, libc::SIGKILL);
    }
    let _ = canary.wait();
    // R12-003: the hook reaped the victim — reap only while the
    // number still names it (never a recycled holder's status).
    wait_child_unless_reaped(&mut victim, pid, pinned);
}

/// S123-round8: descriptor exhaustion must NOT read as retirement.
/// Confined: the forked child lowers its own NOFILE cap and fills
/// its table, so only ITS observations fail (the parent's table is
/// untouched — no parallel-test hazard). Pre-fix the child
/// observes None/true through the false-success path (RED);
/// post-fix both observations report Err (unresolved).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn task_observation_failures_stay_unresolved() {
    // SAFETY: the child exhausts only its own fd table, probes its
    // own live task, and reports via _exit code.
    let probe = unsafe { libc::fork() };
    assert!(probe >= 0, "probe fork failed");
    if probe == 0 {
        unsafe {
            // Lower the soft cap so exhaustion is instant (the hard
            // cap is untouched; the parent is unaffected).
            let mut lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
                libc::_exit(3);
            }
            let narrow = libc::rlimit {
                rlim_cur: 64.min(lim.rlim_max),
                rlim_max: lim.rlim_max,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &narrow) != 0 {
                libc::_exit(3);
            }
            // Fill the table: /dev/null opens until refusal.
            let devnull = b"/dev/null\0";
            loop {
                let fd = libc::open(devnull.as_ptr() as *const _, libc::O_RDONLY);
                if fd < 0 {
                    break;
                }
            }
            let me = libc::getpid();
            let starttime_unresolved = task_starttime_checked(me).is_err();
            let retired_unresolved = task_retired_checked(me).is_err();
            libc::_exit(if starttime_unresolved && retired_unresolved {
                10
            } else {
                11
            });
        }
    }
    let code = reap_probe(probe, Duration::from_secs(20));
    if code == 3 {
        eprintln!("skip: rlimit unavailable for the EMFILE probe");
        return;
    }
    assert_eq!(code, 10, "exhausted observations must stay unresolved");
}

/// S85-round6: with `SIGCHLD` ignored in the confined driver, the
/// run refuses UP FRONT — group reservation is unprovable under
/// auto-reap, so no tool may spawn. A sleeping tool with a 10s
/// timeout returns in under 5s (a run would take the full 10s to
/// time out), with `InvalidInput/Admission` naming auto-reap and
/// zero children. Round-5 ran the tool and diagnosed ECHILD after
/// the fact; the ECHILD branch survives only for competing-waiter
/// reaps (caller-contract violation), pinned by unit tests.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn autoreap_refuses_before_spawn() {
    let (output, elapsed, dir) = run_denial_driver(
        "s85-autoreap",
        std::path::Path::new("/bin/sleep"),
        10_000,
        &["--auto-reap"],
        &["300"],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "refusal must precede the run (a 10s-timeout run would take 10s), took: {elapsed:?}"
    );
    assert!(
        stdout.starts_with("verdict=err")
            && stdout.contains("kind=InvalidInput")
            && stdout.contains("stage=Admission")
            && stdout.contains("auto-reap"),
        "auto-reap must refuse InvalidInput/Admission, got: {stdout}"
    );
    assert!(
        stdout.contains("children_after=0"),
        "no child may spawn, got: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// S85-round6: the combined case — auto-reap PLUS the waitid filter
/// (which masks ECHILD as EPERM) PLUS a fast-exiting tool, with any
/// `kill`/`killpg` attempt turned fatal (SIGSYS). Round-5 signaled
/// the recycled pgid here (the EPERM misread as "reservation
/// intact"); post-fix the run refuses up front and the driver
/// survives — survival is the no-signal oracle. Neuter check:
/// deleting the upfront refusal crashes this test with SIGSYS.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn combined_autoreap_denial_withholds_all_signals() {
    let (output, elapsed, dir) = run_denial_driver(
        "s85-combined",
        std::path::Path::new("/bin/true"),
        10_000,
        &["--auto-reap", "--deny-waitid", "--trap-signal"],
        &[],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "driver must survive (a signal attempt kills it with SIGSYS): {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "refusal must precede the run, took: {elapsed:?}"
    );
    assert!(
        stdout.starts_with("verdict=err")
            && stdout.contains("kind=InvalidInput")
            && stdout.contains("stage=Admission")
            && stdout.contains("auto-reap"),
        "combined case must refuse InvalidInput/Admission, got: {stdout}"
    );
    assert!(
        stdout.contains("children_after=0"),
        "no child may spawn, got: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// S85-round6 control: the trap fires. A normal run (no auto-reap)
/// of a fast tool under the `kill` trap dies with SIGSYS — the
/// EPERM-observation path attempts the group signal under valid
/// pidfd authority (no over-withholding). This control passes pre-
/// and post-fix alike (both attempt the signal there); it proves
/// the combined test's trap would catch an attempt.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn trap_control_proves_group_signal_attempted() {
    use std::os::unix::process::ExitStatusExt as _;
    let (output, _elapsed, dir) = run_denial_driver(
        "s85-trap",
        std::path::Path::new("/bin/true"),
        10_000,
        &["--trap-signal"],
        &[],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.code() == Some(3) {
        assert!(
            stdout.starts_with("setup="),
            "exit 3 must carry its setup reason, got: {stdout}"
        );
        return;
    }
    assert!(
        !output.status.success() && output.status.code().is_none(),
        "trapped run must die by signal, got: {stdout}"
    );
    assert_eq!(
        output.status.signal(),
        Some(libc::SIGSYS),
        "death must be the SIGSYS trap, got: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// S86-round5: with the WNOWAIT observation denied AND the signal
/// routes denied (reaping allowed), retirement of a long-running
/// tool must stay deadline-bounded and report the refused signal
/// instead of blocking past the configured timeout. The surviving
/// sleeper (kill-proof by design) is reaped by the test from the
/// driver's `survivors=` field. Pre-fix `kill_and_wait` ignored
/// the kill failure and blocked in `wait` until natural exit — the
/// 30s hang guard, not the assertions, caught that hang.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn signal_denial_retires_bounded_with_refused_signal() {
    let (output, elapsed, dir) = run_denial_driver(
        "s86-deny-signal",
        std::path::Path::new("/bin/sleep"),
        2000,
        &["--deny-signal"],
        &["300"],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.code() == Some(3) {
        assert!(
            stdout.starts_with("setup="),
            "exit 3 must carry its setup reason, got: {stdout}"
        );
        return;
    }
    assert!(
        output.status.success(),
        "driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed < Duration::from_secs(25),
        "retirement must be bounded (2s retire + 10s settle), took: {elapsed:?}"
    );
    assert!(
        stdout.starts_with("verdict=err")
            && stdout.contains("kind=Backend")
            && stdout.contains("stage=Execute")
            && stdout.contains("errno=Some(1)"),
        "denied observation must fail Backend/Execute with EPERM, got: {stdout}"
    );
    assert!(
        stdout.contains("still alive") && stdout.contains("signal refused"),
        "refused signal must be explicit, got: {stdout}"
    );
    assert!(
        stdout.contains("unsettled") && stdout.contains("stdout"),
        "detached reader keeps its stream diagnosis (S87), got: {stdout}"
    );
    assert!(
        stdout.contains("children_after=1"),
        "the kill-proof sleeper must be reported alive, got: {stdout}"
    );
    kill_survivors(&stdout);
    let _ = std::fs::remove_dir_all(&dir);
}

/// S86-round6: a tool that overruns output and then sleeps, under the
/// full waitid/signal denial, must retire bounded — the overrun path
/// previously called the unbounded `kill_and_wait`, hanging past the
/// run deadline. Pre-fix this test trips the 30s hang guard (RED);
/// post-fix the verdict carries the overrun with bounded retirement
/// fallout. Duration 302 keeps the hang sweep unique.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn overrun_under_denial_retires_bounded() {
    let (output, elapsed, dir) = run_denial_driver(
        "s86-noisy",
        std::path::Path::new("/bin/sh"),
        10_000,
        &["--deny-signal-only"],
        // S112-round8: `exec` turns the tool itself into the
        // sleeper (same pid), so the driver's `survivors=` covers
        // it and no grandchild escapes to sweep — the unconditional
        // global sweep below is deleted with the finding.
        &["-c", "head -c 2000000 /dev/zero; exec sleep 302"],
        &[("sleep", &["302"])],
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.code() == Some(3) {
        assert!(
            stdout.starts_with("setup="),
            "exit 3 must carry its setup reason, got: {stdout}"
        );
        return;
    }
    assert!(
        output.status.success(),
        "driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed < Duration::from_secs(28),
        "overrun retirement must be bounded (10s grace + 10s settle), took: {elapsed:?}"
    );
    assert!(
        stdout.starts_with("verdict=err")
            && stdout.contains("kind=LimitExceeded")
            && stdout.contains("stage=Execute")
            && stdout.contains("over bound"),
        "noisy overrun must fail LimitExceeded/Execute, got: {stdout}"
    );
    assert!(
        stdout.contains("still alive") && stdout.contains("signal refused"),
        "refused signal must ride along, got: {stdout}"
    );
    assert!(
        stdout.contains("children_after=1"),
        "the kill-proof tool must be reported alive, got: {stdout}"
    );
    // S112-round8: the exec'd tool is the driver's own child,
    // so its `survivors=` entry covers it — no sweep needed.
    kill_survivors(&stdout);
    let _ = std::fs::remove_dir_all(&dir);
}

/// S86-round6: wall-clock expiry under the full denial must retire
/// bounded — the timeout path previously called the unbounded
/// `kill_and_wait`, hanging past run-deadline-plus-cleanup. Short
/// run timeout (500ms) plus a kill-proof sleeper: pre-fix the 30s
/// hang guard trips (RED); post-fix the verdict carries the timeout
/// with bounded retirement fallout. Duration 301 keeps the hang
/// sweep unique.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn timeout_under_denial_retires_bounded() {
    let (output, elapsed, dir) = run_denial_driver(
        "s86-timeout",
        std::path::Path::new("/bin/sleep"),
        500,
        &["--deny-signal-only"],
        &["301"],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.code() == Some(3) {
        assert!(
            stdout.starts_with("setup="),
            "exit 3 must carry its setup reason, got: {stdout}"
        );
        return;
    }
    assert!(
        output.status.success(),
        "driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed < Duration::from_secs(28),
        "timeout retirement must be bounded (10s grace + 10s settle), took: {elapsed:?}"
    );
    assert!(
        stdout.starts_with("verdict=err")
            && stdout.contains("kind=LimitExceeded")
            && stdout.contains("stage=Execute")
            && stdout.contains("wall-clock timeout"),
        "denied timeout must fail LimitExceeded/Execute, got: {stdout}"
    );
    assert!(
        stdout.contains("still alive") && stdout.contains("signal refused"),
        "refused signal must ride along, got: {stdout}"
    );
    assert!(
        stdout.contains("children_after=1"),
        "the kill-proof sleeper must be reported alive, got: {stdout}"
    );
    kill_survivors(&stdout);
    let _ = std::fs::remove_dir_all(&dir);
}
