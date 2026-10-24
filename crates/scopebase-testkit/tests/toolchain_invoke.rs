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
                        .and_then(|pid| {
                            std::fs::read(format!("/proc/{pid}/cmdline")).ok()
                        })
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
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("denial driver spawns");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait().expect("try_wait runs") {
            Some(_) => break,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("denial driver hung (S67 regression)");
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

/// S85/S86-round5: run the invoke-denial driver with mode flags,
/// returning its output, wall elapsed, and scratch dir (the caller
/// removes the dir last, so failures keep their evidence — the S67
/// test's convention). The hang guard matches S67's: 30s, then the
/// driver is killed and the test fails.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn run_denial_driver(
    tag: &str,
    tool: &std::path::Path,
    timeout_ms: u64,
    mode_flags: &[&str],
    tool_args: &[&str],
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
    let deadline = start + Duration::from_secs(30);
    loop {
        match child.try_wait().expect("try_wait runs") {
            Some(_) => break,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("denial driver hung ({tag} regression)");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
    let output = child.wait_with_output().expect("output collected");
    (output, start.elapsed(), dir)
}

/// S85/S86-round5: SIGKILL every pid in the driver's `survivors=`
/// field, then prove each is gone (a reused pid naming a non-sleep
/// is equally retired for our purposes — but these tests only run
/// `sleep` tools, so absence is asserted directly).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn kill_survivors(stdout: &str) {
    let field = stdout
        .split_whitespace()
        .find_map(|word| word.strip_prefix("survivors="))
        .expect("driver reports survivors=");
    assert!(!field.is_empty(), "expected survivors, got: {stdout}");
    for pid in field.split(',') {
        let pid: i32 = pid.parse().expect("survivor pid parses");
        // SAFETY: signaling a test-spawned sleeper by its pid.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let gone = std::fs::read(format!("/proc/{pid}/cmdline")).is_err();
            if gone {
                break;
            }
            assert!(Instant::now() < end, "survivor {pid} resisted SIGKILL");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// S85-round5: with the tool auto-reaped (SIGCHLD ignored in the
/// confined driver), the first observation fails with ECHILD — the
/// leader was reaped out from under the run. No signal may be sent
/// to the reusable pid/pgid numbers; unresolved custody is
/// reported, the readers settle (EOF'd pipes), and nothing is left
/// behind. Pre-fix the branch signaled the saved numbers and
/// reported a bare retirement ECHILD with no custody diagnosis.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn autoreap_observation_reports_unresolved_custody() {
    let (output, _elapsed, dir) = run_denial_driver(
        "s85-autoreap",
        std::path::Path::new("/bin/true"),
        10_000,
        &["--auto-reap"],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.starts_with("verdict=err")
            && stdout.contains("kind=Backend")
            && stdout.contains("stage=Execute")
            && stdout.contains("errno=Some(10)"),
        "auto-reap must fail Backend/Execute with ECHILD, got: {stdout}"
    );
    assert!(
        stdout.contains("reservation")
            && stdout.contains("not signaled")
            && stdout.contains("unresolved"),
        "lost reservation must be explicit, got: {stdout}"
    );
    assert!(
        stdout.contains("children_after=0"),
        "no child may survive, got: {stdout}"
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
