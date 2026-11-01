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

/// R16-012: settled live-process evidence — the no-signal
/// oracle for survival asserts (R15-010's defect was tick-only
/// checks: a kill-mutant's zombie keeps its tick and passes).
/// Polls /proc STATE for `secs`: any Z (or disappearance)
/// fails loud immediately (murdered/vanished); surviving the
/// whole window proves live (SIGKILL delivery resolves in ms —
/// a settled window cannot be fooled by async delivery); the
/// final tick equality proves the SAME birth (no recycle).
/// State reads only — never reaps.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn assert_task_settled_live(pid: i32, tick: u64, secs: u64, what: &str) {
    let end = Instant::now() + Duration::from_secs(secs);
    loop {
        match task_state(pid) {
            Some(state) if state != 'Z' => {
                if Instant::now() >= end {
                    break;
                }
            }
            Some(_) => panic!("{what} {pid} zombified (murdered, tick kept)"),
            None => panic!("{what} {pid} vanished (survival needs presence)"),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        task_starttime_checked(pid),
        Ok(Some(tick)),
        "{what} {pid} recycled during the settle window"
    );
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

/// R17-010 (toolchain twin of `await_proc_gone_reaping`):
/// strict retirement evidence for an expected (pid, starttime)
/// identity. Proven absence (`Ok(None)`) and holder reuse (a
/// different tick — the awaited task is gone, else the number
/// could not host another) return true WITHOUT waiting; a live
/// holder is polled (with a WNOHANG wait assist that reaps an
/// adopted zombie and ECHILDs otherwise — always ignored);
/// unreadable stats keep polling (never claimed gone, never
/// waited on); past the bound the await returns false so the
/// caller fails loud. Production callers use this; the
/// unreadable-stat regressions use
/// [`await_task_gone_reaping_with`].
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn await_task_gone_reaping(pid: i32, expected: u64, timeout: std::time::Duration) -> bool {
    await_task_gone_reaping_with(pid, expected, timeout, task_starttime_checked)
}

/// R21-011(c): R20-010 custody verdict — true when the
/// awaited birth is proven gone (absence or recycle). An
/// UNREADABLE stat fails loud (an outage hides liveness —
/// the old `!= Ok(Some)` shape verdicts green over unknown
/// state). Hoisted from the birth-custody probe's two
/// phases so the outage regression exercises the same
/// artifact.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn custody_retired_or_fail(pid: i32, tick: u64, what: &str) -> bool {
    match task_starttime_checked(pid) {
        Ok(None) => true,
        Ok(Some(now)) => now != tick,
        Err(error) => panic!("{what} custody unreadable (outage?): {error}"),
    }
}

/// R17-010: seam for the toolchain unreadable-stat
/// regressions: `gate`, when it reports Err, must skip the
/// wait (unknown is never waited on) and must never certify
/// retirement. Production callers use
/// [`await_task_gone_reaping`].
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn await_task_gone_reaping_with(
    pid: i32,
    expected: u64,
    timeout: std::time::Duration,
    gate: impl Fn(i32) -> Result<Option<u64>, String>,
) -> bool {
    let end = std::time::Instant::now() + timeout;
    loop {
        match gate(pid) {
            Ok(None) => return true,
            Ok(Some(now)) if now != expected => return true,
            Ok(Some(_)) => {
                // SAFETY: waitpid on the verified holder;
                // reaps an adopted zombie, ECHILD
                // otherwise — always ignored.
                let mut status = 0;
                unsafe {
                    libc::waitpid(pid, &mut status, libc::WNOHANG);
                }
            }
            Err(_) => {}
        }
        if std::time::Instant::now() >= end {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// R17-010 (toolchain twin): an unreadable verification sample
/// while the fixture is alive must never certify retirement —
/// even after reads restore. Stubbed gate (Err twice, then the
/// live tick forever): the await must time out false, not latch
/// the earlier unknown as gone. Deterministic: the stub drives
/// the gate; the pid exceeds pid_max so the live arm's waitpid
/// can only ECHILD.
#[test]
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn awaited_unreadable_while_live_never_verifies() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    let calls = AtomicUsize::new(0);
    let gate = |_: i32| {
        if calls.fetch_add(1, Ordering::SeqCst) < 2 {
            Err("injected unreadable stat".to_string())
        } else {
            Ok(Some(9999))
        }
    };
    assert!(
        !await_task_gone_reaping_with(1073741824, 9999, Duration::from_millis(200), gate),
        "unreadable samples over a live fixture must not verify"
    );
}

/// R17-010 (toolchain twin): persistently unreadable stats fail
/// loud past the bound (false → the caller's assert fires) —
/// never certify as gone. Stubbed gate (Err forever), short
/// timeout, pid past pid_max as above.
#[test]
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn awaited_persistent_unreadable_never_verifies() {
    use std::time::Duration;
    let gate =
        |_: i32| -> Result<Option<u64>, String> { Err("injected unreadable stat".to_string()) };
    assert!(
        !await_task_gone_reaping_with(1073741824, 9999, Duration::from_millis(200), gate),
        "persistent unreadable stats must not verify"
    );
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
    // R19015-FLAKE03: 100 placement misses mean the number is
    // squatted — an early hint-theft landed a long-lived
    // suite spawn on it and the rest miss deterministically
    // (same-tick cannot span 100 tries). The squatter is
    // another test's live task (never kill it) — skip loud
    // (retake-contention precedent), never fail.
    let mut replacement = match replacement {
        Some(replacement) => replacement,
        None => {
            eprintln!("skip: stray number squatted during placement (retake contended)");
            // Discharge our own swept stray (birth-gated:
            // a recycled number is spared, never waited on)
            // and restore the hint (as the success path
            // does) before the early return.
            wait_child_unless_reaped(&mut stray, stray_pid, stray_tick);
            locked_restore_hint(&last_before);
            return;
        }
    };
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
    // R19015-FLAKE03: 100 placement misses mean the number is
    // squatted — an early hint-theft landed a long-lived
    // suite spawn on it and the rest miss deterministically
    // (same-tick cannot span 100 tries; never kill the
    // squatter) — skip loud (retake-contention precedent),
    // never fail.
    let mut replacement = match replacement {
        Some(replacement) => replacement,
        None => {
            eprintln!("skip: stray number squatted during placement (retake contended)");
            // Discharge our own swept stray (birth-gated)
            // and restore the hint (as the success path
            // does) before the early return.
            wait_child_unless_reaped(&mut stray, stray_pid, stray_tick);
            locked_restore_hint(&last_before);
            return;
        }
    };
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
                ));
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
                        ));
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

/// R19003-FLAKE01: refcounted soft-NOFILE
/// confinement state (leaf mutex — the critical
/// sections take no other lock).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
static CONFINEMENT_STATE: std::sync::Mutex<Option<ConfinementState>> = std::sync::Mutex::new(None);

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct ConfinementState {
    prev: libc::rlim_t,
    count: usize,
}

/// R19003-FLAKE01: confine this process's soft NOFILE
/// ceiling ahead of deliberate exhaustion (toolchain twin
/// of the audit helper — same contract). An exhauster
/// that fills to the ambient ulimit (~524k) breaks the
/// suite: system-wide discovery scans (100k budget)
/// truncate over the giant table and miss their victims
/// (near-deterministic resonance). Confined to 4096 the
/// exhaustion stays genuine-EMFILE (reads fail
/// identically) while the table stays small. Fresh-image
/// probes hold the guard for life (the limit dies with
/// the child). Refcounted: the first guard applies the
/// cap, the last drop restores the saved ceiling
/// (thread-safe nesting; poison ignored).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn confine_fd_table_for_exhaustion() -> FdTableConfinement {
    let mut slot = CONFINEMENT_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(state) = slot.as_mut() {
        state.count += 1;
        return FdTableConfinement;
    }
    // SAFETY: getrlimit/setrlimit on self only.
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) },
        0,
        "own NOFILE limit must be readable"
    );
    let prev = rlim.rlim_cur;
    // Below the cap already (constrained runner):
    // exhaustion stays genuine, nothing to confine —
    // still counted, so the balanced drop is a no-op.
    let confined = prev.min(4096);
    if confined != prev {
        rlim.rlim_cur = confined;
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) },
            0,
            "soft NOFILE confinement must apply"
        );
    }
    *slot = Some(ConfinementState { prev, count: 1 });
    FdTableConfinement
}

/// R19003-FLAKE01: releases one confinement hold; the
/// last drop restores the saved ceiling. Best-effort:
/// drops never panic.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct FdTableConfinement;

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl Drop for FdTableConfinement {
    fn drop(&mut self) {
        let mut slot = CONFINEMENT_STATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (count, prev) = match slot.as_mut() {
            Some(state) => {
                state.count = state.count.saturating_sub(1);
                (state.count, state.prev)
            }
            None => return,
        };
        if count > 0 {
            return;
        }
        *slot = None;
        // Restore while still holding the mutex (leaf —
        // no other lock inside): no interleaving
        // confine can observe the unrestored window.
        // SAFETY: getrlimit/setrlimit on self only.
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } != 0 {
            return;
        }
        if rlim.rlim_cur != prev {
            rlim.rlim_cur = prev;
            let _ = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) };
        }
    }
}

/// R19003-FLAKE01: the confinement guard caps the soft
/// ceiling at 4096 and restores on the last drop — in
/// order and out of order (refcounted nesting). The final
/// value allows a sibling holder (in-process confiners
/// nest; the cap stays correct either way — never
/// garbage, never stuck). R20-016: this tolerant shape
/// documents sibling-yield only — exactness is proven by
/// `fd_table_confinement_restores_ceiling_exact` (this
/// test is mutant-green without restoration).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn fd_table_confinement_restores_ceiling() {
    // SAFETY: getrlimit on self only.
    let limits_now = || {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) },
            0,
            "own NOFILE limit must be readable"
        );
        (rlim.rlim_cur, rlim.rlim_max)
    };
    let (before, hard) = limits_now();
    let capped = before.min(4096);
    let outer = confine_fd_table_for_exhaustion();
    assert_eq!(limits_now().0, capped, "cap must apply (or already hold)");
    let inner = confine_fd_table_for_exhaustion();
    assert_eq!(limits_now().0, capped, "nested hold keeps the cap");
    drop(inner);
    assert_eq!(limits_now().0, capped, "inner drop must not restore early");
    drop(outer);
    let final_soft = limits_now().0;
    assert!(
        final_soft == before || final_soft == capped || final_soft == hard,
        "last drop must restore (or yield to a live sibling holder), got {final_soft}"
    );
    // Reverse order: dropping the outer hold first must
    // not restore early either.
    let (before2, _) = limits_now();
    let capped2 = before2.min(4096);
    let outer = confine_fd_table_for_exhaustion();
    let inner = confine_fd_table_for_exhaustion();
    drop(outer);
    assert_eq!(
        limits_now().0,
        capped2,
        "outer-first drop must not restore early"
    );
    drop(inner);
    let final_soft = limits_now().0;
    assert!(
        final_soft == before2 || final_soft == capped2 || final_soft == hard,
        "last drop must restore (or yield to a live sibling holder), got {final_soft}"
    );
}

/// R20-016 (toolchain twin): exact restoration in
/// isolation — same mutant-green diagnosis as the audit
/// twin (the tolerant test above accepts `final_soft ==
/// capped`, conflating sibling-yield with
/// broken-restore). Fresh-image probe, no siblings by
/// construction, EXACT restoration both orders; a
/// ≤4096-ambient runner skips.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn fd_table_confinement_restores_ceiling_exact_probe() {
    // SAFETY: getrlimit on self only.
    let limits_now = || {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) },
            0,
            "own NOFILE limit must be readable"
        );
        rlim.rlim_cur
    };
    let before = limits_now();
    if before <= 4096 {
        eprintln!("skip: ambient soft {before} ≤ 4096 (exact restoration untestable)");
        return;
    }
    let outer = confine_fd_table_for_exhaustion();
    assert_eq!(limits_now(), 4096, "cap must apply");
    let inner = confine_fd_table_for_exhaustion();
    assert_eq!(limits_now(), 4096, "nested hold keeps the cap");
    drop(inner);
    assert_eq!(limits_now(), 4096, "inner drop must not restore early");
    drop(outer);
    assert_eq!(
        limits_now(),
        before,
        "last drop must restore exactly (no siblings in fresh image)"
    );
    // Reverse order: dropping the outer hold first must
    // not restore early either.
    let outer = confine_fd_table_for_exhaustion();
    assert_eq!(limits_now(), 4096, "cap must re-apply");
    let inner = confine_fd_table_for_exhaustion();
    drop(outer);
    assert_eq!(
        limits_now(),
        4096,
        "outer-first drop must not restore early"
    );
    drop(inner);
    assert_eq!(
        limits_now(),
        before,
        "reverse-order last drop must restore exactly"
    );
    eprintln!("R20016-EXACT-RESTORED");
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn fd_table_confinement_restores_ceiling_exact() {
    if std::env::var("SCOPEBASE_R20016_EXACT_PROBE").is_ok() {
        fd_table_confinement_restores_ceiling_exact_probe();
        return;
    }
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("fd_table_confinement_restores_ceiling_exact")
        .arg("--exact")
        .arg("--nocapture")
        .env("SCOPEBASE_R20016_EXACT_PROBE", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "exact-restoration probe must pass\n{stderr}"
    );
    if stderr.contains("≤ 4096 (exact restoration untestable)") {
        eprintln!("skip (probe on a ≤4096-ambient runner)");
        return;
    }
    assert!(
        stderr.contains("R20016-EXACT-RESTORED"),
        "probe must cite exact restoration\n{stderr}"
    );
}

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

/// R20-005 (toolchain twin): close every inherited fd but
/// stdio and `keeps`. Faithful twin-port of the lib
/// `shed_inherited_fds` (close_range sweep, syscalls only,
/// no allocation; any failure `_exit(127)`s — a half-shed
/// child must never run on). ALL post-fork branches below
/// must run only this + raw syscalls (MT-fork rule).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
unsafe fn shed_inherited_fds(keep: &[i32]) {
    // Sweep close_range windows between keeps (bound:
    // u32::MAX; keeps below 3 need no action — stdio never
    // sheds). Any failure _exits 127 WITHOUT reporting (the
    // parent observes EOF/death, loud).
    let mut lo: i64 = 3;
    loop {
        if lo > u32::MAX as i64 {
            break;
        }
        let mut next: i64 = u32::MAX as i64 + 1;
        for &fd in keep {
            let fd = fd as i64;
            if fd >= lo && fd < next {
                next = fd;
            }
        }
        if next > lo {
            // SAFETY: close_range on our own table copy
            // (plain fork never shares it); bounds checked
            // above.
            if unsafe {
                libc::syscall(
                    libc::SYS_close_range,
                    lo as libc::c_long,
                    (next - 1) as libc::c_long,
                    0 as libc::c_long,
                )
            } != 0
            {
                unsafe { libc::_exit(127) };
            }
        }
        if next > u32::MAX as i64 {
            break;
        }
        lo = next + 1;
    }
}

/// R20-005 (toolchain twin): fork a pausing middleman that
/// forks an exec'd grandchild sleep and reports its pid.
/// R21-009 (twin mirror): birth guard for a staged
/// middleman pair — armed at fork (before the fallible
/// stat reads); drop retires both (m2 blind-killed FIRST
/// while m1 lives — the middleman pauses until signaled,
/// so m2's number is pinned; then m1 killed + reaped,
/// bounded). Probe-first (R22-007 mirror): m1 zombie ⟹ m2
/// pin-killed (loud when unpinned); m1 gone/ECHILD ⟹ the
/// only sound early return (the tail kills m2 first).
/// Disarm after the explicit tail.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct MiddlemanPairGuard {
    m1: i32,
    m2: i32,
    m2pin: Result<M2Pin, i32>,
    disarmed: bool,
}

/// R22-007 (toolchain twin): pidfd pin on m2's birth
/// (closes on drop).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct M2Pin(std::os::fd::RawFd);

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl Drop for M2Pin {
    fn drop(&mut self) {
        // SAFETY: fd owned by this guard.
        unsafe { libc::close(self.0) };
    }
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl MiddlemanPairGuard {
    fn armed(m1: i32, m2: i32) -> Self {
        use scopebase_testkit::fixture::linux::seccomp::pidfd_open_raw;
        // Pin m2's birth NOW (infallible: Err(errno) on
        // denial/unsupported — silent here, LOUD if the
        // zombie path ever runs unpinned).
        let m2pin = pidfd_open_raw(m2).map(M2Pin);
        MiddlemanPairGuard {
            m1,
            m2,
            m2pin,
            disarmed: false,
        }
    }
    fn disarm(&mut self) {
        self.disarmed = true;
    }
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl Drop for MiddlemanPairGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        let mut st = 0;
        // SAFETY: WNOHANG probe of our own child.
        let probed = unsafe { libc::waitpid(self.m1, &mut st, libc::WNOHANG) };
        if probed > 0 {
            // R22-007 (toolchain twin): m1 ZOMBIE (reaped
            // by the probe) — m2 may LIVE ON (mirror of
            // the lib: pin-kill, loud when unpinned).
            match &self.m2pin {
                Ok(pin) => {
                    // SAFETY: pidfd_send_signal to our
                    // pinned grandchild-birth only.
                    unsafe {
                        libc::syscall(libc::SYS_pidfd_send_signal, pin.0, libc::SIGKILL, 0, 0);
                    }
                }
                Err(errno) => {
                    eprintln!(
                        "R22007-UNPINNED middleman m1={} zombie-reaped, m2={} unpinned \
                         (pin denied: errno {errno}) — m2 may survive (no safe signal \
                         exists; caller owns the residual)",
                        self.m1, self.m2
                    );
                }
            }
            return;
        }
        if probed < 0 {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(-999);
            if errno == libc::ECHILD {
                // m1 gone (reaped by the tail — which kills
                // m2 first): the only sound early return.
                return;
            }
            // Unexpected probe errno: m1's number unpinned
            // (never touch it); pin-kill m2 when held,
            // then report loud.
            if let Ok(pin) = &self.m2pin {
                // SAFETY: pidfd_send_signal to our pinned
                // grandchild-birth only.
                unsafe {
                    libc::syscall(libc::SYS_pidfd_send_signal, pin.0, libc::SIGKILL, 0, 0);
                }
            }
            eprintln!(
                "R22007-PROBE m1={} probe failed (errno {errno} — m1 state unknown, \
                 number untouched); m2={} pin-killed when pinned",
                self.m1, self.m2
            );
            return;
        }
        // m1 live: m2's number is pinned — blind kill sound.
        // SAFETY: signal-only to the pinned grandchild.
        unsafe {
            libc::kill(self.m2, libc::SIGKILL);
        }
        // SAFETY: signal-only to our own child.
        unsafe {
            libc::kill(self.m1, libc::SIGKILL);
        }
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            // SAFETY: WNOHANG reap of our own child.
            if unsafe { libc::waitpid(self.m1, &mut st, libc::WNOHANG) } != 0 {
                return;
            }
            if std::time::Instant::now() >= end {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

/// R21-008 (toolchain twin): read /proc state +
/// process-group in one parse (faithful port of the lib
/// helper — state field 3, pgrp field 5).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn stat_state_pgrp(pid: i32) -> Option<(char, i32)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(") ")?.1;
    let mut fields = after.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let _ppid = fields.next()?;
    let pgrp = fields.next()?.parse::<i32>().ok()?;
    Some((state, pgrp))
}

/// R21-008 (toolchain twin): faithful port of the lib
/// `retire_reportless_middleman` — STOP-freeze, pgrp
/// verify (grouped ⟹ pinned killpg; ungrouped ⟹ m2
/// unborn), kill, zombie-await, hammer, reap, post-reap
/// group-empty probe. Same loudness, same bounds, same
/// accepted wedged-box residual (see the lib doc for the
/// full soundness argument).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn retire_reportless_middleman(m1: i32) {
    use std::time::{Duration, Instant};
    // SAFETY: signals to our own unreaped child (or ESRCH
    // nop when already dead — a dead m1 still needs the
    // freeze-verify below).
    unsafe {
        libc::kill(m1, libc::SIGSTOP);
    }
    let frozen: Option<(char, i32)> = {
        let end = Instant::now() + Duration::from_secs(5);
        let mut seen = None;
        while Instant::now() < end {
            match stat_state_pgrp(m1) {
                Some((st, pgrp)) if matches!(st, 'T' | 't' | 'Z' | 'X' | 'x') => {
                    seen = Some((st, pgrp));
                    break;
                }
                _ => {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        seen
    };
    let Some((fstate, pgrp)) = frozen else {
        eprintln!("R21008-FALLBACK: middleman {m1} unfreezable for 5 s (wedged?) — loud best-effort retire");
        // SAFETY: our own unreaped child (pinned).
        unsafe {
            libc::kill(m1, libc::SIGKILL);
        }
        // R22-008 (toolchain twin): UNCONDITIONAL
        // group-kill — mirror of the lib fix (m1 pinned ⟹
        // ours-or-nonexistent; the read only characterizes
        // the kill LOUDLY, never gates it).
        match stat_state_pgrp(m1) {
            Some((_, g)) if g == m1 => {
                eprintln!("R22008-ASSUMED-GROUPED: middleman {m1} grouped at fallback read — group-killing");
            }
            Some((_, g)) => {
                eprintln!("R22008-ASSUMED-GROUPED: middleman {m1} ungrouped at fallback read (pgrp {g} — m2 unborn?) — killpg anyway (pinned: ours-or-nonexistent, ESRCH-nop when absent)");
            }
            None => {
                eprintln!("R22008-ASSUMED-GROUPED: middleman {m1} pgrp UNREADABLE at fallback (outage?) — killpg anyway (pinned: ours-or-nonexistent; an already-born m2 dies, never strands)");
            }
        }
        // SAFETY: pinned group — ours-or-nonexistent while
        // m1 is unreaped.
        unsafe {
            libc::killpg(m1, libc::SIGKILL);
        }
        reap_child_bounded(m1, "R21008-FALLBACK");
        return;
    };
    let grouped = pgrp == m1;
    if grouped {
        eprintln!(
            "R21008: middleman {m1} grouped at freeze ({fstate}) — group-killing (m2 may live)"
        );
        // SAFETY: pinned group — ours by construction.
        unsafe {
            libc::killpg(m1, libc::SIGKILL);
        }
    } else {
        eprintln!(
            "R21008: middleman {m1} ungrouped at freeze ({fstate}) — m2 unborn, numeric kill only"
        );
    }
    // SAFETY: our own unreaped child (STOPPED m1 dies on
    // SIGKILL without CONT; zombie m1 nop-accepts it).
    unsafe {
        libc::kill(m1, libc::SIGKILL);
    }
    let end = Instant::now() + Duration::from_secs(5);
    let mut zombied = false;
    while Instant::now() < end {
        match stat_state_pgrp(m1) {
            Some(('Z' | 'X' | 'x', _)) => {
                zombied = true;
                break;
            }
            _ => {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    if !zombied {
        eprintln!(
            "R21008: middleman {m1} not zombie 5 s after KILL (wedged?) — loud best-effort retire"
        );
        reap_child_bounded(m1, "R21008");
        return;
    }
    if grouped {
        // SAFETY: still pinned (m1 zombie-unreaped).
        unsafe {
            libc::killpg(m1, libc::SIGKILL);
        }
    }
    reap_child_bounded(m1, "R21008");
    if grouped {
        // Post-reap probe: signal-0 ONLY (the number is
        // unpinned now — never killpg(KILL) here). ESRCH
        // proves m2 dead; non-ESRCH is unactionable ⟹
        // loud, never a blind kill.
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            // SAFETY: signal-0 probe (no delivery).
            let probed = unsafe { libc::killpg(m1, 0) };
            if probed != 0 {
                // R22-009 (toolchain twin): discriminate
                // errno — mirror of the lib fix (ESRCH
                // proves empty; EPERM/other fails
                // LOUD-UNRESOLVED, never an empty
                // citation).
                let errno = std::io::Error::last_os_error().raw_os_error();
                if errno == Some(libc::ESRCH) {
                    eprintln!("R21008: group {m1} empty post-reap (ESRCH) — m2 proven dead");
                    break;
                }
                eprintln!("R22009-UNRESOLVED: group {m1} post-reap probe failed errno {errno:?} (not ESRCH — group-signal denial?) — m2 fate UNKNOWN, never an empty citation");
                break;
            }
            if Instant::now() >= end {
                eprintln!("R21008: group {m1} NON-EMPTY 5 s post-reap (m2-live or foreign squatter — unactionable, loud)");
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// R21-008 (toolchain twin): faithful port of the lib
/// bounded child reap (WNOHANG loop, loud at the bound).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn reap_child_bounded(pid: i32, tag: &str) {
    use std::time::{Duration, Instant};
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let mut st = 0;
        // SAFETY: WNOHANG reap of our own child (specific
        // pid — never steals).
        let got = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) };
        if got == pid || std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
            break;
        }
        if Instant::now() >= end {
            eprintln!("{tag}: child {pid} unreaped after 5 s (wedged?) — loud");
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Twin-port of the lib `fork_pausing_grandchild_sleep`
/// (same contract: live-middleman parentage ⟹ non-child;
/// self-group + shed + null stdio; empty-env exec;
/// poll-bounded report; None FULLY retires before
/// returning — R21-008, same as lib).
///
/// # Safety
///
/// Fork in a multithreaded context: the middleman runs
/// syscalls only plus read-only inherited stack memory,
/// and never returns; the parent must retire both
/// children.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
unsafe fn fork_pausing_grandchild_sleep(dur: &str) -> Option<(i32, i32)> {
    // SAFETY: same contract as the inner helper.
    unsafe { fork_pausing_grandchild_sleep_inner(dur, false, true).0 }
}

/// R21-008 (toolchain twin): faithful port of the lib
/// jammed-report variant — drops the report read end,
/// birth-gates m2 (panics loud when unborn — never
/// vacuous), runs the production tail. Returns the helper
/// result plus m1 for the independent reap proof.
///
/// # Safety
///
/// Same fork contract as the twin helper above.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
unsafe fn fork_pausing_grandchild_sleep_jam_report(dur: &str) -> (Option<(i32, i32)>, i32) {
    // SAFETY: same contract as the inner helper.
    unsafe { fork_pausing_grandchild_sleep_inner(dur, true, true) }
}

/// R22-008/009 (toolchain twin): jammed-report SPAWN ONLY
/// — mirror of the lib helper (spawn + birth-gate WITHOUT
/// the tail; caller prints custody IMMEDIATELY).
///
/// # Safety
///
/// Same fork contract as the twin helper above.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
unsafe fn fork_pausing_grandchild_sleep_jam_noretire(dur: &str) -> Option<i32> {
    // SAFETY: same contract as the inner helper.
    let (_, m1) = unsafe { fork_pausing_grandchild_sleep_inner(dur, true, false) };
    (m1 > 0).then_some(m1)
}

/// R22-016(b) (toolchain twin): PRE-EXEC-STALL pair spawn
/// — mirror of the lib helper (m1 self-groups, forks the
/// stub, pauses; the stub self-stops pre-exec and never
/// execs; birth-gated with the stub pid parsed from m1's
/// children file). Caller prints custody IMMEDIATELY.
///
/// # Safety
///
/// Same fork contract as the twin helper above.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
unsafe fn fork_prestall_grandchild_jam_noretire(dur: &str) -> Option<(i32, i32)> {
    let _ = dur;
    // SAFETY: fork itself is always safe; both children
    // uphold the syscall-only contract below.
    let m1 = unsafe { libc::fork() };
    if m1 == 0 {
        unsafe {
            if libc::setpgid(0, 0) != 0 {
                libc::_exit(127);
            }
            shed_inherited_fds(&[]);
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            if null < 0 {
                libc::_exit(127);
            }
            if libc::dup2(null, 0) < 0 || libc::dup2(null, 1) < 0 || libc::dup2(null, 2) < 0 {
                libc::_exit(127);
            }
            if null > 2 {
                libc::close(null);
            }
            let stub = libc::fork();
            if stub == 0 {
                libc::raise(libc::SIGSTOP);
                loop {
                    libc::pause();
                }
            }
            if stub < 0 {
                libc::_exit(127);
            }
            loop {
                libc::pause();
            }
        }
    }
    if m1 < 0 {
        return None;
    }
    let gate_end = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Ok(kids) = std::fs::read_to_string(format!("/proc/{m1}/task/{m1}/children")) {
            if let Some(first) = kids.split_whitespace().next() {
                if let Ok(stub) = first.parse::<i32>() {
                    if stub > 0 {
                        return Some((m1, stub));
                    }
                }
            }
        }
        if std::time::Instant::now() >= gate_end {
            match stat_state_pgrp(m1) {
                Some((st, _)) => {
                    panic!("R22016B-JAM: birth-gate timed out with m1 {m1} alive-childless (state {st} — wedged pre-fork? box wedged?)")
                }
                None => {
                    panic!("R22016B-JAM: birth-gate timed out with m1 {m1} dead pre-stub (self-exit? — regression vacuous, failing loud)")
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
unsafe fn fork_pausing_grandchild_sleep_inner(
    dur: &str,
    jam: bool,
    retire_on_jam: bool,
) -> (Option<(i32, i32)>, i32) {
    use std::os::unix::io::FromRawFd as _;
    let mut pipe = [0; 2];
    // SAFETY: pipe2 fills both ends.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return (None, -1);
    }
    let (read_fd, write_fd) = (pipe[0], pipe[1]);
    assert!(
        read_fd >= 3 && write_fd >= 3,
        "report pipe must clear stdio (else the middleman's stdio-nulling clobbers it)"
    );
    let dur_c = match std::ffi::CString::new(dur) {
        Ok(c) => c,
        Err(_) => {
            // SAFETY: ends owned by this scope.
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return (None, -1);
        }
    };
    // SAFETY: fork itself is always safe; the middleman
    // upholds the syscall-only contract documented above.
    let m1 = unsafe { libc::fork() };
    if m1 == 0 {
        unsafe {
            // R21-008 (toolchain twin): self-group FIRST
            // (same as lib — the tail's only channel to
            // the unknown-pid grandchild).
            if libc::setpgid(0, 0) != 0 {
                libc::_exit(127);
            }
            shed_inherited_fds(&[write_fd]);
            // Null stdio BEFORE forking the grandchild.
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            if null < 0 {
                libc::_exit(127);
            }
            if libc::dup2(null, 0) < 0 || libc::dup2(null, 1) < 0 || libc::dup2(null, 2) < 0 {
                libc::_exit(127);
            }
            if null > 2 {
                libc::close(null);
            }
            let m2 = libc::fork();
            if m2 == 0 {
                // Grandchild: exec sleep with an EMPTY env.
                let path = c"/bin/sleep".as_ptr();
                let argv0 = c"sleep".as_ptr();
                let argv = [argv0, dur_c.as_ptr(), std::ptr::null()];
                let envp = [std::ptr::null()];
                libc::execve(path, argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
            if m2 < 0 {
                libc::_exit(127);
            }
            // Report the grandchild pid, then pause forever.
            // R21-017 (toolchain twin): hand-rolled decimal —
            // snprintf is NOT async-signal-safe after a
            // multithreaded fork; digits reverse into the
            // stack buffer (m2 > 0 here — failure and
            // grandchild branches exited above).
            let mut buf = [0 as libc::c_char; 32];
            let mut value = m2 as u32;
            let mut digits = 0usize;
            // Bounds exclude panic: u32 decimal ≤ 10 digits
            // plus newline < 32 (no heap, no locks — the
            // only failure mode would be an index panic on
            // an unreachable bound).
            loop {
                buf[digits] = (b'0' + (value % 10) as u8) as libc::c_char;
                digits += 1;
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            {
                let mut i = 0;
                while i < digits / 2 {
                    let other = digits - 1 - i;
                    buf.swap(i, other);
                    i += 1;
                }
            }
            buf[digits] = b'\n' as libc::c_char;
            digits += 1;
            let len = digits as libc::c_int;
            if len > 0 {
                let mut written = 0;
                while written < len {
                    let got = libc::write(
                        write_fd,
                        buf.as_ptr().add(written as usize) as *const _,
                        (len - written) as usize,
                    );
                    if got <= 0 {
                        break;
                    }
                    written += got as libc::c_int;
                }
            }
            loop {
                libc::pause();
            }
        }
    }
    if m1 < 0 {
        // SAFETY: ends owned by this scope.
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        return (None, -1);
    }
    // SAFETY: write end owned by this scope (the middleman
    // holds its own copy).
    unsafe {
        libc::close(write_fd);
    }
    if jam {
        // R21-008 jam (toolchain twin, same as lib): drop
        // the read end, birth-gate m2 (panics loud when
        // unborn — never vacuous), run the production
        // tail.
        // SAFETY: end owned by this scope.
        unsafe {
            libc::close(read_fd);
        }
        let gate_end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut born = false;
        while std::time::Instant::now() < gate_end {
            if let Ok(kids) = std::fs::read_to_string(format!("/proc/{m1}/task/{m1}/children")) {
                if !kids.split_whitespace().next().is_none() {
                    born = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        if !born {
            // R22-014 (twin): discharge BEFORE failing loud
            // (same as lib — the unwind would strand the
            // wedged middleman with no custody held).
            match stat_state_pgrp(m1) {
                Some((st, _)) => {
                    retire_reportless_middleman(m1);
                    panic!("R21008-JAM: birth-gate timed out with m1 {m1} alive-childless (state {st} — wedged pre-fork? box wedged?) (m1 retired before failing loud)")
                }
                None => {
                    reap_child_bounded(m1, "R21008-JAM");
                    panic!("R21008-JAM: birth-gate timed out with m1 {m1} dead pre-report (self-exit? — regression vacuous, failing loud) (corpse reaped before failing loud)")
                }
            }
        }
        if retire_on_jam {
            retire_reportless_middleman(m1);
        }
        return (None, m1);
    }
    // Bounded report read (the middleman reports in µs).
    let mut poller = libc::pollfd {
        fd: read_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: polls our own pipe end.
    let ready = unsafe { libc::poll(&mut poller, 1, 5000) };
    let mut report = String::new();
    let m2 = if ready > 0 {
        use std::io::BufRead as _;
        // SAFETY: read end owned by this scope (File takes
        // the OwnedFd for its Read impl).
        let owned = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(read_fd) };
        let mut reader = std::io::BufReader::new(std::fs::File::from(owned));
        if reader.read_line(&mut report).is_ok() {
            report.trim().parse::<i32>().ok()
        } else {
            None
        }
    } else {
        // SAFETY: end owned by this scope.
        unsafe {
            libc::close(read_fd);
        }
        None
    };
    match m2 {
        Some(m2) if m2 > 0 => (Some((m1, m2)), m1),
        _ => {
            // Report failure: FULL retirement before None
            // (R21-008, same as lib).
            retire_reportless_middleman(m1);
            (None, m1)
        }
    }
}

/// R20-005 (toolchain twin): the grandchild helper
/// reports the true grandchild pid; the grandchild is our
/// non-child (parented to the live middleman) with null
/// stdio. Twin of the fork.rs unit test. Cleanup retires
/// both.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn pausing_grandchild_sleep_reports_nonchild() {
    let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("906") }.expect("grandchild staged");
    // R21-009: guard at birth (before the fallible stat
    // reads below).
    let mut pair = MiddlemanPairGuard::armed(m1, m2);
    // stat fields after ") ": state ppid ... starttime
    // (rsplit: a comm containing ") " must not shift the
    // fields).
    let fields = |pid: i32| -> Vec<String> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat readable");
        let after = text.rsplit_once(") ").map(|x| x.1).expect("comm stripped");
        after.split_whitespace().map(str::to_string).collect()
    };
    let m2fields = fields(m2);
    assert_eq!(
        m2fields[1].parse::<i32>().expect("ppid parses"),
        m1,
        "grandchild must be parented to the live middleman"
    );
    for fd in [0, 1, 2] {
        let link = std::fs::read_link(format!("/proc/{m2}/fd/{fd}")).expect("stdio readable");
        assert_eq!(
            link.to_string_lossy(),
            "/dev/null",
            "grandchild stdio must be null"
        );
    }
    // Non-child: waitpid must refuse (ECHILD), never
    // report status.
    let mut st = 0;
    let got = unsafe { libc::waitpid(m2, &mut st, libc::WNOHANG) };
    assert!(got < 0, "grandchild must not be our child");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD),
        "non-child waitpid must refuse ECHILD"
    );
    // Cleanup: the sleeper (zombifies under the pausing
    // middleman — death is unreadable-or-Z), then the
    // middleman (reaped — ours).
    assert_eq!(
        unsafe { libc::kill(m2, libc::SIGKILL) },
        0,
        "sleeper signaled"
    );
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let dead = match std::fs::read_to_string(format!("/proc/{m2}/stat")) {
            Err(_) => true,
            Ok(text) => {
                text.rsplit_once(") ")
                    .and_then(|(_, after)| after.split_whitespace().next())
                    == Some("Z")
            }
        };
        if dead {
            break;
        }
        assert!(Instant::now() < end, "sleeper must die");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        unsafe { libc::kill(m1, libc::SIGKILL) },
        0,
        "middleman signaled"
    );
    let mut mst = 0;
    let mgot = unsafe { libc::waitpid(m1, &mut mst, 0) };
    assert_eq!(mgot, m1, "middleman status drains to us");
    pair.disarm();
}

/// R22-007 (toolchain twin): settle to zombie (staging).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn settle_zombie_007(pid: i32) {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let state = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|text| {
                text.rsplit_once(") ")
                    .and_then(|(_, after)| after.split_whitespace().next().map(str::to_string))
            });
        if state.as_deref() == Some("Z") {
            return;
        }
        assert!(
            std::time::Instant::now() < end,
            "staging broken (never zombified)"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// R22-007 (toolchain twin): poll tick-aware absence.
/// True when drained within the bound.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn birth_drained_007(pid: i32, tick: u64, timeout: std::time::Duration) -> bool {
    let end = std::time::Instant::now() + timeout;
    loop {
        match task_starttime_checked(pid) {
            Ok(None) => return true,
            Ok(Some(now)) if now != tick => return true,
            Ok(Some(_)) => {}
            Err(error) => panic!("staging broken (stat unreadable: {error})"),
        }
        if std::time::Instant::now() >= end {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// R22-007 (toolchain twin): mirror of the lib zombie-m1
/// leg — the probe reaps m1 and the pin kills the orphaned
/// m2; both births retire. Duration 992 is unique to this
/// test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn middleman_guard_zombie_m1_retires_m2_via_pin() {
    use std::panic::AssertUnwindSafe;
    use std::time::Duration;
    let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("992") }.expect("pair staged");
    let tick2 = task_starttime_checked(m2)
        .expect("m2 stat readable")
        .expect("m2 visible");
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _pair = MiddlemanPairGuard::armed(m1, m2);
        assert_eq!(
            unsafe { libc::kill(m1, libc::SIGKILL) },
            0,
            "staging broken (m1 kill)"
        );
        settle_zombie_007(m1);
        panic!("simulated observation failure");
    }));
    assert!(outcome.is_err(), "staging broken (must unwind)");
    assert_eq!(
        task_starttime_checked(m1),
        Ok(None),
        "m1 must be reaped by the probe"
    );
    let retired = birth_drained_007(m2, tick2, Duration::from_secs(5));
    kill_tick_gated(m2, tick2);
    birth_drained_007(m2, tick2, Duration::from_secs(5));
    assert!(retired, "m2 must retire via the pin (abandoned?!)");
}

/// R22-007 (toolchain twin): mirror of the lib ECHILD leg
/// (tail-honored contract returns clean).
/// CHARACTERIZATION. Duration 993 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn middleman_guard_echild_after_tail_returns_clean() {
    use std::time::{Duration, Instant};
    let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("993") }.expect("pair staged");
    let tick2 = task_starttime_checked(m2)
        .expect("m2 stat readable")
        .expect("m2 visible");
    let pair = MiddlemanPairGuard::armed(m1, m2);
    assert_eq!(
        unsafe { libc::kill(m2, libc::SIGKILL) },
        0,
        "staging broken (m2 kill)"
    );
    settle_zombie_007(m2);
    assert_eq!(
        unsafe { libc::kill(m1, libc::SIGKILL) },
        0,
        "staging broken (m1 kill)"
    );
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let mut st = 0;
        // SAFETY: WNOHANG reap of our own child.
        let got = unsafe { libc::waitpid(m1, &mut st, libc::WNOHANG) };
        if got == m1 {
            break;
        }
        assert!(Instant::now() < end, "staging broken (m1 never reaped)");
        std::thread::sleep(Duration::from_millis(1));
    }
    drop(pair);
    assert_eq!(task_starttime_checked(m1), Ok(None), "m1 must stay reaped");
    assert!(
        birth_drained_007(m2, tick2, Duration::from_secs(5)),
        "m2 must drain via init"
    );
}

/// R22-007 (toolchain twin): mirror of the lib forged-None
/// leg (unpinned zombie degrades loud; m2 survives for the
/// caller). CHARACTERIZATION of the degraded shape.
/// Duration 994 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn middleman_guard_unpinned_zombie_leaves_m2_for_caller() {
    use std::panic::AssertUnwindSafe;
    use std::time::Duration;
    let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("994") }.expect("pair staged");
    let tick2 = task_starttime_checked(m2)
        .expect("m2 stat readable")
        .expect("m2 visible");
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let mut pair = MiddlemanPairGuard::armed(m1, m2);
        pair.m2pin = Err(libc::EPERM);
        assert_eq!(
            unsafe { libc::kill(m1, libc::SIGKILL) },
            0,
            "staging broken (m1 kill)"
        );
        settle_zombie_007(m1);
        panic!("simulated observation failure");
    }));
    assert!(outcome.is_err(), "staging broken (must unwind)");
    // SAFETY: signal 0 probes only.
    assert_eq!(
        unsafe { libc::kill(m2, 0) },
        0,
        "m2 must survive unpinned (loud, then test-cleaned)"
    );
    assert_eq!(
        task_starttime_checked(m2),
        Ok(Some(tick2)),
        "survivor must be OUR birth"
    );
    kill_tick_gated(m2, tick2);
    assert!(
        birth_drained_007(m2, tick2, Duration::from_secs(5)),
        "test must retire the survivor"
    );
}

/// R22-007 denied-pin probe (toolchain twin, fresh image):
/// mirror of the lib probe — seccomp-deny `pidfd_open` in
/// SELF, then zombie-m1 + unwind; the drop must go LOUD
/// (R22007-UNPINNED) and m2 survives for the parent.
/// Duration 995 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn middleman_guard_denied_pin_reports_unpinned_probe() {
    use scopebase_testkit::fixture::linux::seccomp::{install_deny_one, DenyAction};
    use std::panic::AssertUnwindSafe;
    // R23-002: `unsupported_arch` skips explicitly
    // (seccomp denial is x86-only — exit 0 with the SKIP
    // marker; the wrapper judges the marker, never the
    // install). Any other install failure is still
    // staging-broken.
    if let Err(error) = install_deny_one(libc::SYS_pidfd_open, DenyAction::Eperm) {
        if error.stage() == "unsupported_arch" {
            eprintln!("R22007-SKIP unsupported_arch (seccomp denial unavailable)");
            return;
        }
        panic!("deny installs (staging): {error}");
    }
    assert_eq!(
        scopebase_testkit::fixture::linux::seccomp::pidfd_open_raw(std::process::id() as i32),
        Err(libc::EPERM),
        "staging broken (pidfd_open not denied?)"
    );
    let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("995") }.expect("pair staged");
    let tick2 = task_starttime_checked(m2)
        .expect("m2 stat readable")
        .expect("m2 visible");
    println!("R22007-M2 {m2} {tick2}");
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _pair = MiddlemanPairGuard::armed(m1, m2);
        assert_eq!(
            unsafe { libc::kill(m1, libc::SIGKILL) },
            0,
            "staging broken (m1 kill)"
        );
        settle_zombie_007(m1);
        panic!("simulated observation failure");
    }));
    assert!(outcome.is_err(), "staging broken (must unwind)");
    eprintln!("R22007-PIN-DONE");
}

/// R22-007 denied-pin wrapper (toolchain twin): mirror of
/// the lib wrapper (fresh image; cleanup before verdict).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn middleman_guard_denied_pin_reports_unpinned() {
    use std::time::Duration;
    if std::env::var("SCOPEBASE_R22007_DENY_PIN_TWIN").is_ok() {
        middleman_guard_denied_pin_reports_unpinned_probe();
        return;
    }
    let out = run_fresh_probe_bounded(
        "SCOPEBASE_R22007_DENY_PIN_TWIN",
        "middleman_guard_denied_pin_reports_unpinned",
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    // R23-002: explicit unsupported_arch skip (the probe
    // stages nothing on this path — no custody to run —
    // so the check precedes the M2 parse).
    if stderr.contains("R22007-SKIP") {
        eprintln!("skip: seccomp pidfd_open denial unsupported on this arch (see probe stderr)");
        return;
    }
    let (m2, tick2): (i32, u64) = stdout
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix("R22007-M2 ")?;
            let (pid, tick) = rest.split_once(' ')?;
            Some((pid.parse().ok()?, tick.parse().ok()?))
        })
        .expect("staging broken (no m2 line?)");
    kill_tick_gated(m2, tick2);
    assert!(
        birth_drained_007(m2, tick2, Duration::from_secs(5)),
        "parent must retire the survivor"
    );
    assert!(out.status.success(), "probe must complete\n{stderr}");
    assert!(
        stderr.contains("R22007-PIN-DONE"),
        "probe must cite completion\n{stderr}"
    );
    assert!(
        stderr.contains("R22007-UNPINNED"),
        "drop must go loud when unpinned\n{stderr}"
    );
}

/// R21-008 (toolchain twin): faithful port of the lib
/// live-sleeper scan — true when a LIVE (non-zombie)
/// `sleep dur` exists anywhere in /proc. R22-016(a):
/// entry / cmdline read errors other than NotFound fail
/// LOUD (mirror of the lib fix — swallowing them is
/// false absence over live m2).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn live_sleep_with_dur(dur: &str) -> bool {
    let entries = std::fs::read_dir("/proc").expect("/proc readable");
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("readdir mid-scan failed: {error}"),
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let cmdline = match std::fs::read(format!("/proc/{name}/cmdline")) {
            Ok(c) => c,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("/proc/{name}/cmdline unreadable mid-scan: {error}"),
        };
        let mut args = cmdline.split(|b| *b == 0);
        let argv0 = args.next().unwrap_or_default();
        let argv1 = args.next().unwrap_or_default();
        if argv0 != b"sleep" || argv1 != dur.as_bytes() {
            continue;
        }
        match std::fs::read_to_string(format!("/proc/{name}/stat")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("/proc/{name}/stat unreadable mid-scan: {error}"),
            Ok(text) => {
                let state = text
                    .rsplit_once(") ")
                    .and_then(|(_, after)| after.split_whitespace().next());
                if state != Some("Z") {
                    return true;
                }
            }
        }
    }
    false
}

/// R22-004(a) (toolchain twin): mirror of the lib
/// absence-proof — zombies retain /proc entries, so
/// absence ⟺ reaped (no waitpid — a wait would steal a
/// recycled sibling zombie's status). `Ok(true)` = absent
/// ⟹ reaped; `Ok(false)` = present ⟹ UNPROVEN (fail
/// closed); `Err` = outage (fails loud).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn prove_reaped_by_absence_toolchain(pid: i32) -> Result<bool, String> {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.to_string()),
        Ok(_) => Ok(false),
    }
}

/// R21-008 (toolchain twin): mirror of the lib jammed
/// regression — a jammed report post-second-fork fully
/// retires before `None` (m1 reaped, unknown-pid m2 dead).
/// Duration 958 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn jammed_report_retires_both_before_none() {
    use std::time::{Duration, Instant};
    let (result, m1) = unsafe { fork_pausing_grandchild_sleep_jam_report("958") };
    assert!(result.is_none(), "jammed report must yield None (tail ran)");
    assert!(m1 > 0, "jam exposes m1 for the reap proof");
    // R22-004(a): /proc absence, never a wait (a recycled
    // sibling zombie would lose its status to a waitpid).
    assert_eq!(
        prove_reaped_by_absence_toolchain(m1),
        Ok(true),
        "m1 must be reaped already (/proc gone — present means RED or unproven)"
    );
    let end = Instant::now() + Duration::from_secs(10);
    while live_sleep_with_dur("958") {
        assert!(
            Instant::now() < end,
            "RED: unknown-pid m2 stranded live past the jammed report"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// R22-008 (toolchain twin): tight EMFILE hold — port of
/// the lib `OutageHold` (confine soft NOFILE to 4096 +
/// fill, restores on drop). FRESH-IMAGE CHILDREN ONLY —
/// never in the suite process. Single-hold-per-child
/// only. Never raises on confine, never lowers on
/// restore.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct OutageHold {
    previous_cur: Option<libc::rlim_t>,
    held: Vec<std::fs::File>,
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl OutageHold {
    fn exhaust() -> Self {
        // SAFETY: getrlimit/setrlimit with a valid local rlimit.
        let previous_cur = unsafe {
            let mut limit: libc::rlimit = std::mem::zeroed();
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                None
            } else {
                let original = limit.rlim_cur;
                let cap = original.min(4096);
                if cap < original {
                    limit.rlim_cur = cap;
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                        return OutageHold {
                            previous_cur: None,
                            held: Self::fill(),
                        };
                    }
                }
                Some(original)
            }
        };
        OutageHold {
            previous_cur,
            held: Self::fill(),
        }
    }
    fn fill() -> Vec<std::fs::File> {
        let mut held = Vec::new();
        while let Ok(file) = std::fs::File::open("/dev/null") {
            held.push(file);
        }
        assert!(!held.is_empty(), "exhaustion must consume fds");
        held
    }
    /// R22-016(a): release exactly one held fd (the
    /// one-free-slot staging — opendir consumes it, every
    /// later open fails EMFILE).
    fn release_one(&mut self) {
        assert!(self.held.pop().is_some(), "staging broken (hold empty?)");
    }
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl Drop for OutageHold {
    fn drop(&mut self) {
        if let Some(previous) = self.previous_cur {
            // SAFETY: getrlimit/setrlimit with a valid local rlimit.
            unsafe {
                let mut limit: libc::rlimit = std::mem::zeroed();
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0
                    && limit.rlim_cur < previous
                {
                    limit.rlim_cur = previous;
                    libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
                }
            }
        }
    }
}

/// R22-008 (toolchain twin): collect (pid,
/// starttime-tick) of every LIVE (non-zombie) `sleep
/// dur` — mirror of the lib custody scan (NotFound
/// skips; any other read error fails LOUD).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn sleep_pids_with_dur(dur: &str) -> Vec<(i32, u64)> {
    let mut found = Vec::new();
    let entries = std::fs::read_dir("/proc").expect("/proc readable");
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("custody scan: readdir mid-scan failed: {error}"),
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let cmdline = match std::fs::read(format!("/proc/{name}/cmdline")) {
            Ok(c) => c,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                panic!("custody scan: /proc/{name}/cmdline unreadable mid-scan: {error}")
            }
        };
        let mut args = cmdline.split(|b| *b == 0);
        let argv0 = args.next().unwrap_or_default();
        let argv1 = args.next().unwrap_or_default();
        // Basename match: fork-exec'd sleeps carry argv0
        // "sleep", Command-spawned ones (the pair
        // publisher) "/bin/sleep" — the R12 fallback
        // sweeps the latter. Unique durations keep both
        // shapes disjoint.
        let base = argv0.rsplit(|b| *b == b'/').next().unwrap_or_default();
        if base != b"sleep" || argv1 != dur.as_bytes() {
            continue;
        }
        let pid: i32 = match name.parse() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        match task_starttime_checked(pid) {
            Ok(Some(tick)) => {
                let live = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                    .ok()
                    .and_then(|text| {
                        text.rsplit_once(") ").and_then(|(_, after)| {
                            after.split_whitespace().next().map(str::to_string)
                        })
                    });
                if live.as_deref() != Some("Z") {
                    found.push((pid, tick));
                }
            }
            Ok(None) => continue,
            Err(error) => panic!("custody scan: stat unreadable mid-scan: {error}"),
        }
    }
    found
}

/// R22-008 (toolchain twin): wrapper-side custody for an
/// unknown-pid m2 — mirror of the lib helper
/// (tick-gated SIGKILL per scanned birth + bounded drain
/// + re-scan; true when no LIVE `sleep dur` remains).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn kill_sleep_with_dur(dur: &str) -> bool {
    for (pid, tick) in sleep_pids_with_dur(dur) {
        kill_tick_gated(pid, tick);
        if !birth_drained_007(pid, tick, std::time::Duration::from_secs(5)) {
            return false;
        }
    }
    !live_sleep_with_dur(dur)
}

/// R22-014 (toolchain twin): fault-leg duration
/// override — mirror of the lib helper (legs restage
/// under a unique duration; GREEN keeps the default).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn r22014_sleep_dur(default: &'static str) -> String {
    std::env::var("SCOPEBASE_R22014_SLEEP_DUR").unwrap_or_else(|_| default.to_string())
}

/// R22-014/R12 (toolchain twin): fallback custody sweep
/// — mirror of the lib helper (the probe died before
/// transmitting its SLEEPER line; sweep by the unique
/// duration). Returns the swept count.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn r22006_fallback_sweep_sleep(dur: &str) -> usize {
    let swept = sleep_pids_with_dur(dur).len();
    assert!(
        kill_sleep_with_dur(dur),
        "R12 fallback: live sleep-{dur} survived the sweep"
    );
    // Basename recheck (kill_'s trailing live_ scan is
    // fork-shape-exact — blind to "/bin/sleep").
    assert!(
        sleep_pids_with_dur(dur).is_empty(),
        "R12 fallback: live sleep-{dur} survived the sweep"
    );
    swept
}

/// R22-008 fallback probe (toolchain twin): mirror of the
/// lib probe (healthy staging + custody print + fd-table
/// exhaustion + reportless tail into the fallback; the
/// fallback must group-kill UNCONDITIONALLY). RED (old
/// gate: live `sleep 854` survives). Duration 854 is
/// unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn reportless_fallback_kills_group_unconditionally_probe() {
    let dur = r22014_sleep_dur("854");
    let m1 = unsafe { fork_pausing_grandchild_sleep_jam_noretire(&dur) }
        .expect("staging broken (pair spawn)");
    let mut _pair = ReportlessPairGuard::armed(m1);
    let tick1 = task_starttime_checked(m1)
        .expect("staging broken (m1 stat)")
        .expect("staging broken (m1 visible)");
    println!("R22008-M1 {m1} {tick1}");
    std::io::Write::flush(&mut std::io::stdout()).expect("custody line flushed");
    // R22-014 fault leg (twin): staged pre-tail panic
    // (same as lib — the pair guard must discharge).
    if std::env::var("SCOPEBASE_R22014_PAIR_PANIC").is_ok() {
        panic!("staged pre-tail panic (R22-014 pair-discharge regression)");
    }
    let hold = OutageHold::exhaust();
    assert!(
        stat_state_pgrp(m1).is_none(),
        "staging broken (stat readable under the hold?)"
    );
    retire_reportless_middleman(m1);
    _pair.disarm();
    drop(hold);
    eprintln!("R22008-DONE");
}

/// R22-008 fallback wrapper (toolchain twin): mirror of
/// the lib wrapper (fresh image; custody BEFORE verdicts;
/// the tail's own retirement recorded BEFORE custody
/// kills).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn reportless_fallback_kills_group_unconditionally() {
    use std::time::{Duration, Instant};
    if std::env::var("SCOPEBASE_R22008_FALLBACK_TWIN").is_ok() {
        reportless_fallback_kills_group_unconditionally_probe();
        return;
    }
    let outcome = run_fresh_probe_collect(
        "SCOPEBASE_R22008_FALLBACK_TWIN",
        "reportless_fallback_kills_group_unconditionally",
    );
    let stdout = String::from_utf8_lossy(&outcome.out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&outcome.out.stderr).into_owned();
    let (m1, tick1): (i32, u64) = stdout
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix("R22008-M1 ")?;
            let (pid, tick) = rest.split_once(' ')?;
            Some((pid.parse().ok()?, tick.parse().ok()?))
        })
        .expect("staging broken (no m1 line?)");
    let end = Instant::now() + Duration::from_secs(5);
    while live_sleep_with_dur("854") {
        if Instant::now() >= end {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let retired_by_tail = !live_sleep_with_dur("854");
    kill_tick_gated(m1, tick1);
    assert!(
        birth_drained_007(m1, tick1, Duration::from_secs(5)),
        "wrapper must drain m1"
    );
    assert!(
        kill_sleep_with_dur("854"),
        "wrapper must drain the residual sleep 854"
    );
    assert!(!outcome.timed_out, "probe must complete\n{stderr}");
    assert!(outcome.out.status.success(), "probe must exit 0\n{stderr}");
    assert!(
        stderr.contains("R21008-FALLBACK"),
        "probe must take the fallback path\n{stderr}"
    );
    assert!(
        retired_by_tail,
        "RED: fallback suppressed the group-kill (live m2 past the tail)"
    );
    assert!(
        stderr.contains("R22008-DONE"),
        "probe must cite completion\n{stderr}"
    );
    assert!(
        stderr.contains("R22008-ASSUMED-GROUPED"),
        "fallback must cite the assumed-grouped kill\n{stderr}"
    );
}

/// R22-014 fault leg (toolchain twin): mirror of the lib
/// pair-panic leg (restaged under sleep-858; pre-tail
/// panic discharges m1 + m2 through the unwind; no live
/// sleep-858 survives).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn r22008_pair_panic_discharges_before_unwind() {
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("reportless_fallback_kills_group_unconditionally")
        .arg("--nocapture")
        .env("SCOPEBASE_R22008_FALLBACK_TWIN", "1")
        .env("SCOPEBASE_R22014_PAIR_PANIC", "1")
        .env("SCOPEBASE_R22014_SLEEP_DUR", "858")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("leg child runs");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "leg probe must panic as staged\n{stderr}"
    );
    assert!(
        !stderr.contains("R22008-DONE"),
        "panicking probe must never cite completion\n{stderr}"
    );
    let (m1, tick1): (i32, u64) = stdout
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix("R22008-M1 ")?;
            let (pid, tick) = rest.split_once(' ')?;
            Some((pid.parse().ok()?, tick.parse().ok()?))
        })
        .expect("probe must print custody before panicking");
    match task_starttime_checked(m1) {
        Ok(None) => {}
        Ok(Some(now)) => assert_ne!(
            now, tick1,
            "m1 birth must be retired (stranded by the pre-tail panic)"
        ),
        Err(error) => panic!("m1 drainage unverifiable: {error}"),
    }
    assert!(
        sleep_pids_with_dur("858").is_empty(),
        "no live sleep-858 may survive the unwind"
    );
}

/// R22-009 probe-deny probe (toolchain twin): mirror of
/// the lib probe (healthy staging + custody print +
/// negative-pid-kill denial + reportless tail; the
/// post-reap probe must discriminate errno — ESRCH
/// proves empty, EPERM fails LOUD-UNRESOLVED). RED (old
/// probe: "proven dead" over live `sleep 856`). Duration
/// 856 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn reportless_probe_denied_stays_unresolved_probe() {
    use scopebase_testkit::fixture::linux::seccomp::{install_deny_kill_negative_pid, DenyAction};
    let m1 = unsafe { fork_pausing_grandchild_sleep_jam_noretire("856") }
        .expect("staging broken (pair spawn)");
    // Pre-custody unwinds discharge fully (the filter
    // installs after the print); post-print unwinds
    // retire m1 in-probe while the wrapper sweeps m2 by
    // duration (the M1 line is already flushed).
    let mut _pair = ReportlessPairGuard::armed(m1);
    let tick1 = task_starttime_checked(m1)
        .expect("staging broken (m1 stat)")
        .expect("staging broken (m1 visible)");
    println!("R22009-M1 {m1} {tick1}");
    std::io::Write::flush(&mut std::io::stdout()).expect("custody line flushed");
    // R23-002: `unsupported_arch` skips explicitly
    // (seccomp denial is x86-only — exit 0 with the SKIP
    // marker; the wrapper judges the marker, never the
    // install). Any other install failure is still
    // staging-broken.
    if let Err(error) = install_deny_kill_negative_pid(DenyAction::Eperm) {
        if error.stage() == "unsupported_arch" {
            eprintln!("R22009-SKIP unsupported_arch (seccomp denial unavailable)");
            return;
        }
        panic!("deny installs (staging): {error}");
    }
    let own = unsafe { libc::getpgid(0) };
    let self_pid = std::process::id() as i32;
    assert_eq!(
        unsafe { libc::kill(self_pid, 0) },
        0,
        "staging broken (positive-pid kill denied too?)"
    );
    let probed = unsafe { libc::killpg(own, 0) };
    let errno = std::io::Error::last_os_error().raw_os_error();
    assert_eq!(
        (probed, errno),
        (-1, Some(libc::EPERM)),
        "staging broken (killpg not denied?)"
    );
    retire_reportless_middleman(m1);
    _pair.disarm();
    eprintln!("R22009-DONE");
}

/// R22-009 probe-deny wrapper (toolchain twin): mirror of
/// the lib wrapper (fresh image; m2 LIVE by design —
/// survival proven pre-custody, drained, then the
/// probe's evidence judged: UNRESOLVED, never empty).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn reportless_probe_denied_stays_unresolved() {
    use std::time::Duration;
    if std::env::var("SCOPEBASE_R22009_DENY_KILLPG_TWIN").is_ok() {
        reportless_probe_denied_stays_unresolved_probe();
        return;
    }
    let outcome = run_fresh_probe_collect(
        "SCOPEBASE_R22009_DENY_KILLPG_TWIN",
        "reportless_probe_denied_stays_unresolved",
    );
    let stdout = String::from_utf8_lossy(&outcome.out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&outcome.out.stderr).into_owned();
    let (m1, tick1): (i32, u64) = stdout
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix("R22009-M1 ")?;
            let (pid, tick) = rest.split_once(' ')?;
            Some((pid.parse().ok()?, tick.parse().ok()?))
        })
        .expect("staging broken (no m1 line?)");
    assert!(
        live_sleep_with_dur("856"),
        "staging broken (m2 dead pre-custody — the denial staged nothing?)"
    );
    kill_tick_gated(m1, tick1);
    assert!(
        birth_drained_007(m1, tick1, Duration::from_secs(5)),
        "wrapper must drain m1"
    );
    assert!(
        kill_sleep_with_dur("856"),
        "wrapper must drain the live sleep 856"
    );
    // R23-002: explicit unsupported_arch skip (custody
    // above still proves clean — the probe staged and
    // printed pre-install, then exited 0 — so only the
    // verdicts below are skipped).
    if stderr.contains("R22009-SKIP") {
        eprintln!("skip: seccomp killpg denial unsupported on this arch (see probe stderr)");
        return;
    }
    assert!(!outcome.timed_out, "probe must complete\n{stderr}");
    assert!(outcome.out.status.success(), "probe must exit 0\n{stderr}");
    assert!(
        stderr.contains("grouped at freeze"),
        "probe must take the main grouped path\n{stderr}"
    );
    assert!(
        !stderr.contains("R21008-FALLBACK"),
        "probe must not fall back\n{stderr}"
    );
    assert!(
        stderr.contains("R22009-DONE"),
        "probe must cite completion\n{stderr}"
    );
    assert!(
        !stderr.contains("proven dead"),
        "RED: probe certified death over live m2\n{stderr}"
    );
    assert!(
        stderr.contains("R22009-UNRESOLVED"),
        "probe must cite loud-unresolved on EPERM\n{stderr}"
    );
}

/// R22-016(b) (toolchain twin): TEST-SIDE group re-probe
/// — mirror of the lib helper (ESRCH ⟹ empty; 0 ⟹
/// non-empty; other ⟹ UNRESOLVED).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn reprobe_group_post_tail(m1: i32) -> &'static str {
    // SAFETY: signal-0 probe (no delivery).
    let probed = unsafe { libc::killpg(m1, 0) };
    if probed == 0 {
        return "R22016B-REPROBE-NONEMPTY";
    }
    // R22-009 discipline (shared): ESRCH proves
    // empty; any other error is UNRESOLVED (never an
    // empty citation).
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        return "R22016B-REPROBE-EMPTY";
    }
    "R22016B-REPROBE-UNRESOLVED"
}

/// R22-016(b) pre-exec-stall probe (toolchain twin):
/// mirror of the lib probe (pre-exec-stall staging +
/// scan-blind pin + stopped-grouped pin + FULL
/// kill-denial + tail into the fallback + TEST-SIDE
/// group re-probe, which must refuse the false absence).
/// RED (old `!= 0` re-probe: EMPTY over two live
/// processes). Duration 864 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn reportless_preexec_stall_denied_stays_unresolved_probe() {
    use scopebase_testkit::fixture::linux::seccomp::{install_deny_one, DenyAction};
    let (m1, stub) = unsafe { fork_prestall_grandchild_jam_noretire("864") }
        .expect("staging broken (pair spawn)");
    let tick1 = task_starttime_checked(m1)
        .expect("staging broken (m1 stat)")
        .expect("staging broken (m1 visible)");
    let tick_stub = task_starttime_checked(stub)
        .expect("staging broken (stub stat)")
        .expect("staging broken (stub visible)");
    println!("R22016B-M1 {m1} {tick1}");
    println!("R22016B-STUB {stub} {tick_stub}");
    std::io::Write::flush(&mut std::io::stdout()).expect("custody lines flushed");
    assert!(
        !live_sleep_with_dur("864"),
        "staging broken (stub exec'd?!)"
    );
    let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut pinned = false;
    while std::time::Instant::now() < end {
        match stat_state_pgrp(stub) {
            Some((st, pgrp)) if matches!(st, 'T' | 't') && pgrp == m1 => {
                pinned = true;
                break;
            }
            _ => std::thread::sleep(std::time::Duration::from_millis(1)),
        }
    }
    assert!(pinned, "staging broken (stub never stopped-grouped?)");
    eprintln!("R22016B-SCAN-BLIND");
    // R23-002: `unsupported_arch` skips explicitly
    // (seccomp denial is x86-only — exit 0 with the SKIP
    // marker; the wrapper judges the marker, never the
    // install). Any other install failure is still
    // staging-broken.
    if let Err(error) = install_deny_one(libc::SYS_kill, DenyAction::Eperm) {
        if error.stage() == "unsupported_arch" {
            eprintln!("R22016B-SKIP unsupported_arch (seccomp denial unavailable)");
            return;
        }
        panic!("deny installs (staging): {error}");
    }
    let self_pid = std::process::id() as i32;
    let probed_self = unsafe { libc::kill(self_pid, 0) };
    let errno_self = std::io::Error::last_os_error().raw_os_error();
    assert_eq!(
        (probed_self, errno_self),
        (-1, Some(libc::EPERM)),
        "staging broken (kill not denied?)"
    );
    let own = unsafe { libc::getpgid(0) };
    let probed = unsafe { libc::killpg(own, 0) };
    let errno = std::io::Error::last_os_error().raw_os_error();
    assert_eq!(
        (probed, errno),
        (-1, Some(libc::EPERM)),
        "staging broken (killpg not denied?)"
    );
    retire_reportless_middleman(m1);
    eprintln!("{}", reprobe_group_post_tail(m1));
    assert_eq!(
        stat_state_pgrp(m1),
        Some(('S', m1)),
        "staging broken (m1 not live-pausing post-tail?)"
    );
    assert_eq!(
        stat_state_pgrp(stub),
        Some(('T', m1)),
        "staging broken (stub not live-stopped-grouped post-tail?)"
    );
    eprintln!("R22016B-SURVIVED");
    eprintln!("R22016B-DONE");
}

/// R22-016(b) pre-exec-stall wrapper (toolchain twin):
/// mirror of the lib wrapper (fresh image; survival
/// pinned in-probe; best-effort wrapper custody +
/// load-bearing drains; the re-probe judged UNRESOLVED,
/// never EMPTY).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn reportless_preexec_stall_denied_stays_unresolved() {
    use std::time::Duration;
    if std::env::var("SCOPEBASE_R22016B_PRESTALL_TWIN").is_ok() {
        reportless_preexec_stall_denied_stays_unresolved_probe();
        return;
    }
    let outcome = run_fresh_probe_collect(
        "SCOPEBASE_R22016B_PRESTALL_TWIN",
        "reportless_preexec_stall_denied_stays_unresolved",
    );
    let stdout = String::from_utf8_lossy(&outcome.out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&outcome.out.stderr).into_owned();
    let parse = |tag: &str| -> Option<(i32, u64)> {
        stdout.lines().find_map(|line| {
            let rest = line.strip_prefix(tag)?;
            let (pid, tick) = rest.split_once(' ')?;
            Some((pid.parse().ok()?, tick.parse().ok()?))
        })
    };
    let (m1, tick1): (i32, u64) = parse("R22016B-M1 ").expect("staging broken (no m1 line?)");
    let (stub, tick_stub): (i32, u64) =
        parse("R22016B-STUB ").expect("staging broken (no stub line?)");
    kill_tick_gated(m1, tick1);
    assert!(
        birth_drained_007(m1, tick1, Duration::from_secs(5)),
        "wrapper must drain m1"
    );
    kill_tick_gated(stub, tick_stub);
    assert!(
        birth_drained_007(stub, tick_stub, Duration::from_secs(5)),
        "wrapper must drain the stub"
    );
    // R23-002: explicit unsupported_arch skip (custody
    // above still proves clean — the probe staged and
    // printed pre-install, then exited 0 — so only the
    // verdicts below are skipped).
    if stderr.contains("R22016B-SKIP") {
        eprintln!("skip: seccomp kill denial unsupported on this arch (see probe stderr)");
        return;
    }
    assert!(!outcome.timed_out, "probe must complete\n{stderr}");
    assert!(outcome.out.status.success(), "probe must exit 0\n{stderr}");
    assert!(
        stderr.contains("R22016B-SCAN-BLIND"),
        "probe must pin scan-blindness\n{stderr}"
    );
    assert!(
        stderr.contains("R22016B-SURVIVED"),
        "probe must pin post-tail survival\n{stderr}"
    );
    assert!(
        stderr.contains("R21008-FALLBACK"),
        "tail must take the fallback path (SIGSTOP denied)\n{stderr}"
    );
    assert!(
        stderr.contains("R22016B-DONE"),
        "probe must cite completion\n{stderr}"
    );
    assert!(
        !stderr.contains("R22016B-REPROBE-EMPTY"),
        "RED: re-probe certified EMPTY over live m1 + live stub\n{stderr}"
    );
    assert!(
        stderr.contains("R22016B-REPROBE-UNRESOLVED"),
        "re-probe must cite loud-unresolved on EPERM\n{stderr}"
    );
}

/// R22-016(a) scan-outage probe (toolchain twin): mirror
/// of the lib probe (reported pair kept alive + custody
/// print + one-free-slot outage + live-sleeper scan —
/// the scan must fail LOUD, never false-absent). RED
/// (old scan: the probe's own assert fails WITHOUT the
/// mid-scan marker). Duration 851 is unique to this
/// test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn scan_outage_over_live_sleeper_fails_loud_probe() {
    let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("851") }.expect("pair staged");
    // Rides every exit (no disarm — the probe panics by
    // design at THE scan; same as lib).
    let _pair = ReportlessPairGuard::armed(m1);
    let tick1 = task_starttime_checked(m1)
        .expect("staging broken (m1 stat)")
        .expect("staging broken (m1 visible)");
    let tick2 = task_starttime_checked(m2)
        .expect("staging broken (m2 stat)")
        .expect("staging broken (m2 visible)");
    println!("R22016A-M1 {m1} {tick1}");
    println!("R22016A-M2 {m2} {tick2}");
    std::io::Write::flush(&mut std::io::stdout()).expect("custody lines flushed");
    assert!(
        live_sleep_with_dur("851"),
        "staging broken (scan blind pre-outage?)"
    );
    let mut hold = OutageHold::exhaust();
    hold.release_one();
    assert!(
        live_sleep_with_dur("851"),
        "staging broken (scan false over live m2?)"
    );
    drop(hold);
    eprintln!("R22016A-DONE");
}

/// R22-016(a) scan-outage wrapper (toolchain twin):
/// mirror of the lib wrapper (fresh image; the probe is
/// EXPECTED TO FAIL — the loud scan-panic is the
/// verdict; custody BEFORE verdicts).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn scan_outage_over_live_sleeper_fails_loud() {
    use std::time::Duration;
    if std::env::var("SCOPEBASE_R22016A_OUTAGE_TWIN").is_ok() {
        scan_outage_over_live_sleeper_fails_loud_probe();
        return;
    }
    let outcome = run_fresh_probe_collect(
        "SCOPEBASE_R22016A_OUTAGE_TWIN",
        "scan_outage_over_live_sleeper_fails_loud",
    );
    let stdout = String::from_utf8_lossy(&outcome.out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&outcome.out.stderr).into_owned();
    let parse = |tag: &str| -> Option<(i32, u64)> {
        stdout.lines().find_map(|line| {
            let rest = line.strip_prefix(tag)?;
            let (pid, tick) = rest.split_once(' ')?;
            Some((pid.parse().ok()?, tick.parse().ok()?))
        })
    };
    let (m1, tick1): (i32, u64) = parse("R22016A-M1 ").expect("staging broken (no m1 line?)");
    let (m2, tick2): (i32, u64) = parse("R22016A-M2 ").expect("staging broken (no m2 line?)");
    kill_tick_gated(m1, tick1);
    assert!(
        birth_drained_007(m1, tick1, Duration::from_secs(5)),
        "wrapper must drain m1"
    );
    kill_tick_gated(m2, tick2);
    assert!(
        birth_drained_007(m2, tick2, Duration::from_secs(5)),
        "wrapper must drain m2"
    );
    assert!(!outcome.timed_out, "probe must complete\n{stderr}");
    assert!(
        !outcome.out.status.success(),
        "probe must FAIL (the loud scan-panic is the verdict)\n{stderr}"
    );
    assert!(
        stderr.contains("mid-scan"),
        "RED: scan swallowed the outage (no loud mid-scan failure over live m2)\n{stderr}"
    );
}

/// R22-004(a) (toolchain twin): mirror of the lib
/// absence-proof regression — live ⟹ unproven, zombie ⟹
/// unproven with the status retained (no steal), freed ⟹
/// reaped. RED (neuter: waitpid inside the proof).
/// Durations 965 (live) and 968 (zombie, then freed) are
/// unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn reap_proof_by_absence_never_steals() {
    use std::time::{Duration, Instant};
    let mut live = std::process::Command::new("/bin/sleep")
        .arg("965")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("live spawns");
    let live_pid = live.id() as i32;
    let mut _lguard = SilentChildGuard::new(live_pid);
    assert_eq!(
        prove_reaped_by_absence_toolchain(live_pid),
        Ok(false),
        "live occupant must read unproven (never reaped)"
    );
    let _ = live.kill();
    let _ = live.wait();
    _lguard.disarm();
    let mut zombie = std::process::Command::new("/bin/sleep")
        .arg("968")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("zombie spawns");
    let zombie_pid = zombie.id() as i32;
    let mut _zguard = SilentChildGuard::new(zombie_pid);
    let _ = zombie.kill();
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let state = std::fs::read_to_string(format!("/proc/{zombie_pid}/stat"))
            .ok()
            .and_then(|text| {
                text.rsplit_once(") ")
                    .and_then(|(_, after)| after.split_whitespace().next().map(str::to_string))
            });
        if state.as_deref() == Some("Z") {
            break;
        }
        assert!(
            Instant::now() < end,
            "staging broken (sleeper never zombified)"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        prove_reaped_by_absence_toolchain(zombie_pid),
        Ok(false),
        "zombie occupant must read unproven (never certified)"
    );
    match zombie.try_wait() {
        Ok(Some(status)) => assert!(!status.success(), "zombie must be our SIGKILLed sleeper"),
        other => panic!("proof stole the zombie's status?! got {other:?}"),
    }
    _zguard.disarm();
    assert_eq!(
        prove_reaped_by_absence_toolchain(zombie_pid),
        Ok(true),
        "freed number must read reaped"
    );
}

/// R22-019 (toolchain twin): one allocator-hammer body.
/// Nonblocking — always exits promptly once stopped.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn hammer_body(stop: &std::sync::atomic::AtomicBool) {
    use std::sync::atomic::Ordering;
    let mut n = 0u64;
    while !stop.load(Ordering::Relaxed) {
        let v: Vec<u8> = (0..1000u32).map(|x| (x ^ n as u32) as u8).collect();
        drop(format!("{:?}-{n}", &v[..8]));
        n += 1;
    }
}

/// R22-019 (toolchain twin): RAII contention-hammer set —
/// drop sets stop and joins every STARTED worker
/// (unwind-safe; partial starts join the started subset).
/// Faithful port of the lib set.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct HammerSet {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    done: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl HammerSet {
    fn spawn(count: usize) -> Self {
        use std::sync::atomic::Ordering;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        Self::spawn_on(count, stop, done, |stop, done| {
            std::thread::spawn(move || {
                hammer_body(&stop);
                done.fetch_add(1, Ordering::Relaxed);
            })
        })
    }

    /// R23-001 (twin): injectable spawner — mirror of lib
    /// (incremental Self build; mid-construction spawn
    /// panic drops the partial set, never a bare Vec).
    fn spawn_on(
        count: usize,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        done: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        mut spawn_one: impl FnMut(
            std::sync::Arc<std::sync::atomic::AtomicBool>,
            std::sync::Arc<std::sync::atomic::AtomicUsize>,
        ) -> std::thread::JoinHandle<()>,
    ) -> Self {
        let mut set = Self {
            stop,
            done,
            workers: Vec::with_capacity(count),
        };
        for _ in 0..count {
            let (stop, done) = (set.stop.clone(), set.done.clone());
            set.workers.push(spawn_one(stop, done));
        }
        set
    }

    fn done_handle(&self) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        self.done.clone()
    }
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl Drop for HammerSet {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        self.stop.store(true, Ordering::Relaxed);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

/// R21-017 (toolchain twin): behavioral companion — bounded
/// grandchild reporting under concurrent libc activity
/// (mirror of the audit witness; the deterministic pin is
/// the audit's call-path test). Duration 914 is unique to
/// this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn grandchild_reports_under_libc_contention() {
    // RAII hammers (stop + join on drop — success,
    // unwind, and partial-start paths alike).
    let _hammers = HammerSet::spawn(4);
    let retire = |m1: i32, m2: i32| {
        assert_eq!(
            unsafe { libc::kill(m2, libc::SIGKILL) },
            0,
            "sleeper signaled"
        );
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let dead = match std::fs::read_to_string(format!("/proc/{m2}/stat")) {
                Err(_) => true,
                Ok(text) => {
                    text.rsplit_once(") ")
                        .and_then(|(_, after)| after.split_whitespace().next())
                        == Some("Z")
                }
            };
            if dead {
                break;
            }
            assert!(std::time::Instant::now() < end, "sleeper must die");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            unsafe { libc::kill(m1, libc::SIGKILL) },
            0,
            "middleman signaled"
        );
        let mut mst = 0;
        let mgot = unsafe { libc::waitpid(m1, &mut mst, 0) };
        assert_eq!(mgot, m1, "middleman status drains to us");
    };
    for _ in 0..5 {
        // SAFETY: multithreaded fork with a syscall-only
        // child (audited by the call-path test).
        let (m1, m2) =
            unsafe { fork_pausing_grandchild_sleep("914") }.expect("report must arrive bounded");
        // R21-009: guard at birth (the assert below must
        // not strand the pair).
        let mut pair = MiddlemanPairGuard::armed(m1, m2);
        assert!(m1 > 0 && m2 > 0 && m1 != m2, "pids must be valid");
        retire(m1, m2);
        pair.disarm();
    }
    // Hammers stop + join via `_hammers` drop (RAII).
    drop(_hammers);
}

/// R22-019 (toolchain twin): mirror of the lib hammer
/// regression — injected mid-loop failure and partial
/// start must still stop + join every STARTED worker.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn contention_hammers_stop_on_unwind_and_partial_start() {
    use std::sync::atomic::Ordering;
    // Leg 1: injected mid-loop failure (the RAII set
    // drops at unwind — joined before catch returns).
    let set = HammerSet::spawn(4);
    let done = set.done_handle();
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _set = set;
        for i in 0..5 {
            if i == 2 {
                panic!("R22019 injected mid-loop failure");
            }
        }
    }));
    assert!(failed.is_err(), "injection must unwind");
    assert_eq!(
        done.load(Ordering::Relaxed),
        4,
        "every started worker must stop on unwind"
    );
    // Leg 2: partial start (2 workers, then a spawn
    // failure — the started subset must still stop).
    let set = HammerSet::spawn(2);
    let done = set.done_handle();
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _set = set;
        panic!("R22019 simulated spawn failure");
    }));
    assert!(failed.is_err(), "spawn failure must unwind");
    assert_eq!(
        done.load(Ordering::Relaxed),
        2,
        "every started worker must stop on partial start"
    );
    // Leg 3 (R23-001 twin): a REAL mid-construction spawn
    // failure — mirror of lib (done reads exactly 2).
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut calls = 0u32;
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _set = HammerSet::spawn_on(4, stop, done.clone(), |stop, done| {
            calls += 1;
            if calls == 3 {
                panic!("R23001 injected mid-construction spawn failure");
            }
            std::thread::spawn(move || {
                hammer_body(&stop);
                done.fetch_add(1, Ordering::Relaxed);
            })
        });
    }));
    assert!(failed.is_err(), "spawn failure must unwind");
    assert_eq!(
        done.load(Ordering::Relaxed),
        2,
        "started subset must stop on mid-construction panic"
    );
}

/// R22-012 (toolchain twin): env flag selecting the
/// fault-child branch (fresh image).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
const R22012_FAULT_ENV: &str = "SCOPEBASE_R22012_FAULT";

/// R22-012 (toolchain twin): one hammered sibling fd-op,
/// retry-bounded (same rationale as lib — pressure, not
/// proof; the holder-pid assert discriminates).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn hammer_sibling_fd_op() -> std::io::Result<()> {
    let mut last = std::io::Error::other("unreached");
    for _ in 0..3 {
        let attempt = (|| -> std::io::Result<()> {
            let (read, write) = std::io::pipe()?;
            drop((read, write));
            let file = std::fs::File::open("/dev/null")?;
            drop(file);
            Ok(())
        })();
        match attempt {
            Ok(()) => return Ok(()),
            Err(error) => {
                last = error;
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }
    Err(last)
}

/// R22-012 (toolchain twin): current NOFILE soft limit.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn nofile_soft_limit() -> u64 {
    // SAFETY: getrlimit with a valid local rlimit.
    unsafe {
        let mut limit: libc::rlimit = std::mem::zeroed();
        assert_eq!(
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit),
            0,
            "own rlimit readable"
        );
        limit.rlim_cur as u64
    }
}

/// R21-009 (twin mirror): a failed FIRST observation over
/// a staged middleman pair must unwind through the birth
/// guard — both retired before the panic propagates
/// (mirror of the lib regression; R22-012: fresh-image
/// child holds the fault, birth-aware drainage checks).
/// Duration 109 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn middleman_pair_guard_discharges_on_first_read_failure() {
    if std::env::var(R22012_FAULT_ENV).is_ok() {
        r22012_fault_child_scenario();
        return;
    }
    let me = std::process::id();
    let limit_before = nofile_soft_limit();
    let exe = std::env::current_exe().expect("own test binary");
    let mut child = std::process::Command::new(exe)
        .arg("--exact")
        .arg("middleman_pair_guard_discharges_on_first_read_failure")
        .arg("--nocapture")
        .env(R22012_FAULT_ENV, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("fault child spawns");
    // Covers the hammer-loop expects below (a sibling
    // fd-op failure must not strand the fault child).
    let mut _cguard = SilentChildGuard::new(child.id() as i32);
    // Sibling hammer while the child runs (bounded 60 s —
    // a hung child is killed loud, never an unbounded
    // hang).
    let mut hammered = 0u64;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if child.try_wait().expect("child waitable").is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            panic!("fault child hung past 60 s (killed loud)");
        }
        hammer_sibling_fd_op().expect("sibling fd-op succeeds during fresh-image fault");
        hammered += 1;
    }
    assert!(
        hammered > 100,
        "hammer must pressure the fault window (got {hammered})"
    );
    let out = child.wait_with_output().expect("child reaps");
    _cguard.disarm();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "fault child must exit 0\n{stderr}");
    assert!(
        stderr.contains("R22012-DISCHARGED"),
        "discharge marker\n{stderr}"
    );
    let holder: u32 = stderr
        .lines()
        .find_map(|line| {
            line.strip_prefix("R22012-HOLDER pid=")
                .and_then(|pid| pid.trim().parse().ok())
        })
        .expect("holder marker\n{stderr}");
    assert_ne!(
        holder, me,
        "fault must run in the child image (in-process reintroduction fails here)"
    );
    assert_eq!(
        nofile_soft_limit(),
        limit_before,
        "rlimit preserved across the fault"
    );
}

/// R22-012 child scenario (toolchain twin): the R21-009
/// fault, run ONLY in the fresh-image child. Faithful port
/// of the lib scenario (guard-handoff + confine + fill +
/// faulted first read + birth-aware drain proof). Markers
/// on stderr; any assert-fail exits nonzero (parent fails).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn r22012_fault_child_scenario() {
    eprintln!("R22012-HOLDER pid={}", std::process::id());
    let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("109") }.expect("pair staged");
    // R22-014 guard-handoff (same as lib): outer covers
    // the setup reads, inner sees the fault unwind.
    let mut outer = MiddlemanPairGuard::armed(m1, m2);
    let t1 = task_starttime_checked(m1)
        .expect("middleman stat readable")
        .expect("middleman visible");
    let t2 = task_starttime_checked(m2)
        .expect("grandchild stat readable")
        .expect("grandchild visible");
    outer.disarm();
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _pair = MiddlemanPairGuard::armed(m1, m2);
        let _confined = confine_fd_table_for_exhaustion();
        let mut held = Vec::new();
        while let Ok(file) = std::fs::File::open("/dev/null") {
            held.push(file);
        }
        assert!(!held.is_empty(), "exhaustion must consume fds");
        std::fs::read_to_string(format!("/proc/{m2}/stat")).expect("first read");
    }));
    assert!(failed.is_err(), "faulted first read must panic");
    for (pid, birth, who) in [(m1, t1, "middleman"), (m2, t2, "grandchild")] {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match task_starttime_checked(pid) {
                Ok(Some(now)) if now == birth => {}
                Ok(_) => break,
                Err(error) => panic!("{who} {pid} drainage unverifiable: {error}"),
            }
            assert!(
                std::time::Instant::now() < end,
                "{who} {pid} stranded by the failed first read (guard must retire)"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    eprintln!("R22012-DISCHARGED");
}

/// R22-012 (toolchain twin): env flag selecting the hold
/// characterization child branch (fresh image).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
const R22012_CHAR_ENV: &str = "SCOPEBASE_R22012_CHAR";

/// R22-012 characterization (toolchain twin, PERMANENT):
/// mirror of the lib characterization — a held EMFILE
/// table breaks descriptor siblings by design; the hold
/// runs in the child, the wrapper asserts markers + its
/// own rlimit untouched.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn outage_hold_breaks_siblings_by_design() {
    if std::env::var(R22012_CHAR_ENV).is_ok() {
        let before = nofile_soft_limit();
        let _confined = confine_fd_table_for_exhaustion();
        let mut held = Vec::new();
        while let Ok(file) = std::fs::File::open("/dev/null") {
            held.push(file);
        }
        assert!(!held.is_empty(), "exhaustion must consume fds");
        assert!(
            std::io::pipe().is_err(),
            "sibling pipe must fail under the hold (EMFILE)"
        );
        assert!(
            std::fs::File::open("/dev/null").is_err(),
            "sibling open must fail under the hold (EMFILE)"
        );
        drop(held);
        drop(_confined);
        assert!(
            std::io::pipe().is_ok(),
            "sibling pipe must succeed after the drop"
        );
        assert!(
            std::fs::File::open("/dev/null").is_ok(),
            "sibling open must succeed after the drop"
        );
        assert_eq!(
            nofile_soft_limit(),
            before,
            "single hold must restore the rlimit exactly"
        );
        eprintln!("R22012-CHAR-OK");
        return;
    }
    let limit_before = nofile_soft_limit();
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("outage_hold_breaks_siblings_by_design")
        .arg("--nocapture")
        .env(R22012_CHAR_ENV, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("characterization child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "child must exit 0\n{stderr}");
    assert!(
        stderr.contains("R22012-CHAR-OK"),
        "characterization marker\n{stderr}"
    );
    assert_eq!(
        nofile_soft_limit(),
        limit_before,
        "wrapper rlimit untouched by the child hold"
    );
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
    // R16-011: this probe-first shape is PINNED by IR-002 (a
    // live non-child takes no signal here) — the pinned twin
    // below is the only evolution allowed.
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

/// R16-011: SIGKILL for a TICK-VERIFIED live task — the pinned
/// twin of `retire_child_silent` (which stays probe-first and
/// spares non-children for the UNPINNED path per IR-002;
/// toolchain twin of the audit R16-010 fix, same contract). The
/// pin proves OUR staged task (a recycled number mismatches
/// before this is reached), so a non-child (a staged
/// grandchild — waitpid ECHILDs, never ours to reap) is owed
/// SIGKILL exactly like an owned live child; its parent (the
/// live `sh`) or init reaps. Our zombie discharges (waitpid
/// hit, no kill needed); the bounded reap loop only ever reaps
/// an owned child (ECHILD returns at once). Never panics (drop
/// context).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn retire_task_silent(pid: i32) {
    let mut status = 0;
    // SAFETY: WNOHANG probe of a possibly-owned child; never blocks.
    let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if got == pid {
        // Our zombie discharged — done, no kill needed.
        return;
    }
    // got == 0 (our live child) or got < 0 (not our child — a
    // tick-verified staged task): SIGKILL either way.
    // SAFETY: signal-only to a tick-verified staged task; errors ignored.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        // SAFETY: waitpid on a possibly-owned child; WNOHANG never blocks.
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

/// R18-006: waitpid-assist for hygiene polls (toolchain
/// twin of the audit helper — same contract): reap a
/// tick-verified zombie (our child, or an adoptee under a
/// subreaper/PID1 runner) so stat polls observe its
/// disappearance. Fires ONLY while the number still hosts
/// the expected birth (never steal a recycled number's
/// zombie — IR-002/R16-004; same µs gate→waitpid TOCTOU
/// residual as `await_task_gone_reaping`). Never blocks,
/// never panics. Reap path pinned by the audit adoption
/// probe only (identical prctl/fork/kill/waitpid syscalls —
/// harness-independent mechanics; the wrappers differ by
/// stat-reader name alone).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn waitpid_assist_verified(pid: i32, tick: u64) {
    if task_starttime_checked(pid) == Ok(Some(tick)) {
        let mut status = 0;
        // SAFETY: WNOHANG reap of the verified holder;
        // never blocks. Errors ignored.
        unsafe {
            libc::waitpid(pid, &mut status, libc::WNOHANG);
        }
    }
}

/// R18-007: tick-gated retirement for owned test children
/// (toolchain twin of the audit helper — same contract):
/// the gated signal above plus a bounded reaping wait (a
/// stale `Child::wait` after a raw reap would block on, or
/// steal status from, a recycled replacement; a blind
/// numeric kill+wait would murder it — the gated ops below
/// only run on tick-match). Same return contract as the
/// gate. Never panics.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn retire_tick_gated_toolchain_child(pid: i32, tick: u64) -> bool {
    if task_starttime_checked(pid) != Ok(Some(tick)) {
        return task_starttime_checked(pid).is_ok();
    }
    // SAFETY: tick-pinned owned child; errors ignored.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        // SAFETY: waitpid on a tick-pinned child; never blocks.
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if got == pid || got < 0 {
            return true;
        }
        if Instant::now() >= end {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// R22-003(a): birth-custody tail — skip when already
/// retired, else gated retire + WNOHANG-only (never a
/// blind `Child::kill` + BLOCKING `Child::wait` on a
/// possibly-stale handle: after the guard raw-reaped, the
/// number may host a live recycled child (kill murders) or
/// a zombie one (blocking wait steals its status — or
/// wedges on a live recycler)). `retired` is the custody
/// verdict (skip needs no re-verification — our birth gone
/// means nothing of ours to clean, ever); the unretired
/// arm re-verifies by tick inside the gated retire
/// (belt-and-braces over the single-waiter pin). Loud on
/// the unretired arm (RED-path-only evidence).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn retire_tail_unless_retired(pid: i32, tick: u64, retired: bool, what: &str) {
    if retired {
        return;
    }
    eprintln!("{what}: tail retiring unretired fixture {pid}");
    let _ = retire_tick_gated_toolchain_child(pid, tick);
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

/// R17-008: expected-identity pin with transient retry
/// (toolchain twin of the audit helper — same contract):
/// pins ONLY while the live tick matches `expected`.
/// Transient read ERRORS retry within the budget; a PROVEN
/// mismatch (Ok(Some(other))) or proven gone (Ok(None))
/// refuses immediately (None — retrying would pin whatever
/// arrives next).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn pin_expected_tick_with(
    pid: i32,
    expected: u64,
    read: impl Fn(i32) -> Result<Option<u64>, String>,
) -> Option<u64> {
    let end = Instant::now() + Duration::from_millis(100);
    loop {
        match read(pid) {
            Ok(Some(tick)) if tick == expected => return Some(tick),
            Ok(_) => return None,
            Err(_) if Instant::now() < end => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return None,
        }
    }
}

/// R17-008: the production expected-identity pin reader.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn pin_expected_tick(pid: i32, expected: u64) -> Option<u64> {
    pin_expected_tick_with(pid, expected, task_starttime_checked)
}

/// R13-008: Drop guard retiring an owned fixture child on every
/// exit (early return or panic). Covers pausers (retire) and
/// zombies (discharge status — the kill also reaches a child hung
/// before its immediate exit; an already-exited zombie answers
/// ESRCH and is simply reaped). R16-011: a VERIFIED task takes
/// SIGKILL even when it is not our child (a staged grandchild
/// the pin proves ours — toolchain twin of the audit R16-010
/// fix, same contract).
/// R22-014 (toolchain twin): unwind custody for a
/// jammed-spawn pair (m1 known, m2 unknown — mirror of
/// the lib guard; the drop retires through the panic-free
/// production reportless tail).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct ReportlessPairGuard {
    m1: i32,
    disarmed: bool,
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl ReportlessPairGuard {
    fn armed(m1: i32) -> Self {
        ReportlessPairGuard {
            m1,
            disarmed: false,
        }
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl Drop for ReportlessPairGuard {
    fn drop(&mut self) {
        if !self.disarmed {
            retire_reportless_middleman(self.m1);
        }
    }
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct SilentChildGuard {
    pid: i32,
    tick: Option<u64>,
    disarmed: bool,
    // R19-002: the expected birth (expected-identity
    // guards only — None for bare construction). A
    // refused guard (tick None, expected Some) is NOT
    // disarmed: the drop re-evaluates, so a transient
    // that healed after construction still retires
    // through unwind (mismatch/gone stay silent —
    // R18-003 safety preserved).
    expected: Option<u64>,
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
    /// R17-008 RESERVATION CONTRACT: the bare constructor
    /// authenticates WHATEVER birth currently occupies `pid`
    /// (first pin). Sound ONLY while the caller holds the
    /// unreaped-child reservation (own child, never reaped —
    /// the number cannot have recycled) or pins a birth
    /// sighted-live in the immediately preceding statement
    /// with no intervening pause, kill, expiry, or
    /// publication gap. Received pids (pidfile/pipe) resumed
    /// after any lifecycle gap MUST use `new_expected`
    /// (refuses on mismatch) — auto-pinning a replacement
    /// grants the drop kill authority over a task never owned.
    fn new(pid: i32) -> Self {
        let tick = pin_birth_tick(pid);
        SilentChildGuard {
            pid,
            tick,
            disarmed: false,
            expected: None,
        }
    }
    /// R17-008: expected-identity construction for NON-CHILD
    /// targets (received pids — the caller lacks the
    /// unreaped-child reservation the bare constructor
    /// assumes). Pins ONLY while the live birth matches
    /// `expected`; mismatch, gone, or unreadable-after-budget
    /// refuses (None). R18-003: a refused drop never falls
    /// into child cleanup (that murdered an owned-child
    /// replacement the pin had positively distinguished).
    /// R19-002: refusal DEFERS (it is not terminal, and it
    /// does not disarm): the drop re-evaluates — a transient
    /// that healed after construction retires the verified
    /// birth through unwind, while mismatch/gone stay silent
    /// and unreadable-at-drop takes the fd-less fallback.
    /// (Recover early by re-constructing once reads work; a
    /// late `pin` after refusal is redundant — sound but
    /// unnecessary, since the drop re-verifies either way.)
    /// Never panics. Caller obligation: `expected` must name
    /// the intended birth (a transmitted pair, or a tick
    /// sighted while the target was known-live — never a
    /// post-retire re-read, which could name a squatter).
    fn new_expected(pid: i32, expected: u64) -> Self {
        let tick = pin_expected_tick(pid, expected);
        SilentChildGuard {
            pid,
            tick,
            disarmed: false,
            expected: Some(expected),
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
        // R19-002: a refused guard (expected-identity that
        // found mismatch/gone/unreadable) re-evaluates at
        // drop — a transient that healed after construction
        // must not abandon a known writer. A match pins
        // through the verified path below; gone/mismatch
        // stay silent (R18-003 safety); unreadable takes
        // the fd-less fallback (loud unless ESRCH-gone).
        if self.tick.is_none() {
            if let Some(expected) = self.expected {
                match task_starttime_checked(self.pid) {
                    Ok(Some(now)) if now == expected => {
                        self.tick = Some(expected);
                    }
                    Ok(_) => return,
                    Err(error) => {
                        drop_unresolved_custody(self.pid, expected, &error);
                        return;
                    }
                }
            }
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
            // R16-011: verified-ours takes the pinned twin
            // (signals non-children too); the unpinned arm
            // above stays child-only.
            Some(tick) => match task_starttime_checked(self.pid) {
                Ok(Some(now)) if now == tick => retire_task_silent(self.pid),
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
/// R19003-FLAKE02 (toolchain twin of the audit proof): absence
/// is sound ONLY ns-anchored to the retirement it verifies —
/// freed numbers are retaken within µs-ms (frontier-retake +
/// hint-thieves; audit staging-obs failed 4/15 runs with a
/// foreign birth exactly on vacuous plants), and birth-gating
/// cannot save ms-lifetime fixtures (thief births share the
/// jiffy ~90%). Every staged caller now relies on its frozen
/// post-unwind read; trailing fresh-read absence asserts were
/// removed (suite timing, not retirement). Remaining caller:
/// gone-number only (retired-long-ago, non-frontier).
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
    // R19003-FLAKE02: ns-anchored retirement capture —
    // read immediately post-retire inside the catch (a
    // post-unwind read crosses a µs frontier-retake
    // window; a trailing fresh-read assert crosses ms).
    let state_a = std::cell::Cell::new(None);
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
        state_a.set(Some(task_starttime_checked(pid)));
        observe(pid);
    }));
    // A birth panic stages nothing (slot stays -1 — never
    // waitpid(-1): that would reap ANY sibling child).
    if slot_a.get() > 0 {
        assert_eq!(
            state_a.take(),
            Some(Ok(None)),
            "{tag}: retire must leave the fixture gone"
        );
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
    // R19003-FLAKE02: no trailing fresh-read absence
    // assert — `state` above is the ns-anchored
    // retirement proof (see helper docs).
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
    let parent_pid = parent.id() as i32;
    // R22-014: guard at birth (the pid read below must not
    // strand the sh parent).
    let mut _parent_guard = SilentChildGuard::new(parent_pid);
    let mut line = String::new();
    std::io::BufReader::new(parent.stdout.take().expect("sh stdout"))
        .read_line(&mut line)
        .expect("grandchild pid readable");
    let stranger = line.trim().parse::<i32>().expect("pid parses");
    let stick = task_starttime_checked(stranger)
        .expect("stranger stat readable")
        .expect("stranger present");
    // R22-014: guard at sighting (R16-010 non-child kill —
    // the sanity probes below must not strand the sleep;
    // same birth just sighted-live).
    let mut _stranger_guard = SilentChildGuard::new_expected(stranger, stick);
    assert!(
        _stranger_guard.tick.is_some(),
        "stranger pin must take (staged birth live)"
    );
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
    // number + tick, poll it gone, then reap the publisher
    // (its `wait` ends with the grandchild). R15-003:
    // tick-gated (on RED paths the publisher may have
    // reaped the stranger already — a blind kill would
    // murder a recycled replacement).
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
    _parent_guard.disarm();
    _stranger_guard.disarm();
    assert!(survived, "silent retire must not murder a live non-child");
}

/// R16-011: the PINNED path is the twin of IR-002's unpinned
/// one (toolchain twin of the audit R16-010 fix — same
/// contract) — a tick-verified live NON-child (a staged
/// grandchild, never ours to waitpid) dropped through
/// `SilentChildGuard` must DIE: the pin proves OUR task (a
/// recycled number mismatches and spares, as before) and
/// SIGKILL is owed (its parent — the live publisher — or
/// init reaps; nothing we do can reap it). Pre-fix the drop
/// funnels into the child-only retire and ECHILDs without
/// signaling (RED: the grandchild stays live); post-fix the
/// verified arm signals (GREEN). The verdict reads /proc
/// STATE settled (IR-002 discipline: a tick cannot tell live
/// from zombie, SIGKILL delivery is async).
/// R20-004: locate the controlled pair-publisher bin.
/// Integration tests get `CARGO_BIN_EXE_*`; the deps-dir
/// fallback mirrors the audit harness. Loud when missing.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn pair_publisher_bin() -> std::path::PathBuf {
    if let Some(known) = option_env!("CARGO_BIN_EXE_scopebase-pair-publisher") {
        return std::path::PathBuf::from(known);
    }
    let mut exe = std::env::current_exe().expect("own test binary");
    exe.pop();
    if exe.ends_with("deps") {
        exe.pop();
    }
    let bin = exe.join("scopebase-pair-publisher");
    assert!(
        bin.is_file(),
        "publisher bin missing at {bin:?} (run the full package suite)"
    );
    bin
}

/// R21-007/009/010 (holistic, twin mirror): spawn the
/// controlled pair publisher self-grouped (pgid == publisher
/// pid from microseconds after the fork — the R19-015 rule:
/// the group proof below is vacuous or murderous without
/// it). A setpgid failure is a loud spawn error (never a
/// silent ungrouped publisher). Stdout AND stderr piped —
/// read stderr only AFTER the group cleanup (the sleeper
/// inherits the write end: an early read blocks on a
/// stranded sleeper; post-cleanup all writers are dead so
/// EOF is prompt).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn spawn_self_grouped_publisher(
    secs: &str,
    tail: &str,
    envs: &[(&str, &str)],
) -> std::process::Child {
    use std::os::unix::process::CommandExt as _;
    let mut command = std::process::Command::new(pair_publisher_bin());
    command
        .arg(secs)
        .arg(tail)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    // SAFETY: setpgid on self pre-exec, no userspace state.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    command.spawn().expect("self-grouped publisher spawns")
}

/// R22-001 (toolchain twin): one group member's triage
/// evidence (mirror of the lib struct).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct GroupMember {
    pid: i32,
    birth: Option<(i32, u64)>,
    state: Option<char>,
}

/// R22-001 (toolchain twin): enumerate the CURRENT members
/// of process group `pgid` via /proc (mirror of the lib
/// enumerator — evidence only; the ESRCH probe judges).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn enumerate_group_members(pgid: i32) -> Vec<GroupMember> {
    let mut members = Vec::new();
    let entries = match std::fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => return members,
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let name = match entry.file_name().to_str() {
            Some(name) => name.to_string(),
            None => continue,
        };
        let pid: i32 = match name.parse() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        if !task_pgrp_matches(&name, pgid) {
            continue;
        }
        let birth = match (proc_ppid(pid), task_starttime_checked(pid)) {
            (Some(ppid), Ok(Some(tick))) => Some((ppid, tick)),
            _ => None,
        };
        members.push(GroupMember {
            pid,
            birth,
            state: task_state(pid),
        });
    }
    members
}

/// R22-001 (toolchain twin): fail-fast guard — mirror of
/// the lib guard (all subreaper sets confined fresh-image;
/// a set mark here is a leak — panic loud).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn assert_no_subreaper_leak(what: &str) {
    // The get writes the flag through arg2 (a NULL arg2
    // faults — pass a real slot, check the return too).
    let mut marked: libc::c_int = -1;
    // SAFETY: prctl get-only into a valid local slot.
    let got = unsafe {
        libc::prctl(
            libc::PR_GET_CHILD_SUBREAPER,
            &mut marked as *mut libc::c_int,
            0,
            0,
            0,
        )
    };
    assert_eq!(got, 0, "{what}: subreaper query failed");
    assert_eq!(
        marked, 0,
        "{what}: child-subreaper marked in-process (leak — group drains cannot settle adopted zombies)"
    );
}

/// R21-007/009/010 (holistic, twin mirror): await
/// process-group `pgid` empty (bounded). R22-001: PURE
/// OBSERVATION (mirror of the lib fix — the waitpid(-pgid)
/// drain is deleted; no waits here at all; timeout fails
/// loud with the enumerated member evidence). True only on
/// ESRCH. Never signals fatally (signal 0 — safe on an
/// unpinned number; a recycled pgid fails loud here, never
/// murders). Never panics.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn await_group_empty(pgid: i32, timeout: std::time::Duration) -> bool {
    use std::time::{Duration, Instant};
    let end = Instant::now() + timeout;
    loop {
        // SAFETY: signal 0 probes existence only.
        let probed = unsafe { libc::killpg(pgid, 0) };
        if probed < 0 {
            // SAFETY: errno location for this thread.
            let errno = unsafe { libc::__errno_location().read() };
            if errno == libc::ESRCH {
                return true;
            }
        }
        if Instant::now() >= end {
            // Loud evidence (WHO survived — with
            // ppid/tick/state per member for triage).
            let members = enumerate_group_members(pgid);
            let detail: Vec<String> = members
                .iter()
                .map(|member| {
                    format!(
                        "pid={} ppid={:?} tick={:?} state={:?}",
                        member.pid,
                        member.birth.map(|birth| birth.0),
                        member.birth.map(|birth| birth.1),
                        member.state,
                    )
                })
                .collect();
            eprintln!(
                "group {pgid} not empty after {timeout:?}: {}",
                detail.join(", ")
            );
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// R21-007 (receiver, twin mirror): retire a publisher whose
/// pair never parsed (stranger pid UNKNOWN — no tick-gated
/// kill can name it) via its self-group. Reservation-pinned:
/// the leader is OUR child and NOTHING reaped it yet (no
/// guard armed, no wait called — the number cannot have
/// recycled, so the first tick read below names OUR birth
/// and pgid == pid is certain). Order (R22-001, mirror of
/// the lib reorder): pin + self-group check → killpg FIRST
/// (while the pin holds) → leader kill → await
/// leader-ZOMBIE (death proven, pin STILL held — unreaped)
/// with members drained touch-free (pin re-verified every
/// poll; a mid-drain release panics at once) → reap the
/// leader through its handle (exit status preserved) →
/// ESRCH proof (touch-free — the pin is gone; a recycled
/// pgid fails loud here, never murders). Returns the
/// leader's exit status. PANICS (loud — never silent, never
/// murdering) when the leader is already reaped (reservation
/// violated — a killpg would be unpinned), the pin releases
/// mid-drain (someone reaped behind our back — refused to
/// proceed unpinned), never self-grouped (the killpg would
/// name a foreign group), unreapable, or the group survives
/// the bounded settle. R22-005 (mirror of the lib):
/// unreadable pin reads (outage) route to the degraded
/// reservation path (same contract as the lib) instead of
/// panic-abandoning.
/// The member set is closed (leader + /bin/sleep — neither
/// forks), so one pinned killpg suffices (no post-reap
/// second strike — that would be unpinned murder-bait).
/// Members settle via init (adoption by us is impossible,
/// asserted below).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn retire_unparsed_publisher_group(
    publisher: &mut std::process::Child,
) -> std::process::ExitStatus {
    use std::time::{Duration, Instant};
    let pubpid = publisher.id() as i32;
    // Pin (live or zombie both pin — a zombie IS the
    // unreaped reservation; gone means someone reaped
    // behind our back). The birth tick is kept: every poll
    // below re-verifies it (the pin must hold through the
    // whole drain, not just at entry).
    let pubtick = match task_starttime_checked(pubpid) {
        Ok(Some(tick)) => tick,
        Ok(None) => panic!(
            "unparsed publisher {pubpid} already reaped (reservation violated — \
             group retire refused: unpinned killpg)"
        ),
        Err(error) => {
            return retire_unparsed_degraded_toolchain(
                publisher,
                pubpid,
                DegradedPinToolchain::Handle,
                &format!("tick unreadable: {error}"),
            );
        }
    };
    // Pgrp tri-state: self ⟹ normal (below); foreign ⟹
    // panic (never self-grouped — unchanged); gone ⟹ panic
    // (pin released mid-entry — violation); outage ⟹
    // degraded (tick-pin held).
    match read_pgrp_checked_toolchain(pubpid) {
        Ok(Some(pgrp)) if pgrp == pubpid => {}
        Ok(Some(foreign)) => panic!(
            "unparsed publisher {pubpid} in group {foreign} (never self-grouped — \
             group retire refused: killpg would name a foreign group)"
        ),
        Ok(None) => panic!(
            "unparsed publisher {pubpid} stat malformed (pgrp unparseable — \
             group unverifiable)"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => panic!(
            "unparsed publisher {pubpid} reaped mid-entry (pin released — \
             group retire refused: unpinned killpg)"
        ),
        Err(error) => {
            return retire_unparsed_degraded_toolchain(
                publisher,
                pubpid,
                DegradedPinToolchain::Tick(pubtick),
                &format!("pgrp unreadable: {error}"),
            );
        }
    }
    assert_no_subreaper_leak("retire_unparsed_publisher_group");
    // SAFETY: SIGKILL to our own pinned group, then our
    // own pinned child; errors ignored (a racing death
    // answers ESRCH and the proof below still judges).
    unsafe {
        libc::killpg(pubpid, libc::SIGKILL);
        libc::kill(pubpid, libc::SIGKILL);
    }
    drain_pinned_group(
        pubpid,
        pubtick,
        "unparsed publisher",
        Duration::from_secs(5),
    );
    // Reap the leader through its handle (status kept —
    // instant: already zombie).
    let start = Instant::now();
    let status = loop {
        match publisher.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= Duration::from_secs(5) {
                    panic!("unparsed publisher {pubpid} unreapable after SIGKILL");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("unparsed publisher {pubpid} wait failed: {error:?}"),
        }
    };
    // Prove ESRCH-empty (touch-free observation — safe
    // now the pin is gone; a recycled pgid fails loud
    // here with the member evidence, never murders).
    assert!(
        await_group_empty(pubpid, Duration::from_secs(5)),
        "unparsed publisher {pubpid} group survived the retire"
    );
    status
}

/// R22-005 (toolchain twin): tri-state pgrp read
/// (`task_pgrp_matches` conflates into bool — mirror of
/// the lib helper).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn read_pgrp_checked_toolchain(pid: i32) -> Result<Option<i32>, std::io::Error> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(text
        .rsplit_once(") ")
        .and_then(|(_, after)| after.split_whitespace().nth(2))
        .and_then(|field| field.parse::<i32>().ok()))
}

/// R22-005 (toolchain twin): mirror of the lib degraded
/// pin — `Tick` (a tick read succeeded ⟹ number held ⟹
/// killpg sound) or `Handle` (validated by `try_wait`
/// inside the degraded retire).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[derive(Debug)]
enum DegradedPinToolchain {
    Tick(u64),
    Handle,
}

/// R22-005 (toolchain twin): mirror of the lib
/// outage-degraded unparsed retire — NO /proc reads (all
/// outage-proof); trusts the audited reservation loud
/// (same proof as the lib: the number is HELD so the
/// killpg names our group); returns the leader's status
/// on full discharge, panics loud post-discharge on a
/// residual.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn retire_unparsed_degraded_toolchain(
    publisher: &mut std::process::Child,
    pubpid: i32,
    pin: DegradedPinToolchain,
    why: &str,
) -> std::process::ExitStatus {
    use std::time::{Duration, Instant};
    let pin_note = match pin {
        DegradedPinToolchain::Tick(tick) => format!("tick-pin {tick}"),
        DegradedPinToolchain::Handle => "handle-pin".to_string(),
    };
    eprintln!(
        "R22005-DEGRADED unparsed publisher {pubpid}: {why} — trusting the RESERVATION loud \
         (our unreaped child, self-grouped at spawn, never regroups; pin: {pin_note}; \
         pgrp unverified (outage) — self-groupedness by reservation, not by read)"
    );
    assert_no_subreaper_leak("retire_unparsed_publisher_group (degraded)");
    let mut status = match pin {
        DegradedPinToolchain::Tick(_) => None,
        DegradedPinToolchain::Handle => match publisher.try_wait() {
            Ok(None) => None,
            Ok(Some(status)) => Some(status),
            Err(error) => panic!(
                "unparsed publisher {pubpid} handle stale ({error:?} — reaped behind our \
                 back: reservation violated, unpinned everything refused)"
            ),
        },
    };
    if status.is_none() {
        // SAFETY: killpg under pin + reservation (see the
        // lib proof — the number is HELD so the group is
        // ours).
        unsafe {
            libc::killpg(pubpid, libc::SIGKILL);
            libc::kill(pubpid, libc::SIGKILL);
        }
    } else {
        eprintln!(
            "R22005-DEGRADED unparsed publisher {pubpid}: leader already dead (reaped \
             above — pin released, NO killpg: probe-only)"
        );
    }
    let mut stolen = false;
    if status.is_none() {
        let start = Instant::now();
        status = loop {
            match publisher.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if start.elapsed() >= Duration::from_secs(5) {
                        panic!(
                            "unparsed publisher {pubpid} unreapable after SIGKILL \
                             (degraded — D-state?)"
                        );
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => {
                    eprintln!(
                        "R22005-DEGRADED unparsed publisher {pubpid}: leader reaped behind \
                         our back ({error:?} — status stolen by a sibling wait)"
                    );
                    stolen = true;
                    break None;
                }
            }
        };
    }
    let leader_note = match (&status, stolen) {
        (Some(status), _) => format!("leader reaped ({status:?})"),
        (None, true) => "leader reaped behind our back (status stolen)".to_string(),
        (None, false) => unreachable!("reap loop always resolves"),
    };
    await_group_empty_degraded_toolchain(pubpid, &leader_note);
    match status {
        Some(status) => status,
        None => panic!(
            "unparsed publisher {pubpid} group discharged ({leader_note}) but the status \
             is lost (sibling steal — cannot return what we do not have)"
        ),
    }
}

/// R22-005 (toolchain twin): mirror of the lib
/// outage-proof group-empty probe (killpg-0 only; ESRCH ⟹
/// our group gone; other errno ⟹ fail closed at once;
/// survival past the bound ⟹ loud residual panic).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn await_group_empty_degraded_toolchain(pubpid: i32, leader_note: &str) {
    use std::time::{Duration, Instant};
    let start = Instant::now();
    loop {
        // SAFETY: signal 0 probes only.
        let probed = unsafe { libc::killpg(pubpid, 0) };
        if probed != 0 {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(-999);
            if errno == libc::ESRCH {
                return;
            }
            panic!(
                "unparsed publisher {pubpid} group probe failed with errno {errno} \
                 (foreign group on a recycled pgid? — fail closed; {leader_note})"
            );
        }
        if start.elapsed() >= Duration::from_secs(5) {
            panic!(
                "unparsed publisher {pubpid} group survived the degraded retire \
                 ({leader_note}; sleeper residual — unkillable-by-us post-reap: no pin \
                 to killpg under)"
            );
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// R22-002 (toolchain twin): pinned group drain shared by
/// the unparsed retire and the publisher-cell branches —
/// mirror of the lib helper (leader to ZOMBIE with the pin
/// held throughout + every other member absent, watched
/// touch-free; mid-drain pin release panics at once).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn drain_pinned_group(pubpid: i32, pubtick: u64, what: &str, timeout: std::time::Duration) {
    use std::time::{Duration, Instant};
    let end = Instant::now() + timeout;
    loop {
        match task_starttime_checked(pubpid) {
            Ok(Some(now)) if now == pubtick => {}
            Ok(_) => panic!(
                "{what} {pubpid} pin released mid-drain \
                 (reaped behind our back — refused to proceed unpinned)"
            ),
            Err(_) => {}
        }
        let zombie = task_state(pubpid) == Some('Z');
        let members: Vec<i32> = enumerate_group_members(pubpid)
            .iter()
            .map(|member| member.pid)
            .filter(|pid| *pid != pubpid)
            .collect();
        if zombie && members.is_empty() {
            return;
        }
        if Instant::now() >= end {
            panic!(
                "{what} {pubpid} group drain stuck \
                 (leader zombie: {zombie}; members: {members:?})"
            );
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// R22-002 (toolchain twin): retire a HUNG publisher group —
/// mirror of the lib fn (re-pin first: reaped/recycled →
/// panic WITHOUT killing; kill + killpg pinned → pinned
/// settle → bounded WNOHANG-only handle reap). Returns the
/// leader's exit status. Caller judges hung-ness.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn retire_hung_publisher_group(
    publisher: &mut std::process::Child,
    pubpid: i32,
    pubtick: u64,
) -> std::process::ExitStatus {
    use std::time::{Duration, Instant};
    match task_starttime_checked(pubpid) {
        Ok(Some(now)) if now == pubtick => {}
        Ok(_) => panic!(
            "hung publisher {pubpid} pin lost (reaped/recycled — killpg refused: unpinned murder-bait)"
        ),
        Err(error) => panic!(
            "hung publisher {pubpid} tick unreadable ({error:?}) — group unverifiable"
        ),
    }
    assert_no_subreaper_leak("retire_hung_publisher_group");
    // SAFETY: SIGKILL to our own pinned child, then our
    // own pinned group; errors ignored (a racing death
    // answers ESRCH and the settle below still judges).
    let _ = publisher.kill();
    unsafe {
        libc::killpg(pubpid, libc::SIGKILL);
    }
    drain_pinned_group(pubpid, pubtick, "hung publisher", Duration::from_secs(5));
    let start = Instant::now();
    loop {
        match publisher.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) => {
                if start.elapsed() >= Duration::from_secs(5) {
                    panic!("hung publisher {pubpid} unreapable after SIGKILL");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("hung publisher {pubpid} wait failed: {error:?}"),
        }
    }
}

/// R22-002 (toolchain twin): retire an EXITED publisher
/// group — mirror of the lib fn (re-pin first; record
/// stranded → killpg only when stranded (pinned) → pinned
/// settle → bounded handle reap → touch-free ESRCH proof).
/// Returns (status, stranded, post_empty).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn retire_exited_publisher_group(
    publisher: &mut std::process::Child,
    pubpid: i32,
    pubtick: u64,
) -> (std::process::ExitStatus, bool, bool) {
    use std::time::{Duration, Instant};
    match task_starttime_checked(pubpid) {
        Ok(Some(now)) if now == pubtick => {}
        Ok(_) => panic!(
            "exited publisher {pubpid} pin lost (reaped/recycled — killpg refused: unpinned murder-bait)"
        ),
        Err(error) => panic!(
            "exited publisher {pubpid} tick unreadable ({error:?}) — group unverifiable"
        ),
    }
    assert_no_subreaper_leak("retire_exited_publisher_group");
    let stranded = enumerate_group_members(pubpid)
        .iter()
        .any(|member| member.pid != pubpid);
    // SAFETY: SIGKILL to our own pinned child (zombie noop
    // on real paths) and — only when stranded — our own
    // pinned group; errors ignored (the settle below still
    // judges).
    let _ = publisher.kill();
    if stranded {
        unsafe {
            libc::killpg(pubpid, libc::SIGKILL);
        }
    }
    drain_pinned_group(pubpid, pubtick, "exited publisher", Duration::from_secs(5));
    let start = Instant::now();
    let status = loop {
        match publisher.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= Duration::from_secs(5) {
                    panic!("exited publisher {pubpid} unreapable after SIGKILL");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("exited publisher {pubpid} wait failed: {error:?}"),
        }
    };
    let post_empty = await_group_empty(pubpid, Duration::from_secs(5));
    (status, stranded, post_empty)
}

/// R19-001: pipe-publisher script — the publisher reads its
/// OWN unreaped child's starttime (field 22 of /proc/PID/stat;
/// robust to spaces in comm via the last-") " strip; `${20}` —
/// note braces, `$20` would parse as `$2` + "0") and transmits
/// "pid tick". The publisher holds its child unreaped from birth
/// (it only waits at the end), so the number cannot recycle
/// between spawn and the stat — the transmitted tick names the
/// published birth certainly. Receivers parse with
/// [`parse_published_pair`] and must NEVER first-read the tick
/// (a gap replacement would self-authenticate).
/// R20-004: SUPERSEDED by the controlled
/// `scopebase-pair-publisher` bin (bash reaps at command
/// boundaries). Historical record only, pinned by the golden
/// below; all production callers spawn the bin.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn pair_publisher_script(sleep_secs: &str, tail: &str) -> String {
    format!(
        "sleep {sleep_secs} & P=$!; IFS= read -r T < /proc/$P/stat; \
         T=${{T##*) }}; set -- $T; echo \"$P ${{20}}\"; {tail}"
    )
}

/// R19-001: parse a pipe-published birth pair ("pid tick":
/// exactly two fields, positive pid).
/// R21-007 (twin mirror): the Result core — the receiver's
/// pre-parse failure path retires the unknown-sleeper group
/// BEFORE failing loud, so it needs the cause as a value
/// (never a bare panic past the unreaped leader).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn try_parse_published_pair(line: &str, what: &str) -> Result<(i32, u64), String> {
    let mut parts = line.split_whitespace();
    let pid_text = parts
        .next()
        .ok_or_else(|| format!("{what}: published pair missing pid in {line:?}"))?;
    let pid: i32 = pid_text
        .parse()
        .map_err(|_| format!("{what}: published pid unparsable in {line:?}"))?;
    let tick_text = parts
        .next()
        .ok_or_else(|| format!("{what}: published pair missing tick in {line:?}"))?;
    let tick: u64 = tick_text
        .parse()
        .map_err(|_| format!("{what}: published tick unparsable in {line:?}"))?;
    if parts.next().is_some() || pid <= 0 {
        return Err(format!("{what}: published pair malformed in {line:?}"));
    }
    Ok((pid, tick))
}

/// R19-001: parse a pipe-published birth pair ("pid tick":
/// exactly two fields, positive pid).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn parse_published_pair(line: &str, what: &str) -> (i32, u64) {
    try_parse_published_pair(line, what).unwrap_or_else(|cause| panic!("{cause}"))
}

/// R19-001: the publisher script renders exactly (golden — the
/// `${20}` braces and greedy comm-strip are load-bearing) and the
/// pair parser accepts a golden line.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn pair_publisher_script_renders_golden() {
    assert_eq!(
        pair_publisher_script("57", "wait"),
        "sleep 57 & P=$!; IFS= read -r T < /proc/$P/stat; \
         T=${T##*) }; set -- $T; echo \"$P ${20}\"; wait"
    );
    let (pid, tick) = parse_published_pair("1234 5678", "golden");
    assert_eq!((pid, tick), (1234, 5678));
}

/// R22-020 (toolchain twin): discharge (not vacancy) —
/// mirror of the lib helper (absent OR recycled to a
/// different birth; the original tick is always
/// available at the call sites).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn assert_sleeper_discharged(pid: i32, orig: u64) {
    match task_starttime_checked(pid) {
        Ok(None) => {}
        Ok(Some(now)) if now != orig => {}
        observed => panic!(
            "publisher must reap its zombie (wait tail): number {pid} still the original birth ({observed:?} vs orig {orig})"
        ),
    }
}

/// R20-004 (twin mirror): killing the publisher's child
/// BEFORE the stat must not corrupt the transmitted birth.
/// Same pause-hook flow as the audit harness: stage the
/// sleep under the absent flag, read its live tick, SIGKILL
/// it, poll ZOMBIE, release, require the exact original
/// pair + exit 0 + the number discharged. Duration 85 is
/// unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn pair_publisher_pause_hook_transmits_original_birth() {
    use std::io::BufRead as _;
    let flag = std::env::temp_dir().join(format!(
        "scopebase-r20004-twin-pause-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&flag);
    let mut publisher = std::process::Command::new(pair_publisher_bin())
        .arg("85")
        .arg("wait")
        .env("SCOPEBASE_PUBLISHER_PAUSE_FILE", &flag)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("publisher spawns");
    let pubpid = publisher.id() as i32;
    // R22-014: guard at birth (the children scan + tick
    // read below must not strand the publisher).
    let mut _pguard = SilentChildGuard::new(pubpid);
    let sleep = {
        let mut found = None;
        let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < end {
            let text = std::fs::read_to_string(format!("/proc/{pubpid}/task/{pubpid}/children"))
                .unwrap_or_default();
            let kids: Vec<i32> = text
                .split_whitespace()
                .filter_map(|w| w.parse().ok())
                .collect();
            if kids.len() == 1 {
                found = Some(kids[0]);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        found.expect("publisher must stage exactly one sleep child")
    };
    let orig = task_starttime_checked(sleep)
        .expect("sleep stat readable")
        .expect("sleep live");
    // R22-014: guard at sighting (R16-010 non-child
    // kill — the zombie poll below must not strand
    // the sleep; same birth just sighted-live).
    let mut _sguard = SilentChildGuard::new(sleep);
    // SAFETY: signal-only to the staged sleep.
    assert_eq!(
        unsafe { libc::kill(sleep, libc::SIGKILL) },
        0,
        "sleep signaled"
    );
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if task_state(sleep) == Some('Z') {
            break;
        }
        assert!(
            std::time::Instant::now() < end,
            "sleep must zombify (publisher must not reap it)"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    {
        use std::os::unix::io::AsRawFd as _;
        let mut poller = libc::pollfd {
            fd: publisher
                .stdout
                .as_ref()
                .expect("publisher stdout")
                .as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: polls our own pipe end, zero timeout.
        let ready = unsafe { libc::poll(&mut poller, 1, 0) };
        assert_eq!(ready, 0, "pair must wait on the absent flag (hook engaged)");
    }
    std::fs::write(&flag, "go").expect("flag created");
    let mut line = String::new();
    std::io::BufReader::new(publisher.stdout.take().expect("publisher stdout"))
        .read_line(&mut line)
        .expect("pair line readable");
    let output = publisher.wait_with_output().expect("publisher reaps");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let _ = std::fs::remove_file(&flag);
    let (pid, tick) = parse_published_pair(line.trim(), "paused publication");
    assert_eq!(
        (pid, tick),
        (sleep, orig),
        "transmitted must name the original birth despite pre-stat death\n{stderr}"
    );
    assert!(output.status.success(), "publisher must exit 0\n{stderr}");
    assert_sleeper_discharged(sleep, orig);
    _pguard.disarm();
    _sguard.disarm();
}

/// R21-005 (twin mirror): the controlled publisher must
/// normalize an inherited SIGCHLD=SIG_IGN disposition
/// (SIG_IGN survives exec and auto-reaps). Same launcher
/// as the audit harness: `trap '' CHLD` in a child shell,
/// then exec the publisher — the trap never touches the
/// test's own process. Pre-fix the killed sleep auto-reaps
/// (RED at the zombify poll); post-fix the pair names the
/// original birth. Duration 105 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn pair_publisher_normalizes_inherited_sigchld_ign() {
    use std::io::BufRead as _;
    let flag = std::env::temp_dir().join(format!(
        "scopebase-r21005-twin-pause-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&flag);
    let mut publisher = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("trap '' CHLD; exec \"$0\" \"$@\"")
        .arg(pair_publisher_bin())
        .arg("105")
        .arg("wait")
        .env("SCOPEBASE_PUBLISHER_PAUSE_FILE", &flag)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("launcher spawns");
    let pubpid = publisher.id() as i32;
    // R22-014: guard at birth (the children scan + tick
    // read below must not strand the publisher).
    let mut _pguard = SilentChildGuard::new(pubpid);
    let sleep = {
        let mut found = None;
        let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < end {
            let text = std::fs::read_to_string(format!("/proc/{pubpid}/task/{pubpid}/children"))
                .unwrap_or_default();
            let kids: Vec<i32> = text
                .split_whitespace()
                .filter_map(|w| w.parse().ok())
                .collect();
            if kids.len() == 1 {
                found = Some(kids[0]);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        found.expect("publisher must stage exactly one sleep child")
    };
    let orig = task_starttime_checked(sleep)
        .expect("sleep stat readable")
        .expect("sleep live");
    // R22-014: guard at sighting (R16-010 non-child
    // kill — the zombie poll below must not strand
    // the sleep; same birth just sighted-live).
    let mut _sguard = SilentChildGuard::new(sleep);
    // SAFETY: signal-only to the staged sleep.
    assert_eq!(
        unsafe { libc::kill(sleep, libc::SIGKILL) },
        0,
        "sleep signaled"
    );
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if task_state(sleep) == Some('Z') {
            break;
        }
        assert!(
            std::time::Instant::now() < end,
            "sleep must zombify (publisher must normalize inherited SIG_IGN)"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    {
        use std::os::unix::io::AsRawFd as _;
        let mut poller = libc::pollfd {
            fd: publisher
                .stdout
                .as_ref()
                .expect("publisher stdout")
                .as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: polls our own pipe end, zero timeout.
        let ready = unsafe { libc::poll(&mut poller, 1, 0) };
        assert_eq!(ready, 0, "pair must wait on the absent flag (hook engaged)");
    }
    std::fs::write(&flag, "go").expect("flag created");
    let mut line = String::new();
    std::io::BufReader::new(publisher.stdout.take().expect("publisher stdout"))
        .read_line(&mut line)
        .expect("pair line readable");
    let output = publisher.wait_with_output().expect("publisher reaps");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let _ = std::fs::remove_file(&flag);
    let (pid, tick) = parse_published_pair(line.trim(), "paused publication");
    assert_eq!(
        (pid, tick),
        (sleep, orig),
        "transmitted must name the original birth despite pre-stat death\n{stderr}"
    );
    assert!(output.status.success(), "publisher must exit 0\n{stderr}");
    assert_sleeper_discharged(sleep, orig);
    _pguard.disarm();
    _sguard.disarm();
}

/// R22-020 (toolchain twin): discharge survives
/// replacement — mirror of the lib regression (legs 1-3
/// everywhere: vacancy passes, live-under-mismatched-tick
/// passes, still-original fails loud-caught; leg 4 steers
/// a REAL replacement onto the freed number, best-effort).
/// Live-child legs run their helper assert under
/// catch_unwind + cleanup + re-assert (the twin has no
/// RAII guard type — RED runs stay clean without one).
/// RED (vacancy-only helper: legs 2 and 4 fail). Duration
/// 867 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn sleeper_discharge_recognized_across_replacement() {
    use std::time::{Duration, Instant};
    // Numeric reap-by-number (own unreaped child — no
    // pidfd anywhere in this test).
    let reap_number = |pid: i32, tick: u64, who: &str| {
        // SAFETY: SIGKILL to our own unreaped child.
        assert_eq!(
            unsafe { libc::kill(pid, libc::SIGKILL) },
            0,
            "{who} signaled"
        );
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let mut st = 0;
            // SAFETY: WNOHANG reap of our own killed child.
            let _ = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) };
            if task_starttime_checked(pid) != Ok(Some(tick)) {
                break;
            }
            assert!(Instant::now() < end, "{who} must drain");
            std::thread::sleep(Duration::from_millis(1));
        }
    };
    let spawn_sleeper = || {
        let child = std::process::Command::new("/bin/sleep")
            .arg("867")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("sleeper spawns");
        let pid = child.id() as i32;
        let tick = task_starttime_checked(pid)
            .expect("sleeper stat readable")
            .expect("sleeper visible");
        (child, pid, tick)
    };
    // Leg 1 (vacancy): reaped number, original tick.
    let (dead, dpid, dtick) = spawn_sleeper();
    reap_number(dpid, dtick, "leg-1 sleeper");
    let _ = dead;
    assert_sleeper_discharged(dpid, dtick);
    // Leg 2 (retick): LIVE number under a mismatched
    // tick (catch + cleanup + re-assert: RED-clean
    // without a guard type).
    let (live, lpid, ltick) = spawn_sleeper();
    let leg2 = std::panic::catch_unwind(|| assert_sleeper_discharged(lpid, ltick.wrapping_add(1)));
    reap_number(lpid, ltick, "leg-2 sleeper");
    let _ = live;
    assert!(
        leg2.is_ok(),
        "live number under a mismatched tick is discharged"
    );
    // Leg 3 (violation): LIVE number under its OWN tick
    // (caught, never escaping).
    let (ours, opid, otick) = spawn_sleeper();
    let violation = std::panic::catch_unwind(|| assert_sleeper_discharged(opid, otick));
    reap_number(opid, otick, "leg-3 sleeper");
    let _ = ours;
    assert!(
        violation.is_err(),
        "original birth must fail the discharge check"
    );
    let payload = violation.unwrap_err();
    let text = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(
        text.contains("must reap"),
        "violation must cite the wait tail\n{text}"
    );
    // Leg 4 (steered replacement): REAL new birth on leg
    // 1's freed number (best-effort: skips loud when
    // unsteerable/stolen/same-jiffy).
    let last_before = std::fs::read_to_string("/proc/sys/kernel/ns_last_pid").ok();
    let mut placed = None;
    for _ in 0..5 {
        if !locked_steer_next_pid(dpid) {
            break;
        }
        let child = std::process::Command::new("/bin/sleep")
            .arg("867")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("replacement spawns");
        let rpid = child.id() as i32;
        if rpid != dpid {
            let rtick = task_starttime_checked(rpid)
                .expect("stranger stat readable")
                .expect("stranger visible");
            reap_number(rpid, rtick, "stolen placement");
            continue;
        }
        placed = Some(child);
        break;
    }
    if let Some(last) = last_before {
        locked_restore_hint(last.trim());
    }
    let replacement = match placed {
        Some(child) => child,
        None => {
            eprintln!("skip: replacement unplaceable (steering unavailable or number contended)");
            return;
        }
    };
    let rtick = task_starttime_checked(dpid)
        .expect("replacement stat readable")
        .expect("replacement visible");
    if rtick == dtick {
        reap_number(dpid, rtick, "same-jiffy replacement");
        let _ = replacement;
        eprintln!("skip: replacement shares the original jiffy (tick-granularity residual)");
        return;
    }
    let leg4 = std::panic::catch_unwind(|| assert_sleeper_discharged(dpid, dtick));
    reap_number(dpid, rtick, "replacement");
    let _ = replacement;
    assert!(
        leg4.is_ok(),
        "steered replacement is a discharge of the original"
    );
}

/// Observe-before-cleanup: RED runs retire the survivor so the
/// failure stays clean. Duration 57 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn child_guard_drop_retires_verified_non_child() {
    use std::io::BufRead as _;
    let mut parent = std::process::Command::new(pair_publisher_bin())
        .arg("57")
        .arg("wait")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("publisher spawns");
    let mut line = String::new();
    std::io::BufReader::new(parent.stdout.take().expect("publisher stdout"))
        .read_line(&mut line)
        .expect("grandchild pid readable");
    // R19-001: transmitted pair (the publisher's own
    // stat — no receiver first-read).
    // R16-011: custody before the sanity reads (the drop
    // under test moves this guard into its own scope
    // below) — expected-identity, so a reap + recycle
    // between publication and acquisition refuses instead
    // of authenticating the replacement.
    let (grand, tick) = parse_published_pair(line.trim(), "grandchild publication");
    let pinned = SilentChildGuard::new_expected(grand, tick);
    // Sanity: live, and not our child (the ECHILD the old
    // path hid behind).
    assert!(
        matches!(task_state(grand), Some(state) if state != 'Z'),
        "staged grandchild must be live"
    );
    {
        let mut status = 0;
        // SAFETY: WNOHANG probe only.
        let got = unsafe { libc::waitpid(grand, &mut status, libc::WNOHANG) };
        assert!(got < 0, "staged grandchild must not be our child");
    }
    // R18-005: no late-pin — a refusal here means the
    // transmitted birth is gone or unreadable (stage
    // broken), and the retirement under test needs a
    // pinned guard now (R19-002: the drop would
    // re-evaluate at unwind, but this test asserts the
    // pin lands at acquisition, not later).
    {
        let fired = pinned;
        assert!(
            fired.tick.is_some(),
            "acquisition must pin the transmitted birth (stage broken otherwise)"
        );
    } // Drop fires here.
      // R17-009: DISCHARGE required (not merely death) — the
      // live publisher reaps promptly; a lingering zombie past the
      // window is unresolved (the old Z-or-gone verdict masked
      // undischarged kills). R17-010: strict retirement
      // evidence — unreadable samples keep polling and fail
      // loud past the bound (never certified as gone).
    let retired = await_task_gone_reaping(grand, tick, Duration::from_secs(5));
    // Cleanup (runs on RED too): tick-gated kill (R15-003 —
    // a blind kill would risk a recycled replacement), poll
    // gone, then reap the publisher (its `wait` ends
    // with the grandchild).
    let _ = kill_tick_gated(grand, tick);
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if task_starttime_checked(grand) != Ok(Some(tick)) {
            break;
        }
        assert!(Instant::now() < end, "staged grandchild must die");
        std::thread::sleep(Duration::from_millis(10));
    }
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if parent.try_wait().expect("parent wait").is_some() {
            break;
        }
        assert!(Instant::now() < end, "publisher must exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        retired,
        "pinned guard drop must retire the verified grandchild"
    );
}

/// R17-009: toolchain twin — kill an ADOPTED grandchild via
/// the pinned drop, then require status DISCHARGE (not
/// merely death). The publisher exits immediately (no wait)
/// so the sleeper is orphaned to init; the pinned drop signals
/// it; init reaps. The verdict requires GONE — a lingering
/// zombie past the window is unresolved. Duration 76 is
/// unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn adopted_kill_discharges_through_init() {
    use std::io::BufRead as _;
    let mut publisher = std::process::Command::new(pair_publisher_bin())
        .arg("76")
        .arg("exit 0")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("publisher spawns");
    let mut line = String::new();
    std::io::BufReader::new(publisher.stdout.take().expect("publisher stdout"))
        .read_line(&mut line)
        .expect("orphan pid readable");
    // R19-001: transmitted pair (parsed before the
    // publisher is reaped — the tick crosses the publication,
    // never a post-gap first-read).
    let (orphan, otick) = parse_published_pair(line.trim(), "orphan publication");
    // Reap the publisher: the sleeper is necessarily adopted away
    // (proven by construction — no ppid parse needed).
    let status = publisher.wait().expect("publisher exit");
    assert!(status.success(), "publisher must exit clean");
    // Sanity: live, and not our child.
    assert!(
        matches!(task_state(orphan), Some(state) if state != 'Z'),
        "adopted sleeper must be live"
    );
    {
        let mut status = 0;
        // SAFETY: WNOHANG probe only.
        let got = unsafe { libc::waitpid(orphan, &mut status, libc::WNOHANG) };
        assert!(got < 0, "adopted sleeper must not be our child");
    }
    // Pinned drop kills (R18-004: expected-identity
    // over the transmitted birth — a reap + recycle
    // between publication and acquisition refuses instead
    // of authenticating the replacement; a refusal stands
    // down and the discharge verdict below fails loud).
    {
        let fired = SilentChildGuard::new_expected(orphan, otick);
        assert!(
            fired.tick.is_some(),
            "acquisition must pin the transmitted birth"
        );
    } // Drop fires here.
      // Verdict: DISCHARGED (gone) — init reaps promptly.
      // R17-010: strict evidence — unreadable samples keep
      // polling and fail loud past the bound.
    let discharged = await_task_gone_reaping(orphan, otick, Duration::from_secs(5));
    // Cleanup (mutant-clean): tick-gated kill,
    // waitpid-assisted poll gone (R18-006: under a
    // subreaper/PID1 runner the killed orphan reparents to
    // the suite as a zombie — stat alone would time out).
    let _ = kill_tick_gated(orphan, otick);
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        waitpid_assist_verified(orphan, otick);
        if task_starttime_checked(orphan) != Ok(Some(otick)) {
            break;
        }
        assert!(Instant::now() < end, "adopted sleeper must die");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        discharged,
        "adopted kill must discharge through the adopter, not linger as zombie"
    );
}

/// R17-007: probe body (fresh image,
/// SCOPEBASE_R17007_NONCHILD) — toolchain twin of the audit
/// pin-recovery mirror: fail the constructor reads through
/// their budget (EMFILE), succeed the explicit birth read
/// after restore, late-pin the recovered tick, drop, require
/// the known grandchild retired. RED (constructor-pin
/// assert): unwind drops unpinned, ECHILDs past the live
/// grandchild. Duration 43 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn nonchild_pin_recovery_probe() {
    use std::io::BufRead as _;
    // R19003-FLAKE01: confine the table before any
    // exhaustion below (fresh image — the limit dies
    // with the probe).
    let _confined = confine_fd_table_for_exhaustion();
    let mut parent = std::process::Command::new(pair_publisher_bin())
        .arg("43")
        .arg("wait")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("publisher spawns");
    let mut line = String::new();
    std::io::BufReader::new(parent.stdout.take().expect("publisher stdout"))
        .read_line(&mut line)
        .expect("grandchild pid readable");
    // R19-001: transmitted pair (parsed pre-exhaustion —
    // pipe reads need no new fd — so recovery never depends
    // on a post-restore first-read, which would
    // self-authenticate a gap replacement).
    let (grand, tick) = parse_published_pair(line.trim(), "grandchild publication");
    // Fail the constructor reads: exhaust through
    // construction (the retry budget expires to None).
    let mut held = Vec::new();
    while let Ok(file) = std::fs::File::open("/dev/null") {
        held.push(file);
    }
    assert!(!held.is_empty(), "exhaustion must consume fds");
    let mut pinned = SilentChildGuard::new(grand);
    assert!(
        pinned.tick.is_none(),
        "construction must fail under EMFILE (stage broken otherwise)"
    );
    drop(held);
    // R17-007: pin-before-panic — the constructor
    // exhausted its budget (None); the transmitted tick
    // reaches the guard HERE, before every fallible check
    // below (R18-005: a panic anywhere below unwinds
    // through a PINNED guard that retires the known
    // grandchild).
    if pinned.tick.is_none() {
        pinned.pin(tick);
        eprintln!("R17007 construction pin missed; late-pinned transmitted tick");
    }
    // Post-restore verification (post-pin, so
    // unwind-safe): the table works again and still
    // observes the transmitted birth.
    assert_eq!(
        task_starttime_checked(grand),
        Ok(Some(tick)),
        "restored table must re-observe the transmitted birth"
    );
    // Sanity: live, and not our child.
    assert!(
        matches!(task_state(grand), Some(state) if state != 'Z'),
        "staged grandchild must be live"
    );
    {
        let mut status = 0;
        // SAFETY: WNOHANG probe only.
        let got = unsafe { libc::waitpid(grand, &mut status, libc::WNOHANG) };
        assert!(got < 0, "staged grandchild must not be our child");
    }
    // Caught (probe scaffolding): RED runs reach cleanup.
    let fired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _fired = pinned;
    })); // Drop fires here (scope end or unwind).
         // R17-009: DISCHARGE required (not merely death) — the
         // live publisher reaps promptly; a lingering zombie past the
         // window is unresolved. R17-010: strict evidence —
         // unreadable samples keep polling and fail loud past
         // the bound.
    let retired = await_task_gone_reaping(grand, tick, Duration::from_secs(5));
    // Cleanup (runs on RED too): tick-gated kill, poll gone,
    // reap the publisher.
    let _ = kill_tick_gated(grand, tick);
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if task_starttime_checked(grand) != Ok(Some(tick)) {
            break;
        }
        assert!(Instant::now() < end, "staged grandchild must die");
        std::thread::sleep(Duration::from_millis(10));
    }
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if parent.try_wait().expect("parent wait").is_some() {
            break;
        }
        assert!(Instant::now() < end, "publisher must exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(retired, "recovered pin must retire the known grandchild");
    assert!(fired.is_ok(), "pin scope must not panic");
    eprintln!("R17007-RECOVERED retired=1");
}

/// R17-007: toolchain twin — a constructor that exhausts its
/// retry budget (None) while the explicit birth read succeeds
/// must pass the recovered tick to the guard (late-pin).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn nonchild_recovered_pin_retires_on_drop() {
    if std::env::var("SCOPEBASE_R17007_NONCHILD").is_ok() {
        nonchild_pin_recovery_probe();
        return;
    }
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("nonchild_recovered_pin_retires_on_drop")
        .arg("--nocapture")
        .env("SCOPEBASE_R17007_NONCHILD", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "probe must retire through the recovered pin\n{stderr}"
    );
    assert!(
        stderr.contains("R17007-RECOVERED retired=1"),
        "probe must cite the retirement\n{stderr}"
    );
}

/// R18-005 (toolchain twin): probe body (fresh image,
/// SCOPEBASE_R18005) — exhaust construction, recover the
/// birth tick, then fail a diagnostic write (read-only
/// handle): the recovered tick must reach the guard BEFORE
/// the fallible check, so the pinned unwind-drop retires +
/// discharges the grandchild before the failure reports.
/// RED (pin after the failure point): the unwind drops
/// R20-008 (toolchain twin): O_EXCL claim with
/// owned-reclaim. Twin-port of the audit `claim_excl_file`
/// (`fixture/linux/audit.rs`, IR-001 shape): `create_new`
/// never follows a symlink and never blocks on a fifo; an
/// own-uid leftover unlinks and retries once; a foreign
/// plant refuses loud.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn claim_excl_file(path: &std::path::Path, what: &str) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let attempt = || {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    };
    match attempt() {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            use std::os::unix::fs::MetadataExt as _;
            // SAFETY: getuid queries only.
            let ours = std::fs::symlink_metadata(path)
                .map(|meta| meta.uid() == unsafe { libc::getuid() })
                .unwrap_or(false);
            if !ours {
                return Err(format!(
                    "{what} {path:?} preplanted by another owner: refusing"
                ));
            }
            std::fs::remove_file(path)
                .map_err(|error| format!("{what} {path:?} stale reclaim failed: {error}"))?;
            attempt().map_err(|error| format!("{what} {path:?} reclaim failed: {error}"))
        }
        Err(error) => Err(format!("{what} {path:?} claim failed: {error}")),
    }
}

/// R20-008 (toolchain twin): create + write the probe
/// diagnostics file through the O_EXCL claim. Twin-port of
/// the audit `write_diag_excl`.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn write_diag_excl(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let mut file = claim_excl_file(path, "diagnostics")?;
    file.write_all(bytes)
        .map_err(|error| format!("diagnostics {path:?} unwritten: {error}"))
}

/// R20-008 (toolchain twin): open the probe diagnostics
/// for read — O_NOFOLLOW + O_NONBLOCK + own-uid +
/// regular-file. Twin-port of the audit `open_diag_read`
/// INCLUDING the R20-009 O_NONBLOCK (a fifo swapped
/// between create and open returns at once and the
/// regular-file check refuses — never blocks).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn open_diag_read(path: &std::path::Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("diagnostics {path:?} unreadable: {error}"))?;
    let meta = file
        .metadata()
        .map_err(|error| format!("diagnostics {path:?} unstattable: {error}"))?;
    // SAFETY: getuid queries only.
    if meta.uid() != unsafe { libc::getuid() } {
        return Err(format!("diagnostics {path:?} not owned by us: refusing"));
    }
    if !meta.is_file() {
        return Err(format!("diagnostics {path:?} not a regular file: refusing"));
    }
    Ok(file)
}

/// R21-016 (toolchain twin): rescue write-open for the FIFO
/// watchdog — nonblocking (a refused-and-closed worker
/// leaves no reader; a blocking rescue would hang FOREVER).
/// A genuinely read-blocked worker IS a waiting reader, so
/// the nonblocking open still succeeds and unblocks.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn open_fifo_rescue_write(diag: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(diag)
}

/// unpinned and ECHILDs past the live grandchild. Duration
/// 905 is unique to this test. Fresh image: whole-table
/// exhaustion is process-shared — in-process staging flaked
/// under suite EMFILE pressure.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn recovered_pin_precedes_fallible_probe() {
    use std::io::{BufRead as _, Write as _};
    // R19003-FLAKE01: confine the table before any
    // exhaustion below (fresh image — the limit dies
    // with the probe).
    let _confined = confine_fd_table_for_exhaustion();
    let mut parent = std::process::Command::new(pair_publisher_bin())
        .arg("905")
        .arg("wait")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("publisher spawns");
    let mut line = String::new();
    std::io::BufReader::new(parent.stdout.take().expect("publisher stdout"))
        .read_line(&mut line)
        .expect("grandchild pid readable");
    // R19-001: transmitted pair (parsed pre-exhaustion —
    // pipe reads need no new fd — so recovery never depends
    // on a post-restore first-read).
    let (grand, tick) = parse_published_pair(line.trim(), "grandchild publication");
    // Fail the constructor reads: exhaust through
    // construction (the retry budget expires to None).
    let mut held = Vec::new();
    while let Ok(file) = std::fs::File::open("/dev/null") {
        held.push(file);
    }
    assert!(!held.is_empty(), "exhaustion must consume fds");
    let pinned = SilentChildGuard::new(grand);
    assert!(
        pinned.tick.is_none(),
        "construction must fail under EMFILE (stage broken otherwise)"
    );
    drop(held);
    // R20-007: the recovered tick reaches the guard HERE —
    // before diag creation and every fallible check below
    // (a creation failure must unwind through a PINNED
    // guard — the old order created first and stranded the
    // grandchild past an ECHILD skip). Bare-new guard: pin
    // is sound. Twin of the audit R19-010 reorder.
    let mut pinned = pinned;
    if pinned.tick.is_none() {
        pinned.pin(tick);
    }
    // Diagnostics file, opened read-only below (the write
    // fails for real — no suite-wide interference, unlike
    // closing stderr).
    let diag = std::env::temp_dir().join(format!("scopebase-r18005-tc-{}.log", std::process::id()));
    // Clear either-shape stale litter (a killed RED run can
    // leave the steered directory behind).
    let _ = std::fs::remove_file(&diag);
    let _ = std::fs::remove_dir(&diag);
    // R20-007 steering: pre-create a directory at the OWN
    // diag path (the probe knows its pid; the parent cannot
    // pre-plant racelessly) — creation itself must fail,
    // through the pinned unwind.
    let steer_dir = std::env::var("SCOPEBASE_R19010_TC_DIR").is_ok();
    if steer_dir {
        std::fs::create_dir(&diag).expect("steering plants a directory at the diag path");
    }
    let fired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _fired = pinned;
        // R20-008: hardened creation + read (O_EXCL claim,
        // NOFOLLOW + NONBLOCK + own-uid + regular-file) —
        // twin of the audit R19-011 path.
        write_diag_excl(&diag, b"r18005 diagnostics\n").expect("diagnostics created");
        let mut log = open_diag_read(&diag).expect("diagnostics readable");
        writeln!(log, "R18005 recovered tick={tick}").expect("diagnostic write");
    }));
    if steer_dir {
        // The failure must BE the creation failure (not
        // a later line): the expect payload says so.
        let payload = fired.unwrap_err();
        let message = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        assert!(
            message.contains("diagnostics created"),
            "steered failure must be the creation failure, got {message:?}"
        );
    } else {
        assert!(
            fired.is_err(),
            "diagnostic write must fail (read-only handle)"
        );
    }
    // Observe before cleanup: the grandchild must be gone
    // (retired + discharged by the unwind-drop).
    let retired = await_task_gone_reaping(grand, tick, Duration::from_secs(5));
    // Cleanup (runs on RED too): tick-gated kill, poll
    // gone, reap the publisher.
    let _ = kill_tick_gated(grand, tick);
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if task_starttime_checked(grand) != Ok(Some(tick)) {
            break;
        }
        assert!(Instant::now() < end, "staged grandchild must die");
        std::thread::sleep(Duration::from_millis(10));
    }
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if parent.try_wait().expect("parent wait").is_some() {
            break;
        }
        assert!(Instant::now() < end, "publisher must exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    // Cleanup runs on RED too (the steered plant is a
    // directory — rmdir, not remove_file).
    let _ = std::fs::remove_dir(&diag);
    let _ = std::fs::remove_file(&diag);
    assert!(
        retired,
        "pinned unwind must retire before the failure reports"
    );
    if steer_dir {
        eprintln!("R19010-TC-CREATION retired=1");
    } else {
        eprintln!("R18005-RECOVERED retired=1");
    }
}

/// R18-005 (toolchain twin): the recovered tick must reach
/// the guard BEFORE the next fallible check (fresh-image
/// wrapper — the probe body above runs in a child with its
/// own fd table).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn recovered_pin_precedes_fallible_checks() {
    if std::env::var("SCOPEBASE_R18005").is_ok() {
        recovered_pin_precedes_fallible_probe();
        return;
    }
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("recovered_pin_precedes_fallible_checks")
        .arg("--nocapture")
        .env("SCOPEBASE_R18005", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "probe must retire through the preceding pin\n{stderr}"
    );
    assert!(
        stderr.contains("R18005-RECOVERED retired=1"),
        "probe must cite the retirement\n{stderr}"
    );
}

/// R20-007 (toolchain twin): failing the diag creation
/// itself must still unwind through the pinned guard —
/// retirement + discharge before the creation failure
/// reports. Probe-side steering (SCOPEBASE_R19010_TC_DIR):
/// the probe pre-creates a directory at its own diag path,
/// so the exclusive create refuses. RED (pin after
/// creation): the unwind drops unpinned, ECHILD-skips past
/// the live grandchild, and the probe fails its retirement
/// assert. Fresh-image wrapper — the probe body is shared
/// with R18-005. Twin of the audit
/// `diag_creation_failure_unwinds_pinned`.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn diag_creation_failure_unwinds_pinned() {
    if std::env::var("SCOPEBASE_R19010_TC_DIR").is_ok() {
        recovered_pin_precedes_fallible_probe();
        return;
    }
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("diag_creation_failure_unwinds_pinned")
        .arg("--nocapture")
        .env("SCOPEBASE_R19010_TC_DIR", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "probe must retire through the preceding pin\n{stderr}"
    );
    assert!(
        stderr.contains("R19010-TC-CREATION retired=1"),
        "probe must cite the retirement\n{stderr}"
    );
}

/// R20-008 (toolchain twin): a preplanted symlink at the
/// diagnostics path must not redirect the creation write
/// into a victim. Twin of the audit
/// `diag_symlink_plant_leaves_victim_intact` (same shape,
/// twin helpers).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn diag_symlink_plant_leaves_victim_intact() {
    let stem = format!("scopebase-r19011-tc-symlink-{}", std::process::id());
    let diag = std::env::temp_dir().join(format!("{stem}.log"));
    let victim = std::env::temp_dir().join(format!("{stem}.victim"));
    let _ = std::fs::remove_file(&diag);
    let _ = std::fs::remove_file(&victim);
    std::fs::write(&victim, "r19011-sentinel").expect("victim staged");
    std::os::unix::fs::symlink(&victim, &diag).expect("diag symlink planted");
    let created = write_diag_excl(&diag, b"r18005 diagnostics\n");
    let content = std::fs::read(&victim).expect("victim readable");
    let _ = std::fs::remove_file(&diag);
    let _ = std::fs::remove_file(&victim);
    assert!(
        created.is_ok(),
        "creation must succeed past an own-uid plant"
    );
    assert_eq!(
        content, b"r19011-sentinel",
        "creation must write no byte through a planted diag symlink"
    );
}

/// R20-008 (toolchain twin): a preplanted fifo at the
/// diagnostics path must not block creation. Twin of the
/// audit `diag_fifo_plant_never_blocks_creation`.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn diag_fifo_plant_never_blocks_creation() {
    use std::os::unix::ffi::OsStrExt as _;
    let stem = format!("scopebase-r19011-tc-fifo-{}", std::process::id());
    let diag = std::env::temp_dir().join(format!("{stem}.log"));
    let _ = std::fs::remove_file(&diag);
    let cpath = std::ffi::CString::new(diag.as_os_str().as_bytes()).expect("diag path is C-safe");
    // SAFETY: mkfifo on our own temp path; mode 600.
    assert_eq!(
        unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) },
        0,
        "fifo planted"
    );
    let (tx, rx) = std::sync::mpsc::channel();
    let worker_path = diag.clone();
    let worker = std::thread::spawn(move || {
        let _ = tx.send(write_diag_excl(&worker_path, b"r18005 diagnostics\n"));
    });
    let created = rx.recv_timeout(std::time::Duration::from_secs(10));
    let _ = std::fs::remove_file(&diag);
    let created = created.expect("creation must complete past a fifo plant (never block)");
    let _ = worker.join();
    assert!(
        created.is_ok(),
        "creation must succeed past an own-uid fifo plant"
    );
}

/// R20-008 (toolchain twin): the diagnostics read handle
/// must not follow a create→open re-plant into a victim.
/// Twin of the audit `diag_read_handle_refuses_replant`.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn diag_read_handle_refuses_replant() {
    use std::io::Read as _;
    let stem = format!("scopebase-r19011-tc-swap-{}", std::process::id());
    let diag = std::env::temp_dir().join(format!("{stem}.log"));
    let victim = std::env::temp_dir().join(format!("{stem}.victim"));
    let _ = std::fs::remove_file(&diag);
    let _ = std::fs::remove_file(&victim);
    write_diag_excl(&diag, b"r18005 diagnostics\n").expect("diag created");
    std::fs::write(&victim, "r19011-sentinel").expect("victim staged");
    std::fs::remove_file(&diag).expect("swap unlinks own diag");
    std::os::unix::fs::symlink(&victim, &diag).expect("swap plants symlink");
    let opened = open_diag_read(&diag);
    let mut followed_content = None;
    if let Ok(mut file) = opened {
        let mut probe = String::new();
        if file.read_to_string(&mut probe).is_ok() {
            followed_content = Some(probe);
        }
    }
    let victim_content = std::fs::read(&victim).expect("victim readable");
    let _ = std::fs::remove_file(&diag);
    let _ = std::fs::remove_file(&victim);
    assert!(
        followed_content.is_none(),
        "read handle must refuse a re-planted symlink, followed into {followed_content:?}"
    );
    assert_eq!(
        victim_content, b"r19011-sentinel",
        "victim must keep its sentinel"
    );
}

/// R20-008 (toolchain twin): a fifo swapped in between
/// diag create and read-open must neither block the open
/// nor be followed. Twin of the audit
/// `diag_fifo_swap_never_blocks_read_open` (R20-009 shape:
/// O_NONBLOCK + regular-file refusal).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn diag_fifo_swap_never_blocks_read_open() {
    use std::io::Read as _;
    use std::os::unix::ffi::OsStrExt as _;
    let stem = format!("scopebase-r20009-tc-fifo-{}", std::process::id());
    let diag = std::env::temp_dir().join(format!("{stem}.log"));
    let _ = std::fs::remove_file(&diag);
    write_diag_excl(&diag, b"r20009 diagnostics\n").expect("diag created");
    // Positive control: the real diag opens and reads.
    let mut control = String::new();
    open_diag_read(&diag)
        .expect("regular diag must open")
        .read_to_string(&mut control)
        .expect("regular diag must read");
    assert_eq!(control, "r20009 diagnostics\n", "control must read through");
    // Swap in the fifo (the create→open re-plant,
    // sequenced instead of racing).
    std::fs::remove_file(&diag).expect("swap unlinks own diag");
    let cpath = std::ffi::CString::new(diag.as_os_str().as_bytes()).expect("diag path is C-safe");
    // SAFETY: mkfifo on our own temp path; mode 600.
    assert_eq!(
        unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) },
        0,
        "fifo planted"
    );
    let (tx, rx) = std::sync::mpsc::channel();
    let worker_path = diag.clone();
    let worker = std::thread::spawn(move || {
        let _ = tx.send(open_diag_read(&worker_path));
    });
    let mut blocked = false;
    let refused = match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(result) => result,
        Err(_) => {
            blocked = true;
            // Unblock the worker (a writer releases the
            // read open; the worker then refuses on the
            // type check and exits — even RED leaks no
            // thread). R21-016: nonblocking rescue (a
            // refused-and-closed worker leaves no reader).
            let _ = open_fifo_rescue_write(&diag);
            rx.recv_timeout(std::time::Duration::from_secs(10))
                .expect("worker must exit after unblock")
        }
    };
    let _ = worker.join();
    let _ = std::fs::remove_file(&diag);
    assert!(!blocked, "read-open must not block on a swapped-in fifo");
    assert!(
        refused.is_err(),
        "read-open must refuse a fifo, got {refused:?}"
    );
}

/// R21-016 (toolchain twin): the watchdog's rescue open must
/// never block — mirror of the audit regression (a
/// refused-and-closed worker stalled pre-send leaves no
/// reader; a blocking rescue hangs FOREVER). R22-021: the
/// worker/main rendezvous is EXPLICIT — no 100ms/300ms
/// timing asserts (scheduling skew can neither flake nor
/// vacate them): the worker signals refusal-established
/// (proving it RAN and refused — rescue is truly
/// post-refusal, never never-started-vacuous), then HOLDS
/// its send until released; the main thread awaits the
/// signal, rescues, releases, and demands the refused
/// result. Two schedule cells (delayed receiver / delayed
/// worker) skew WHO waits — the rendezvous orders
/// everything causally, so both cells assert the same
/// outcomes. Rescue still runs in a thread (RED fails
/// instead of hanging the suite). RED (blocking): 5s
/// timeout → panic. GREEN (O_NONBLOCK): ENXIO at once.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn diag_fifo_rescue_open_never_blocks() {
    use std::os::unix::ffi::OsStrExt as _;
    use std::time::Duration;
    // Schedule cells: (worker pre-open delay, main
    // pre-rescue delay). Cell "rx": the receiver is
    // late (worker held 300ms+ pre-send). Cell "tx":
    // the worker is late (refusal awaited, never
    // assumed).
    for (cell, worker_pre_delay, main_pre_rescue_delay) in [
        ("rx", Duration::ZERO, Duration::from_millis(300)),
        ("tx", Duration::from_millis(300), Duration::ZERO),
    ] {
        let stem = format!("scopebase-r21016-rescue-tc-{}-{cell}", std::process::id());
        let diag = std::env::temp_dir().join(format!("{stem}.log"));
        let _ = std::fs::remove_file(&diag);
        let cpath =
            std::ffi::CString::new(diag.as_os_str().as_bytes()).expect("diag path is C-safe");
        // SAFETY: mkfifo on our own temp path; mode 600.
        assert_eq!(
            unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) },
            0,
            "cell {cell}: fifo planted"
        );
        let (tx, rx) = std::sync::mpsc::channel();
        let (refused_tx, refused_rx) = std::sync::mpsc::channel::<bool>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let worker_path = diag.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(worker_pre_delay);
            let result = open_diag_read(&worker_path);
            // Rendezvous: refusal established (proves the
            // worker RAN and refused — the rescue below
            // is truly post-refusal), then HOLD the send
            // until released (post-refusal pre-send
            // stall, steered not slept).
            refused_tx.send(result.is_err()).expect("refusal signaled");
            release_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("release arrives");
            let _ = tx.send(result);
        });
        // Await refusal-established (bounded — a
        // never-started worker times out here instead
        // of passing vacuous).
        let refused_flag = match refused_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(flag) => flag,
            Err(_) => panic!(
                "cell {cell}: worker must establish refusal (never-started workers must not pass vacuous)"
            ),
        };
        assert!(refused_flag, "cell {cell}: worker must have refused");
        // Delayed-receiver skew lands here (the worker
        // is held pre-send through the rendezvous).
        std::thread::sleep(main_pre_rescue_delay);
        // Rescue in a thread: RED must fail, never hang.
        let rescue_path = diag.clone();
        let (rtx, rrx) = std::sync::mpsc::channel();
        let _rescue = std::thread::spawn(move || {
            let outcome = open_fifo_rescue_write(&rescue_path).is_ok();
            let _ = rtx.send(outcome);
        });
        if rrx.recv_timeout(Duration::from_secs(5)).is_err() {
            panic!(
                "cell {cell}: rescue open must complete (a blocking rescue hangs with no reader)"
            );
        }
        // Release the worker; demand its refused result.
        if release_tx.send(()).is_err() {
            panic!("cell {cell}: release sent");
        }
        let refused = match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(result) => result,
            Err(_) => panic!("cell {cell}: worker must still deliver"),
        };
        assert!(
            refused.is_err(),
            "cell {cell}: worker must have refused, got {refused:?}"
        );
        let _ = worker.join();
        let _ = std::fs::remove_file(&diag);
    }
}

/// R19-002 (toolchain twin): probe body (fresh image,
/// SCOPEBASE_R19002) — exhaust construction (refusal),
/// restore readable identity, then inject a later caller
/// failure: the refused guard must re-evaluate at drop and
/// retire the known writer (healed transient), while a
/// genuine mismatch stays silent. Duration 911 is unique to
/// this test. Fresh image: whole-table exhaustion is
/// process-shared.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn refused_guard_heals_at_drop_probe() {
    use std::io::BufRead as _;
    // R19003-FLAKE01: confine the table before any
    // exhaustion below (fresh image — the limit dies
    // with the probe).
    let _confined = confine_fd_table_for_exhaustion();
    let mut parent = std::process::Command::new(pair_publisher_bin())
        .arg("911")
        .arg("wait")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("publisher spawns");
    let mut line = String::new();
    std::io::BufReader::new(parent.stdout.take().expect("publisher stdout"))
        .read_line(&mut line)
        .expect("grandchild pair readable");
    let (grand, transmitted) = parse_published_pair(line.trim(), "grandchild publication");
    // Mismatch control first (genuine mismatch stays
    // silent — the R18-003 safety, pinned inside this
    // regression too).
    {
        let refused = SilentChildGuard::new_expected(grand, transmitted.wrapping_add(7));
        assert!(
            refused.tick.is_none(),
            "mismatched expected birth must refuse"
        );
    } // Drop fires here: must stand down.
    assert_task_settled_live(
        grand,
        transmitted,
        2,
        "mismatched refusal must spare the live grandchild",
    );
    // Heal arm: exhaust through construction (the retry
    // budget expires to None).
    let mut held = Vec::new();
    while let Ok(file) = std::fs::File::open("/dev/null") {
        held.push(file);
    }
    assert!(!held.is_empty(), "exhaustion must consume fds");
    let guard = SilentChildGuard::new_expected(grand, transmitted);
    assert!(
        guard.tick.is_none(),
        "construction must refuse under EMFILE (stage broken otherwise)"
    );
    drop(held);
    // Later caller failure (reads healed): the unwind
    // must retire through the re-evaluated drop.
    let fired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _fired = guard;
        panic!("R19002 injected post-restore failure");
    }));
    assert!(fired.is_err(), "injection must unwind");
    // Observe before cleanup: retired + discharged by
    // the drop.
    let retired = await_task_gone_reaping(grand, transmitted, Duration::from_secs(5));
    // Cleanup (runs on RED too): tick-gated kill, poll
    // gone, reap the publisher.
    let _ = kill_tick_gated(grand, transmitted);
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if task_starttime_checked(grand) != Ok(Some(transmitted)) {
            break;
        }
        assert!(Instant::now() < end, "staged grandchild must die");
        std::thread::sleep(Duration::from_millis(10));
    }
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if parent.try_wait().expect("parent wait").is_some() {
            break;
        }
        assert!(Instant::now() < end, "publisher must exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        retired,
        "re-evaluated drop must retire after the failure reports"
    );
    eprintln!("R19002-HEALED retired=1");
}

/// R19-002 (toolchain twin): a refused guard re-evaluates at
/// drop — a transient that healed after construction must
/// retire through unwind (fresh-image wrapper — the probe body
/// above runs in a child with its own fd table).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn refused_guard_heals_at_drop() {
    if std::env::var("SCOPEBASE_R19002").is_ok() {
        refused_guard_heals_at_drop_probe();
        return;
    }
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("refused_guard_heals_at_drop")
        .arg("--nocapture")
        .env("SCOPEBASE_R19002", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "probe must retire through the re-evaluated drop\n{stderr}"
    );
    assert!(
        stderr.contains("R19002-HEALED retired=1"),
        "probe must cite the retirement\n{stderr}"
    );
}

/// R17-008: toolchain twin — the first pin on a received pid
/// must not authenticate a replacement birth. Transmit (pid,
/// tick), run the pause-scale lifecycle, steer a
/// different-birth non-child onto the freed number, resume
/// construction + drop: the replacement survives
/// settled-live. RED (bare constructor): the first pin
/// authenticates the replacement and the pinned drop murders
/// it. GREEN (expected-identity): refusal, silent drop.
/// Duration 46 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn child_expected_pin_refuses_recycled_non_child() {
    use std::io::BufRead as _;
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
    let spawn_sh = || {
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 46 & echo $!; wait")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("sh spawns")
    };
    let read_sleep = |sh: &mut std::process::Child| -> i32 {
        let mut line = String::new();
        std::io::BufReader::new(sh.stdout.take().expect("sh stdout"))
            .read_line(&mut line)
            .expect("sleep pid readable");
        line.trim().parse::<i32>().expect("pid parses")
    };
    // TRANSMIT: stage sh1's sleeper, learn (pid, tick).
    let mut sh1 = spawn_sh();
    let want = read_sleep(&mut sh1);
    let orig_tick = task_starttime_checked(want)
        .expect("transmitted stat readable")
        .expect("transmitted visible");
    // Pause-scale lifecycle: the sleeper dies, the shell
    // reaps it and exits, the number frees.
    assert!(
        kill_tick_gated(want, orig_tick),
        "transmitted sleeper signaled"
    );
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if sh1.try_wait().expect("sh1 wait").is_some() {
            break;
        }
        assert!(Instant::now() < end, "publishing shell must exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(task_starttime_checked(want), Ok(None), "number must free");
    // REPLACE: steer sh2's sleeper (a non-child) onto the
    // freed number (hint want-2: sh takes want-1, its
    // sleeper takes want).
    let _nsflock = ns_last_pid_flock();
    let mut placed = None;
    for _ in 0..100 {
        if !steer_next_pid_unlocked(want - 1) {
            break;
        }
        let mut sh2 = spawn_sh();
        let sleep = read_sleep(&mut sh2);
        if sleep == want {
            match task_starttime_checked(want) {
                Ok(Some(t)) if t != orig_tick => {
                    placed = Some((sh2, t));
                    break;
                }
                Ok(Some(_)) => {
                    // Same-tick retake (S100): retire,
                    // restore, skip loud below.
                    let _ = kill_tick_gated(want, orig_tick);
                    let _ = sh2.kill();
                    let _ = sh2.wait();
                    drop(_nsflock);
                    locked_restore_hint(&last_before);
                    eprintln!("skip: same-tick retake (S100 — untestable this run)");
                    return;
                }
                _ => {
                    let _ = sh2.kill();
                    let _ = sh2.wait();
                    continue;
                }
            }
        }
        // Miss: retire the known sleep, then its shell (no
        // leak on any path).
        if let Ok(Some(t)) = task_starttime_checked(sleep) {
            let _ = kill_tick_gated(sleep, t);
        }
        let _ = sh2.kill();
        let _ = sh2.wait();
    }
    // R17-006: custody across the restore (fresh, live,
    // microsecond window — bare construction is sound here
    // per the reservation contract).
    // R18-008 residual: an unpinned drop is child-only
    // (ECHILD-silent on the non-child sleeper) — pin
    // failure + restore panic together strand
    // (double-fault, accepted).
    let mut restore_guard = placed.as_ref().map(|_| SilentChildGuard::new(want));
    drop(_nsflock);
    locked_restore_hint(&last_before);
    if let Some(guard) = restore_guard.as_mut() {
        guard.disarm();
    }
    let (mut sh2, replacetick) = match placed {
        Some(placed) => placed,
        None => {
            eprintln!("skip: replacement retake contended");
            return;
        }
    };
    // RESUME (GREEN: expected-identity refuses the
    // recycled number — the live birth is not the
    // transmitted one).
    {
        let guard = SilentChildGuard::new_expected(want, orig_tick);
        assert!(
            guard.tick.is_none(),
            "constructor must refuse the recycled number"
        );
    } // Drop fires here (unpinned: silent).
    assert_task_settled_live(
        want,
        replacetick,
        2,
        "replacement must survive resumed construction",
    );
    // Cleanup: retire the replacement, reap sh2.
    let _ = kill_tick_gated(want, replacetick);
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if task_starttime_checked(want) != Ok(Some(replacetick)) {
            break;
        }
        assert!(Instant::now() < end, "replacement must die in cleanup");
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = sh2.wait();
}

/// R18-004 (toolchain twin): pausing an actual pipe-pid
/// caller between publication and acquisition must not grant
/// authority over a replacement. Stage sh1's sleeper,
/// transmit (pid, tick), run the pause-scale lifecycle,
/// steer a DIFFERENT-birth non-child onto the freed number,
/// then resume the caller-shaped acquisition + drop: the
/// replacement must survive settled-live. RED (bare
/// acquisition, the original caller): the first pin
/// authenticates the replacement and the drop murders it.
/// GREEN (expected-identity over the transmitted pair): the
/// constructor refuses and the drop stays silent. Duration
/// 903 is unique to this test.
#[test]
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn pipe_acquisition_refuses_recycled_publication() {
    use std::io::BufRead as _;
    let _serial = STEER_SERIAL
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
    let spawn_sh = || {
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 903 & echo $!; wait")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("sh spawns")
    };
    let read_sleep = |sh: &mut std::process::Child| -> i32 {
        let mut line = String::new();
        std::io::BufReader::new(sh.stdout.take().expect("sh stdout"))
            .read_line(&mut line)
            .expect("sleep pid readable");
        line.trim().parse::<i32>().expect("pid parses")
    };
    // TRANSMIT: stage sh1's sleeper, learn (pid, tick).
    let mut sh1 = spawn_sh();
    let want = read_sleep(&mut sh1);
    let orig_tick = task_starttime_checked(want)
        .expect("transmitted stat readable")
        .expect("transmitted visible");
    // Pause-scale lifecycle: the sleeper dies, the shell
    // reaps it and exits, the number frees.
    assert!(
        kill_tick_gated(want, orig_tick),
        "transmitted sleeper signaled"
    );
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if sh1.try_wait().expect("sh1 wait").is_some() {
            break;
        }
        assert!(Instant::now() < end, "publishing shell must exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(task_starttime_checked(want), Ok(None), "number must free");
    // REPLACE: steer sh2's sleeper (a non-child) onto the
    // freed number (hint want-1: sh takes want-1, its
    // sleeper takes want).
    let _nsflock = ns_last_pid_flock();
    let mut placed = None;
    for _ in 0..100 {
        if !steer_next_pid_unlocked(want - 1) {
            break;
        }
        let mut sh2 = spawn_sh();
        let sleep = read_sleep(&mut sh2);
        if sleep == want {
            match task_starttime_checked(want) {
                Ok(Some(t)) if t != orig_tick => {
                    placed = Some((sh2, t));
                    break;
                }
                Ok(Some(_)) => {
                    let _ = kill_tick_gated(want, orig_tick);
                    let _ = sh2.kill();
                    let _ = sh2.wait();
                    drop(_nsflock);
                    locked_restore_hint(&last_before);
                    eprintln!("skip: same-tick retake (S100 — untestable this run)");
                    return;
                }
                _ => {
                    let _ = sh2.kill();
                    let _ = sh2.wait();
                    continue;
                }
            }
        }
        if let Ok(Some(t)) = task_starttime_checked(sleep) {
            let _ = kill_tick_gated(sleep, t);
        }
        let _ = sh2.kill();
        let _ = sh2.wait();
    }
    // R18-008: custody across the restore (mirror of the
    // twin test's R17-006 guard — a restore panic here
    // stranded sh2 plus its sleeper). Residual: an
    // unpinned drop is child-only (ECHILD-silent on the
    // non-child sleeper) — pin failure + restore panic
    // together strand (double-fault, accepted).
    let mut restore_guard = placed.as_ref().map(|_| SilentChildGuard::new(want));
    drop(_nsflock);
    locked_restore_hint(&last_before);
    if let Some(guard) = restore_guard.as_mut() {
        guard.disarm();
    }
    let (mut sh2, replacetick) = match placed {
        Some(placed) => placed,
        None => {
            eprintln!("skip: replacement retake contended");
            return;
        }
    };
    assert_ne!(
        replacetick, orig_tick,
        "steered replacement must be a different birth (non-vacuity)"
    );
    // RESUME (GREEN: expected-identity refuses the
    // recycled number — the live birth is not the
    // transmitted one; RED was bare acquisition here,
    // which pinned the replacement and murdered it).
    {
        let acquired = SilentChildGuard::new_expected(want, orig_tick);
        assert!(
            acquired.tick.is_none(),
            "resumed acquisition must refuse the recycled number"
        );
    } // Drop fires here (refused: silent).
    assert_task_settled_live(
        want,
        replacetick,
        2,
        "replacement must survive resumed acquisition",
    );
    // Cleanup: retire the replacement, reap sh2.
    let _ = kill_tick_gated(want, replacetick);
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if task_starttime_checked(want) != Ok(Some(replacetick)) {
            break;
        }
        assert!(Instant::now() < end, "replacement must die in cleanup");
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = sh2.wait();
}

/// R19-001 (toolchain twin): pipe publication must transmit the
/// birth — the receiver's acquisition tick crosses the
/// publication gap in the publication, never via a post-gap
/// first-read (which self-authenticates a gap replacement and
/// murders it — demonstrated RED on the audit twin). Pair
/// publishers + transmitted acquisition: refusal, silence,
/// survival. Duration 908 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn pipe_publication_transmits_birth_across_replacement() {
    use std::io::BufRead as _;
    let _serial = STEER_SERIAL
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
    // Pair publishers (production post-fix shape).
    let spawn_publisher = || {
        std::process::Command::new(pair_publisher_bin())
            .arg("908")
            .arg("wait")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("publisher spawns")
    };
    let read_pair = |publisher: &mut std::process::Child| -> (i32, u64) {
        let mut line = String::new();
        std::io::BufReader::new(publisher.stdout.take().expect("publisher stdout"))
            .read_line(&mut line)
            .expect("sleep pair readable");
        parse_published_pair(line.trim(), "sleep publication")
    };
    let mut pub1 = spawn_publisher();
    let (want, transmitted) = read_pair(&mut pub1);
    // Steering kill (choreography, using the transmitted
    // birth — pub1 holds its child unreaped, so the number
    // is stable): drives the pause-scale lifecycle below.
    assert!(
        kill_tick_gated(want, transmitted),
        "published sleeper signaled"
    );
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if pub1.try_wait().expect("pub1 wait").is_some() {
            break;
        }
        assert!(Instant::now() < end, "publishing publisher must exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(task_starttime_checked(want), Ok(None), "number must free");
    // REPLACE: steer pub2's sleeper (a non-child) onto the
    // freed number. pub2 transmits its own pair — the
    // replacement's birth arrives without any receiver
    // first-read (pub2 holds it unreaped throughout).
    let _nsflock = ns_last_pid_flock();
    let mut placed = None;
    for _ in 0..100 {
        if !steer_next_pid_unlocked(want - 1) {
            break;
        }
        let mut pub2 = spawn_publisher();
        let (sleep, sleep_tick) = read_pair(&mut pub2);
        if sleep == want {
            if sleep_tick != transmitted {
                placed = Some((pub2, sleep_tick));
                break;
            }
            let _ = kill_tick_gated(want, transmitted);
            let _ = pub2.kill();
            let _ = pub2.wait();
            drop(_nsflock);
            locked_restore_hint(&last_before);
            eprintln!("skip: same-tick retake (S100 — untestable this run)");
            return;
        }
        // Miss: retire via the transmitted birth (pub2
        // holds it unreaped), then its publisher.
        let _ = kill_tick_gated(sleep, sleep_tick);
        let _ = pub2.kill();
        let _ = pub2.wait();
    }
    let mut restore_guard = placed.as_ref().map(|_| SilentChildGuard::new(want));
    drop(_nsflock);
    locked_restore_hint(&last_before);
    if let Some(guard) = restore_guard.as_mut() {
        guard.disarm();
    }
    let (mut pub2, replacetick) = match placed {
        Some(placed) => placed,
        None => {
            eprintln!("skip: replacement retake contended");
            return;
        }
    };
    assert_ne!(
        replacetick, transmitted,
        "steered replacement must be a different birth (non-vacuity)"
    );
    // RESUME (GREEN: transmitted acquisition — the tick
    // crossed the gap in the publication, never via a
    // post-gap first-read; the constructor refuses the
    // recycled number and the drop stays silent).
    {
        let acquired = SilentChildGuard::new_expected(want, transmitted);
        assert!(
            acquired.tick.is_none(),
            "resumed acquisition must refuse the recycled number"
        );
    } // Drop fires here (refused: silent).
    assert_task_settled_live(
        want,
        replacetick,
        2,
        "replacement must survive resumed acquisition",
    );
    // Cleanup: retire the replacement, reap pub2.
    let _ = kill_tick_gated(want, replacetick);
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if task_starttime_checked(want) != Ok(Some(replacetick)) {
            break;
        }
        assert!(Instant::now() < end, "replacement must die in cleanup");
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = pub2.wait();
}

/// R18-003 (toolchain twin): an expected-identity REFUSAL must
/// stand down — the drop must not run child cleanup over a
/// number positively known to host another birth. Live owned
/// child + mismatched expected tick: construct (refuses),
/// drop, require the child still live. RED (refusal falls
/// into the child-cleanup arm): the drop murders the child.
/// Duration 899 is unique to this test.
#[test]
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn expected_pin_refusal_spares_live_owned_child() {
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("899")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("sleeper spawns");
    let pid = child.id() as i32;
    // R20-010: custody AT birth (mirror the audit R19-012
    // pattern — the starttime read below must never run
    // unguarded; disarmed after the explicit retire).
    let mut birth = SilentChildGuard::new(pid);
    let tick = task_starttime_checked(pid)
        .expect("sleeper stat readable")
        .expect("sleeper visible");
    {
        let refused = SilentChildGuard::new_expected(pid, tick.wrapping_add(7));
        assert!(
            refused.tick.is_none(),
            "mismatched expected birth must refuse"
        );
    } // Drop fires here: must stand down.
    let end = Instant::now() + Duration::from_millis(200);
    while Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        matches!(child.try_wait(), Ok(None)),
        "refused drop must spare the live owned child"
    );
    assert_eq!(
        task_starttime_checked(pid),
        Ok(Some(tick)),
        "refused drop must not disturb the live birth"
    );
    let _ = child.kill();
    let _ = child.wait();
    birth.disarm();
}

/// R18-003 (toolchain twin): refusal over a ZOMBIE owned child
/// must preserve its status for the owner (no reap by the
/// refused drop). RED (refusal falls into child cleanup): the
/// drop reaps and our wait finds ECHILD. Exit 99 is unique to
/// this test.
#[test]
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn expected_pin_refusal_preserves_zombie_owned_child() {
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 99")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("sh spawns");
    let pid = child.id() as i32;
    // R20-010: custody AT birth (the zombie-settle loop and
    // stat reads below must never run unguarded; disarmed
    // after our own wait preserves the status).
    let mut birth = SilentChildGuard::new(pid);
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if matches!(task_state(pid), Some('Z')) {
            break;
        }
        assert!(Instant::now() < end, "setup child never zombied");
        std::thread::sleep(Duration::from_millis(1));
    }
    let tick = task_starttime_checked(pid)
        .expect("zombie stat readable")
        .expect("zombie visible");
    {
        let refused = SilentChildGuard::new_expected(pid, tick.wrapping_add(7));
        assert!(
            refused.tick.is_none(),
            "mismatched expected birth must refuse"
        );
    } // Drop fires here: must not reap.
    let status = child.wait().expect("zombie status stays with us");
    birth.disarm();
    assert_eq!(status.code(), Some(99), "exit code must survive");
}

/// R20-010(1): custody AT birth cleans up failed first
/// observations — the R18-003 refusal fixtures ran stat
/// reads with no guard (a panic stranded sleep-899). Two
/// phases: (a) pinned guard + injected post-guard failure →
/// unwind retires through the verified drop; (b) unpinned
/// guard under EMFILE (the pin exhausts to None) + a failing
/// observation read → unwind retires through fd-less
/// child-only cleanup. Both require disappearance after
/// restore (observe-before-cleanup: evidence, explicit
/// retire of leftovers, then the verdict — RED runs stay
/// clean). Durations 923/924 are unique to this test.
/// Fresh-image probe body (phase (b) exhausts the fd table).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn birth_custody_cleans_failed_first_observation_probe() {
    // Phase (a): pinned guard, injected failure.
    let child = std::process::Command::new("/bin/sleep")
        .arg("923")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("sleeper spawns");
    let pid = child.id() as i32;
    // R21-009: birth guard at spawn (before the fallible
    // first read); disarmed after the read transfers
    // custody to the guard under test (outer coverage
    // would mask the inner retire — discrimination).
    let mut outer = SilentChildGuard::new(pid);
    // R21-009 fault: fail the first observation (reads
    // dead at the stat below — the `.expect` panics and
    // the outer guard must unwind-retire before it).
    // Birth captured healthy first (birth-aware wrapper
    // check — absence alone proves nothing). Declared
    // AFTER `outer` (drops first — restores reads before
    // the retire re-verifies).
    let _fault = std::env::var("SCOPEBASE_R21009_BIRTH_STAT_FAIL")
        .is_ok()
        .then(|| {
            let tick = task_starttime_checked(pid)
                .expect("pre-fault birth readable")
                .expect("pre-fault fixture visible");
            eprintln!("R21009-BIRTH pid={pid} tick={tick}");
            let confined = confine_fd_table_for_exhaustion();
            let mut held = Vec::new();
            while let Ok(file) = std::fs::File::open("/dev/null") {
                held.push(file);
            }
            assert!(!held.is_empty(), "fault exhaustion must consume fds");
            (confined, held)
        });
    let tick = task_starttime_checked(pid)
        .expect("sleeper stat readable")
        .expect("sleeper visible");
    drop(_fault);
    outer.disarm();
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _birth = SilentChildGuard::new(pid);
        panic!("R20010 injected post-guard failure");
    }));
    let gone_a = custody_retired_or_fail(pid, tick, "phase (a) fixture");
    retire_tail_unless_retired(pid, tick, gone_a, "phase (a) tail");
    assert!(failed.is_err(), "phase (a) must inject the failure");
    assert!(gone_a, "phase (a) unwind must retire the fixture");
    // Phase (b): unpinned guard under EMFILE, failing read.
    let _confined = confine_fd_table_for_exhaustion();
    let child2 = std::process::Command::new("/bin/sleep")
        .arg("924")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("sleeper spawns");
    let pid2 = child2.id() as i32;
    // R21-009: birth guard at spawn (before the fallible
    // first read); disarmed after the read transfers
    // custody to the guard under test (discrimination).
    let mut outer2 = SilentChildGuard::new(pid2);
    let tick2 = task_starttime_checked(pid2)
        .expect("sleeper stat readable")
        .expect("sleeper visible");
    outer2.disarm();
    let mut held = Vec::new();
    while let Ok(file) = std::fs::File::open("/dev/null") {
        held.push(file);
    }
    assert!(!held.is_empty(), "exhaustion must consume fds");
    let failed2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _birth = SilentChildGuard::new(pid2);
        let _ = task_starttime_checked(pid2).expect("fixture stat readable");
    }));
    drop(held);
    let gone_b = custody_retired_or_fail(pid2, tick2, "phase (b) fixture");
    retire_tail_unless_retired(pid2, tick2, gone_b, "phase (b) tail");
    assert!(failed2.is_err(), "phase (b) observation must fail");
    assert!(gone_b, "phase (b) unwind must retire the fixture");
    eprintln!("R20010-BIRTH-CUSTODY-DONE");
}

/// R20-010(1) wrapper: the birth-custody probe runs
/// fresh-image (phase (b) exhausts the fd table — the limit
/// dies with the probe).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn birth_custody_cleans_failed_first_observation() {
    if std::env::var("SCOPEBASE_R20010_BIRTH_CUSTODY").is_ok() {
        birth_custody_cleans_failed_first_observation_probe();
        return;
    }
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("birth_custody_cleans_failed_first_observation")
        .arg("--nocapture")
        .env("SCOPEBASE_R20010_BIRTH_CUSTODY", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "probe must complete the birth-custody case\n{stderr}"
    );
    assert!(
        stderr.contains("R20010-BIRTH-CUSTODY-DONE"),
        "probe must cite completion\n{stderr}"
    );
}

/// R21-009 (birth-custody): a failed FIRST observation
/// must panic with the staged fixture already retired —
/// the birth guard (armed at spawn) unwind-retires before
/// the `.expect` propagates. Runs the birth-custody probe
/// with reads dead at the phase-(a) stat: the probe must
/// FAIL (loud first-observation failure, never the
/// completion citation) and the staged birth must be
/// gone-or-recycled (birth-aware — absence alone proves
/// nothing; unreadable fails). Pre-fix RED: the unguarded
/// stat strands the sleeper.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn birth_stat_failure_discharges_before_panic() {
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("birth_custody_cleans_failed_first_observation")
        .arg("--nocapture")
        .env("SCOPEBASE_R20010_BIRTH_CUSTODY", "1")
        .env("SCOPEBASE_R21009_BIRTH_STAT_FAIL", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "fault probe must fail loud (first observation dead)\n{stderr}"
    );
    assert!(
        stderr.contains("sleeper stat readable"),
        "probe must name the failed first read\n{stderr}"
    );
    assert!(
        !stderr.contains("R20010-BIRTH-CUSTODY-DONE"),
        "failed probe must never cite completion\n{stderr}"
    );
    let line = stderr
        .lines()
        .find(|line| line.contains("R21009-BIRTH"))
        .expect("probe must print the staged birth");
    // R21009-BIRTH pid={pid} tick={tick}.
    let mut parts = line.split_whitespace().skip(1);
    let pid: i32 = parts
        .next()
        .expect("pid slot")
        .strip_prefix("pid=")
        .expect("pid shape")
        .parse()
        .expect("pid parses");
    let tick: u64 = parts
        .next()
        .expect("tick slot")
        .strip_prefix("tick=")
        .expect("tick shape")
        .parse()
        .expect("tick parses");
    match task_starttime_checked(pid) {
        Ok(None) => {}
        Ok(Some(now)) => assert_ne!(
            now, tick,
            "staged birth must be retired (stranded by the failed first read)"
        ),
        Err(error) => panic!("staged retirement unverifiable: {error}"),
    }
}

/// R21-011(c) outage probe (fresh-image: exhausts the fd
/// table — the limit dies with the probe). Under held
/// EMFILE the stat read errors (a genuine observation
/// outage over a LIVE fixture): the custody verdict must
/// fail loud, never green-verdict over unknown state (the
/// old `!= Ok(Some)` shape returned true on Err). Duration
/// 931 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn custody_oracle_outage_probe() {
    let _confined = confine_fd_table_for_exhaustion();
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("931")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("sleeper spawns");
    let pid = child.id() as i32;
    // R22-014: guard at birth (pre-exhaust — the tick
    // read below must not strand the sleeper; no unwind
    // path exists under EMFILE here (the oracle is
    // caught, drop/kill/wait are infallible), so the
    // drop always verifies).
    let mut _guard = SilentChildGuard::new(pid);
    let tick = task_starttime_checked(pid)
        .expect("sleeper stat readable")
        .expect("sleeper visible");
    let mut held = Vec::new();
    while let Ok(file) = std::fs::File::open("/dev/null") {
        held.push(file);
    }
    assert!(!held.is_empty(), "exhaustion must consume fds");
    let failed_loud = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        custody_retired_or_fail(pid, tick, "probe fixture")
    })) {
        Err(payload) => payload
            .downcast_ref::<String>()
            .is_some_and(|message| message.contains("unreadable")),
        Ok(_) => false,
    };
    drop(held);
    let _ = child.kill();
    let _ = child.wait();
    _guard.disarm();
    assert!(
        failed_loud,
        "outage must fail loud on unreadable custody, never green-verdict"
    );
    eprintln!("R21011-TWIN-OUTAGE-DONE");
}

/// R21-011(c) outage wrapper: the probe runs fresh-image
/// (it exhausts the fd table).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn custody_oracle_outage_refuses_green_verdict() {
    if std::env::var("SCOPEBASE_R21011_TWIN_OUTAGE").is_ok() {
        custody_oracle_outage_probe();
        return;
    }
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("custody_oracle_outage_refuses_green_verdict")
        .arg("--nocapture")
        .env("SCOPEBASE_R21011_TWIN_OUTAGE", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "probe must complete the outage case\n{stderr}"
    );
    assert!(
        stderr.contains("R21011-TWIN-OUTAGE-DONE"),
        "probe must cite completion\n{stderr}"
    );
}

/// R19-014: stranger-staging verdict (shared by the staging
/// arm and the forced-adoption probe — the probe exercises
/// this actual path): assist-then-sample — reap-only
/// assistance first (a suite-adopted zombie would read Some
/// and fail a sample-first verdict even though it is
/// retired), then sample the pair state and assert retirement
/// (no leak). Called pre-arms (R18-010: unconditional). The
/// sample is the ns-anchored retirement proof (R19003-FLAKE02:
/// no trailing fresh-read absence assert follows it).
/// R18-010 sensitivity preserved: the assistance is reap-only
/// (never kills), so a live survivor still reads Some and
/// fails — only reaped zombies flip to None. Silent budget
/// expiry (the asserts below report).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn stranger_staging_verdict(stranger: i32, stick: u64, sh: i32, shtick: u64, budget: Duration) {
    let end = Instant::now() + budget;
    loop {
        // R18-006: reap tick-verified zombies (adopted or
        // owned) so the sample below observes them gone.
        // Reap-only: a live survivor is never touched
        // (R18-010 sensitivity).
        waitpid_assist_verified(stranger, stick);
        waitpid_assist_verified(sh, shtick);
        let down = task_starttime_checked(stranger) != Ok(Some(stick))
            && task_starttime_checked(sh) != Ok(Some(shtick));
        if down || Instant::now() >= end {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let sstate = task_starttime_checked(stranger);
    let hstate = task_starttime_checked(sh);
    assert_eq!(
        sstate,
        Ok(None),
        "stranger failure must not leak the grandchild"
    );
    assert_eq!(hstate, Ok(None), "stranger failure must not leak sh");
}

/// R16-011: probe-staging failure custody — every staged birth
/// across the EMFILE/late-pin/gated-kill shapes must disappear
/// with its status discharged when an injected failure reports.
/// Three arms (each stages + guards exactly as the fixed sites
/// do, injects under catch, then requires disappearance +
/// discharge + report): a pauser with an injected OBSERVATION
/// failure before any read; a pauser pinned then failed by an
/// injected ASSERTION (the late-pin second-guard shape); an sh
/// plus a staged grandchild with an injected failure (the
/// EMFILE stranger shape — grandchild custody needs the pinned
/// twin).
/// Observe-before-cleanup per arm (mutant runs stay clean);
/// asserts read captured evidence. Pre-fix (guards removed)
/// every arm strands (RED, proven by mutant runs during
/// development); post-fix all retire (GREEN). Duration 56 is
/// unique to this test.
/// R17-002: the stranger-arm hygiene must not touch the
/// handle after the guards raw-reaped (a recycled number
/// would be signaled or status-stolen). Arm 1 (live
/// replacement): gated kill stands down, no wait, survival.
/// Arm 2 (zombie replacement, same hygiene shape): status
/// stays with its owner.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn probe_staging_failures_retire_before_report() {
    use std::io::BufRead as _;
    // Arm OBS: pauser birth, observation failure injected
    // before any read.
    let slot = std::cell::Cell::new(-1);
    let obs = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let pid = fork_pauser();
        slot.set(pid);
        let _guard = SilentChildGuard::new(pid);
        panic!("R16011 injected observation failure");
    }));
    let opid = slot.get();
    assert!(opid > 0, "obs arm must stage a pauser");
    let ostate = task_starttime_checked(opid);
    retire_child_silent(opid);
    assert_eq!(ostate, Ok(None), "obs failure must not leak the pauser");
    // R19003-FLAKE02: no trailing fresh-read absence
    // assert — `ostate` is the ns-anchored retirement
    // proof (see helper docs).
    assert!(obs.is_err(), "obs failure must report");
    // Arm PINNED: pauser birth + pin, assertion failure
    // injected after (the late-pin second-guard shape).
    let slot = std::cell::Cell::new(-1);
    let pinned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let pid = fork_pauser();
        slot.set(pid);
        let mut _guard = SilentChildGuard::new(pid);
        let tick = task_starttime_checked(pid)
            .expect("pinned stat readable")
            .expect("pinned visible");
        _guard.pin(tick);
        panic!("R16011 injected assertion failure");
    }));
    let ppid = slot.get();
    assert!(ppid > 0, "pinned arm must stage a pauser");
    let pstate = task_starttime_checked(ppid);
    retire_child_silent(ppid);
    assert_eq!(pstate, Ok(None), "pinned failure must not leak the pauser");
    // R19003-FLAKE02: no trailing fresh-read absence
    // assert — `pstate` is the ns-anchored retirement
    // proof (see helper docs).
    assert!(pinned.is_err(), "pinned failure must report");
    // R17-002: serialize steerers (scoped hold — the OBS and
    // PINNED arms above run unconditionally; only the
    // stranger arm needs reuse control).
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
    locked_restore_hint(&last_before);
    // Arm STRANGER: publisher + grandchild, failure injected
    // after staging (the EMFILE stranger shape).
    // R17-002: the publisher IS reaped — by the guards' raw waitpid,
    // proven by the discharge asserts below — so no handle
    // `wait` follows (any would risk a recycled holder).
    #[allow(clippy::zombie_processes)]
    let mut parent = std::process::Command::new(pair_publisher_bin())
        .arg("56")
        .arg("wait")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("publisher spawns");
    let publisher = parent.id() as i32;
    // Outer custody for the pre-catch reads (the inner guards
    // below are the tested artifact; these only cover staging
    // and verify silent at the end).
    let mut outer_publisher = SilentChildGuard::new(publisher);
    let mut line = String::new();
    std::io::BufReader::new(parent.stdout.take().expect("publisher stdout"))
        .read_line(&mut line)
        .expect("grandchild pid readable");
    // R19-001: transmitted pair (no receiver
    // first-read), then expected-identity custody (a reap
    // + recycle between publication and acquisition
    // refuses instead of authenticating the replacement).
    let (stranger, stick) = parse_published_pair(line.trim(), "stranger publication");
    let mut outer_stranger = SilentChildGuard::new_expected(stranger, stick);
    let pubtick = task_starttime_checked(publisher)
        .expect("publisher stat readable")
        .expect("publisher present");
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _publisher_guard = SilentChildGuard::new(publisher);
        // R17-008: expected-identity — the stranger's tick
        // was read just above (refuse a recycled number).
        let _stranger_guard = SilentChildGuard::new_expected(stranger, stick);
        panic!("R16011 injected stranger-staging failure");
    }));
    // R19-014: verdict pre-arms (R18-010: unconditional —
    // a contended placement must SKIP only its arm, never
    // suppress this. Stranger pair discharged first: a
    // missing-reap mutant in the guards leaves publisher holding
    // its number and fails HERE — instead of blocking
    // placement below into a silent SKIP).
    stranger_staging_verdict(stranger, stick, publisher, pubtick, Duration::from_secs(5));
    assert!(failed.is_err(), "stranger failure must report");
    // R17-002 arm 1 (live): steer a live replacement onto
    // publisher's freed number, then run the hygiene — the publisher kill
    // must be tick-gated (stand down) with no handle wait
    // (RED: the blind kill murders the replacement).
    let mut live = match steer_sleep_onto(publisher, false) {
        Some(kid) => kid,
        None => {
            // R18-010: SKIP branch re-proves the discharge
            // (the original publisher at its pinned tick must be
            // gone — fail loud, never suppress).
            assert_child_gone(publisher, pubtick, "stranger-publisher");
            eprintln!("skip: retake contended");
            return;
        }
    };
    let mut live_guard = SilentChildGuard::new(publisher);
    let retick = task_starttime_checked(publisher)
        .expect("replacement stat readable")
        .expect("replacement visible");
    if retick == pubtick {
        let _ = live.kill();
        let _ = live.wait();
        live_guard.disarm();
        eprintln!("skip: same-tick retake (S100 — untestable this run)");
        return;
    }
    let start = Instant::now();
    // Hygiene (mutant-clean): tick-gated stranger kill,
    // tick-gated publisher kill (R17-002: the guards already
    // raw-reaped — a handle kill/wait would murder or steal
    // a recycled number's replacement), poll both gone.
    let _ = kill_tick_gated(stranger, stick);
    let _ = kill_tick_gated(publisher, pubtick);
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        // R18-006: reap tick-verified zombies (adopted or
        // owned) so the poll below observes them gone (a
        // killed stranger whose publisher died first reparents to
        // the suite — stat alone would time out).
        waitpid_assist_verified(stranger, stick);
        waitpid_assist_verified(publisher, pubtick);
        let down = task_starttime_checked(stranger) != Ok(Some(stick))
            && task_starttime_checked(publisher) != Ok(Some(pubtick));
        if down {
            break;
        }
        assert!(Instant::now() < end, "stranger pair must die in hygiene");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "hygiene must not block on a live replacement"
    );
    assert!(
        matches!(live.try_wait(), Ok(None)),
        "live replacement must survive hygiene"
    );
    let _ = live.kill();
    let _ = live.wait();
    live_guard.disarm();
    // R17-002 arm 2 (zombie): same hygiene shape, zombie
    // replacement — its status must stay with its owner
    // (RED: stolen by the handle wait).
    let mut zombie = match steer_sleep_onto(publisher, false) {
        Some(kid) => kid,
        None => {
            // R18-010: SKIP branch re-proves the discharge
            // (same mutant discriminator as arm 1).
            assert_child_gone(publisher, pubtick, "stranger-publisher");
            eprintln!("skip: retake contended");
            return;
        }
    };
    let mut zombie_guard = SilentChildGuard::new(publisher);
    let retick = task_starttime_checked(publisher)
        .expect("replacement stat readable")
        .expect("replacement visible");
    if retick == pubtick {
        let _ = zombie.kill();
        let _ = zombie.wait();
        zombie_guard.disarm();
        eprintln!("skip: same-tick retake (S100 — untestable this run)");
        return;
    }
    let _ = zombie.kill();
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if task_retired_checked(publisher) == Ok(true) {
            break;
        }
        assert!(Instant::now() < end, "replacement never zombied");
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = kill_tick_gated(publisher, pubtick);
    assert!(
        matches!(zombie.try_wait(), Ok(Some(_))),
        "zombie replacement status must stay with its owner"
    );
    zombie_guard.disarm();
    outer_publisher.disarm();
    outer_stranger.disarm();
    // R18-010: stranger-arm verdicts moved before the arms
    // (unconditional — see above).
}

/// R19-014 (toolchain twin): probe body (fresh image,
/// SCOPEBASE_R19014_SUBREAPER) — forced-adoption schedule
/// (STOP-freeze the publisher, kill the stranger, settle Z
/// with the publisher still T, SIGKILL the publisher WITHOUT
/// reaping so the zombie adopts to the probe), then the ACTUAL shared
/// staging verdict. RED (sample-first verdict): the sample
/// catches the adopted zombie (Some) and fails even though
/// assistance would reap it. GREEN (assist-then-sample):
/// the verdict assists first and reads None. Duration 79 is
/// unique to this test (both harnesses).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn stranger_verdict_adoption_probe() {
    use std::io::BufRead as _;
    // Confined subreaper (fresh image — the process-global
    // mark stays inside the probe).
    // SAFETY: prctl on self; marking a fresh probe process.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0,
        "probe must become a child subreaper"
    );
    #[allow(clippy::zombie_processes)]
    let mut publisher = std::process::Command::new(pair_publisher_bin())
        .arg("79")
        .arg("wait")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("publisher spawns");
    let pubpid = publisher.id() as i32;
    // Staging custody (a staging panic must not strand the
    // pair; the drops below stay silent once the verdict
    // retires it). R20-010: custody immediately after spawn
    // (the read/parse/stat below must never run unguarded).
    let mut publisher_guard = SilentChildGuard::new(pubpid);
    assert!(
        publisher_guard.tick.is_some(),
        "publisher custody must pin (stage broken otherwise)"
    );
    let mut line = String::new();
    std::io::BufReader::new(publisher.stdout.take().expect("publisher stdout"))
        .read_line(&mut line)
        .expect("stranger pid readable");
    // R19-001: transmitted pair (no receiver first-read).
    let (stranger, stick) = parse_published_pair(line.trim(), "stranger publication");
    // R20-010: custody immediately after parse (the
    // stat below must never run unguarded).
    let mut stranger_guard = SilentChildGuard::new_expected(stranger, stick);
    assert!(
        stranger_guard.tick.is_some(),
        "stranger custody must pin (stage broken otherwise)"
    );
    let pubtick = task_starttime_checked(pubpid)
        .expect("publisher stat readable")
        .expect("publisher visible");
    // Freeze the publisher: from here it cannot reap.
    // SAFETY: SIGSTOP to our own staged publisher.
    assert_eq!(
        unsafe { libc::kill(pubpid, libc::SIGSTOP) },
        0,
        "publisher freeze"
    );
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if matches!(task_state(pubpid), Some(state) if state == 'T') {
            break;
        }
        assert!(Instant::now() < end, "publisher must stop");
        std::thread::sleep(Duration::from_millis(1));
    }
    // Kill the stranger under the frozen publisher.
    assert!(
        kill_tick_gated(stranger, stick),
        "stranger kill must not fail unreadable (broken staging)"
    );
    // Non-vacuity: stranger Z while the publisher is still T
    // (the publisher provably never reaped across the death).
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if matches!(task_state(stranger), Some(state) if state == 'Z') {
            break;
        }
        assert!(Instant::now() < end, "stranger must zombify");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        matches!(task_state(pubpid), Some(state) if state == 'T'),
        "publisher still frozen at stranger death (else it may have reaped)"
    );
    // Kill the publisher WITHOUT reaping: dies unreaped, so the
    // stranger zombie adopts to the probe (nearest subreaper
    // ancestor). A stopped task needs no CONT to die by
    // SIGKILL.
    // SAFETY: SIGKILL to our own frozen publisher.
    assert_eq!(
        unsafe { libc::kill(pubpid, libc::SIGKILL) },
        0,
        "publisher kill must land on the frozen publisher"
    );
    // The ACTUAL shared verdict (RED pre-fix: the sample
    // catches the adopted zombie; GREEN post-fix: the verdict
    // assists first). RED cleanup rides the guards (they reap
    // the adoptee + publisher on unwind).
    stranger_staging_verdict(stranger, stick, pubpid, pubtick, Duration::from_secs(5));
    stranger_guard.disarm();
    publisher_guard.disarm();
    eprintln!("R19014-VERDICT retired=1");
}

/// R19-014 (toolchain twin): driver — the forced-adoption
/// probe above runs in a child with its own process identity
/// (the prctl mark must not leak into the suite).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn stranger_staging_verdict_assists_adopted_zombie() {
    if std::env::var("SCOPEBASE_R19014_SUBREAPER").is_ok() {
        stranger_verdict_adoption_probe();
        return;
    }
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("stranger_staging_verdict_assists_adopted_zombie")
        .arg("--nocapture")
        .env("SCOPEBASE_R19014_SUBREAPER", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "probe verdict must pass under forced adoption\n{stderr}"
    );
    assert!(
        stderr.contains("R19014-VERDICT retired=1"),
        "probe must cite the verdict\n{stderr}"
    );
}

/// R20-010(2) (twin mirror): custody at each pair-setup
/// step — spawn/read/parse/stat `.expect`s with no guard
/// strand the pair on panic. Phase (a): guards at spawn
/// (publisher) and parse (stranger), then an injected
/// failure → unwind retires both. Phase (b): the publisher
/// dies before its stat read → unwind retires the stranger
/// through its guard. Observe-before-cleanup. R21 holistic:
/// self-grouped spawns, Result setups (a read/parse/stat
/// failure retires the unknown-sleeper group before failing
/// loud), gated tails (never ungated kill + blocking wait),
/// bounded phase-(b) reap. Durations 927/928 are unique to
/// this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn pair_setup_failure_retires_guarded_fixtures() {
    use std::io::BufRead as _;
    use std::time::{Duration, Instant};
    // Phase (a): injected failure after setup.
    let mut publisher = spawn_self_grouped_publisher("927", "wait", &[]);
    let pubpid = publisher.id() as i32;
    // R21-009-pair-setup: the setup is a Result — a
    // read/parse/stat failure retires the unknown-sleeper
    // group BEFORE failing loud (never a bare `.expect`
    // past the unreaped leader).
    let setup: Result<((i32, u64), u64), String> = (|| {
        let mut line = String::new();
        std::io::BufReader::new(
            publisher
                .stdout
                .take()
                .ok_or_else(|| "publisher stdout missing".to_string())?,
        )
        .read_line(&mut line)
        .map_err(|error| format!("stranger pair unreadable: {error}"))?;
        let pair = try_parse_published_pair(line.trim(), "stranger publication")?;
        let pubtick = match task_starttime_checked(pubpid) {
            Ok(Some(tick)) => tick,
            Ok(None) => return Err("publisher gone pre-guard".to_string()),
            Err(error) => return Err(format!("publisher stat unreadable: {error}")),
        };
        Ok((pair, pubtick))
    })();
    let ((stranger, stick), pubtick_a) = match setup {
        Ok(ok) => ok,
        Err(cause) => {
            let status = retire_unparsed_publisher_group(&mut publisher);
            panic!("phase (a) setup failed ({cause}) — group retired ({status:?})");
        }
    };
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _publisher_guard = SilentChildGuard::new(pubpid);
        let _stranger_guard = SilentChildGuard::new_expected(stranger, stick);
        panic!("R20010 injected post-setup failure");
    }));
    let gone_pub_a = await_task_gone_reaping(pubpid, pubtick_a, Duration::from_secs(5));
    let gone_str_a = await_task_gone_reaping(stranger, stick, Duration::from_secs(5));
    let _ = kill_tick_gated(stranger, stick);
    // R21-010-tails: gated retire + WNOHANG-only reap
    // (never the ungated kill + blocking wait — the number
    // may host a replacement now).
    let _ = retire_tick_gated_toolchain_child(pubpid, pubtick_a);
    assert!(failed.is_err(), "phase (a) must inject the failure");
    assert!(
        gone_pub_a && gone_str_a,
        "phase (a) unwind must retire the pair"
    );
    // Phase (b): publisher dies before its stat read.
    let mut publisher_b = spawn_self_grouped_publisher("928", "wait", &[]);
    let pubpid_b = publisher_b.id() as i32;
    let setup_b: Result<((i32, u64), u64), String> = (|| {
        let mut line_b = String::new();
        std::io::BufReader::new(
            publisher_b
                .stdout
                .take()
                .ok_or_else(|| "publisher stdout missing".to_string())?,
        )
        .read_line(&mut line_b)
        .map_err(|error| format!("stranger pair unreadable: {error}"))?;
        let pair = try_parse_published_pair(line_b.trim(), "stranger publication")?;
        let pubtick = match task_starttime_checked(pubpid_b) {
            Ok(Some(tick)) => tick,
            Ok(None) => return Err("publisher gone pre-guard".to_string()),
            Err(error) => return Err(format!("publisher stat unreadable: {error}")),
        };
        Ok((pair, pubtick))
    })();
    let ((stranger_b, stick_b), pubtick_b) = match setup_b {
        Ok(ok) => ok,
        Err(cause) => {
            let status = retire_unparsed_publisher_group(&mut publisher_b);
            panic!("phase (b) setup failed ({cause}) — group retired ({status:?})");
        }
    };
    let failed_b = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _publisher_guard = SilentChildGuard::new(pubpid_b);
        let _stranger_guard = SilentChildGuard::new_expected(stranger_b, stick_b);
        assert!(kill_tick_gated(pubpid_b, pubtick_b));
        // R21-010-tails: bounded WNOHANG reap (never a
        // blocking wait — same µs behavior on the SIGKILLed
        // child, loud instead of wedged on the impossible).
        let start = Instant::now();
        let reaped = loop {
            let mut status = 0;
            // SAFETY: WNOHANG reap of our own killed
            // child; never blocks.
            let got = unsafe { libc::waitpid(pubpid_b, &mut status, libc::WNOHANG) };
            if got == pubpid_b {
                break true;
            }
            if got < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break false;
            }
            if start.elapsed() >= Duration::from_secs(5) {
                break false;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        assert!(reaped, "publisher reaps");
        let _ = task_starttime_checked(pubpid_b)
            .expect("publisher stat readable")
            .expect("publisher visible");
    }));
    let gone_str_b = await_task_gone_reaping(stranger_b, stick_b, Duration::from_secs(5));
    let _ = kill_tick_gated(stranger_b, stick_b);
    let _ = retire_tick_gated_toolchain_child(pubpid_b, pubtick_b);
    assert!(failed_b.is_err(), "phase (b) stat must fail");
    assert!(gone_str_b, "phase (b) unwind must retire the stranger");
}

/// R22-005 (toolchain twin): fresh-image probe — mirror of
/// the lib outage probe (valid publication, then persistent
/// EMFILE across the setup-stat + retire; the degraded path
/// must discharge; verdict via handle-status + killpg-0
/// group ESRCH — all outage-proof). RED (old code:
/// pin re-read panics before any signal).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn outage_unparsed_retire_discharges_probe() {
    use std::io::BufRead as _;
    let mut publisher = spawn_self_grouped_publisher("983", "wait", &[]);
    let pubpid = publisher.id() as i32;
    // R22-014: guard at birth (the pair read below must
    // not strand the publisher).
    let mut _pguard = SilentChildGuard::new(pubpid);
    let mut line = String::new();
    std::io::BufReader::new(publisher.stdout.take().expect("publisher stdout"))
        .read_line(&mut line)
        .expect("pair readable");
    let (stranger, stick) = try_parse_published_pair(line.trim(), "outage publication")
        .expect("pair must parse (valid publication)");
    // R22-014: guard the transmitted sleep (expected-tick
    // pin — the sleep is live (can't recycle), so the
    // pin always takes; a refused pin fails loud here,
    // never unwinds unguarded past it).
    let mut _sguard = SilentChildGuard::new_expected(stranger, stick);
    assert!(
        _sguard.tick.is_some(),
        "sleep pin must take (transmitted birth live)"
    );
    let _confined = confine_fd_table_for_exhaustion();
    let mut held = Vec::new();
    while let Ok(file) = std::fs::File::open("/dev/null") {
        held.push(file);
    }
    assert!(!held.is_empty(), "staging broken (nothing held)");
    assert!(
        std::fs::File::open("/dev/null").is_err(),
        "staging broken (outage not established)"
    );
    assert!(
        task_starttime_checked(pubpid).is_err(),
        "staging broken (setup stat readable — outage not biting?)"
    );
    let status = retire_unparsed_publisher_group(&mut publisher);
    _pguard.disarm();
    _sguard.disarm();
    let group_errno = {
        // SAFETY: signal 0 probes only.
        let probed = unsafe { libc::killpg(pubpid, 0) };
        if probed == 0 {
            0
        } else {
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(-999)
        }
    };
    assert_eq!(
        group_errno,
        libc::ESRCH,
        "group must be ESRCH-empty (sleeper discharged)"
    );
    eprintln!("R22005-DISCHARGED status={status:?}");
}

/// R22-005 (toolchain twin): the outage probe runs
/// fresh-image (it exhausts the fd table). Duration 983 is
/// unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn outage_unparsed_retire_discharges() {
    if std::env::var("SCOPEBASE_R22005_OUTAGE_TWIN").is_ok() {
        outage_unparsed_retire_discharges_probe();
        return;
    }
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("outage_unparsed_retire_discharges")
        .arg("--nocapture")
        .env("SCOPEBASE_R22005_OUTAGE_TWIN", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "probe must discharge under persistent outage\n{stderr}"
    );
    assert!(
        stderr.contains("R22005-DEGRADED"),
        "probe must take the degraded path\n{stderr}"
    );
    assert!(
        stderr.contains("R22005-DISCHARGED"),
        "probe must cite discharge\n{stderr}"
    );
}

/// R22-006 (toolchain twin): run a fresh-image probe child
/// with a bounded wait (60s — a hung child is killed loud)
/// and collect its output. Same pipe rule as the lib: no
/// live descendant may hold the probe's pipes (grandchild
/// stderr goes to a file).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn run_fresh_probe_bounded(env: &str, test: &str) -> std::process::Output {
    let exe = std::env::current_exe().expect("own test binary");
    let mut child = std::process::Command::new(exe)
        .arg("--exact")
        .arg(test)
        .arg("--nocapture")
        .env(env, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("probe child spawns");
    // Covers the timeout-panic below (the child is
    // killed but unreaped there — the drop reaps it).
    let mut _cguard = SilentChildGuard::new(child.id() as i32);
    let end = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if child.try_wait().expect("child waitable").is_some() {
            break;
        }
        if std::time::Instant::now() >= end {
            let _ = child.kill();
            panic!("probe child {test} hung past 60s (killed loud)");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let out = child.wait_with_output().expect("probe output readable");
    _cguard.disarm();
    out
}

/// R22-008 (toolchain twin): timeout-COLLECTING probe run
/// — mirror of the lib helper (kill + reap + read the
/// pipes to EOF on timeout; early-flushed custody lines
/// survive for wrapper-side custody of forever-pausing
/// middlemen).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct ProbeOutcome {
    timed_out: bool,
    out: std::process::Output,
}

/// R22-008 (toolchain twin): run a fresh-image probe
/// child, collecting its output EVEN on timeout. The
/// wrapper judges completion via `timed_out` + a DONE
/// marker, never by output presence alone.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn run_fresh_probe_collect(env: &str, test: &str) -> ProbeOutcome {
    let exe = std::env::current_exe().expect("own test binary");
    let mut child = std::process::Command::new(exe)
        .arg("--exact")
        .arg(test)
        .arg("--nocapture")
        .env(env, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("probe child spawns");
    let mut _cguard = SilentChildGuard::new(child.id() as i32);
    let end = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut timed_out = false;
    loop {
        if child.try_wait().expect("child waitable").is_some() {
            break;
        }
        if std::time::Instant::now() >= end {
            let _ = child.kill();
            timed_out = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let out = child.wait_with_output().expect("probe output readable");
    _cguard.disarm();
    ProbeOutcome { timed_out, out }
}

/// R22-006 (toolchain twin): parse a `R22006-SLEEPER pid
/// tick` line from probe stdout.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn parse_r22006_sleeper(stdout: &str) -> Option<(i32, u64)> {
    stdout.lines().find_map(|line| {
        let rest = line.strip_prefix("R22006-SLEEPER ")?;
        let (pid, tick) = rest.split_once(' ')?;
        Some((pid.parse().ok()?, tick.parse().ok()?))
    })
}

/// R22-006 (toolchain twin): parse a `R22006-CODE n` line
/// from probe stdout.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn parse_r22006_code(stdout: &str) -> Option<i32> {
    stdout.lines().find_map(|line| {
        line.strip_prefix("R22006-CODE ")
            .and_then(|code| code.parse().ok())
    })
}

/// R22-006 (toolchain twin): parse a `R22006-ERRLOG path`
/// line from probe stdout.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn parse_r22006_errlog(stdout: &str) -> Option<std::path::PathBuf> {
    stdout.lines().find_map(|line| {
        line.strip_prefix("R22006-ERRLOG ")
            .map(std::path::PathBuf::from)
    })
}

/// R22-006 (toolchain twin): nonce for probe errlog names.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn errlog_nonce() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// R22-006 kill-denied probe (toolchain twin, fresh image):
/// mirror of the lib probe — seccomp-deny `kill` in SELF,
/// run the publisher into its wait-step fault, forward the
/// pair + exit code + evidence path.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn publisher_guard_denied_kill_reports_unresolved_probe() {
    use scopebase_testkit::fixture::linux::seccomp::{install_deny_one, DenyAction};
    use std::io::BufRead as _;
    // R23-002: `unsupported_arch` skips explicitly
    // (seccomp denial is x86-only — exit 0 with the SKIP
    // marker; the wrapper judges the marker, never the
    // install). Any other install failure is still
    // staging-broken.
    if let Err(error) = install_deny_one(libc::SYS_kill, DenyAction::Eperm) {
        if error.stage() == "unsupported_arch" {
            eprintln!("R22006-SKIP unsupported_arch (seccomp denial unavailable)");
            return;
        }
        panic!("deny-kill installs (staging): {error}");
    }
    // SAFETY: signal 0 to self probes only.
    let probed = unsafe { libc::kill(std::process::id() as i32, 0) };
    assert_eq!(probed, -1, "staging broken (kill not denied?)");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM),
        "staging broken (wrong denial errno?)"
    );
    let errlog = std::env::temp_dir().join(format!(
        "scopebase-r22006-kill-twin-{}-{}.log",
        std::process::id(),
        errlog_nonce()
    ));
    println!("R22006-ERRLOG {}", errlog.display());
    let errfile = std::fs::File::create(&errlog).expect("errlog creatable (staging)");
    let dur = r22014_sleep_dur("986");
    let mut publisher = std::process::Command::new(pair_publisher_bin())
        .arg(&dur)
        .arg("wait")
        .env("SCOPEBASE_PUBLISHER_FAULT_STEP", "wait")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(errfile)
        .spawn()
        .expect("publisher spawns");
    let mut line = String::new();
    std::io::BufReader::new(publisher.stdout.take().expect("publisher stdout"))
        .read_line(&mut line)
        .expect("pair readable");
    let (sleeper, stick) = try_parse_published_pair(line.trim(), "denied publication")
        .expect("pair must parse (valid transmit)");
    // R22-014 fault leg (twin): die before transmitting
    // (same as lib — the R12 fallback must sweep).
    if std::env::var("SCOPEBASE_R22014_EARLY_DEATH").is_ok() {
        std::process::exit(42);
    }
    println!("R22006-SLEEPER {sleeper} {stick}");
    let status = publisher.wait().expect("publisher waitable");
    println!("R22006-CODE {}", status.code().unwrap_or(-999));
    eprintln!("R22006-KILL-DONE");
}

/// R22-006 kill-denied wrapper (toolchain twin): mirror of
/// the lib wrapper (fresh image; cleanup before verdict so
/// RED runs stay clean). Duration 986 is unique to this
/// test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn publisher_guard_denied_kill_reports_unresolved() {
    use std::time::{Duration, Instant};
    if std::env::var("SCOPEBASE_R22006_DENY_KILL_TWIN").is_ok() {
        publisher_guard_denied_kill_reports_unresolved_probe();
        return;
    }
    let out = run_fresh_probe_bounded(
        "SCOPEBASE_R22006_DENY_KILL_TWIN",
        "publisher_guard_denied_kill_reports_unresolved",
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    // R23-002: explicit unsupported_arch skip (the probe
    // stages nothing on this path — no custody to run —
    // so the check precedes the sleeper parse).
    if stderr.contains("R22006-SKIP") {
        eprintln!("skip: seccomp kill denial unsupported on this arch (see probe stderr)");
        return;
    }
    // R12 (twin): no transmitted birth ⟹ sweep by the
    // unique duration, clean the errlog best-effort,
    // fail loud (same as lib).
    let (sleeper, stick) = match parse_r22006_sleeper(&stdout) {
        Some(pair) => pair,
        None => {
            let swept = r22006_fallback_sweep_sleep(&r22014_sleep_dur("986"));
            if let Some(errlog) = parse_r22006_errlog(&stdout) {
                let _ = std::fs::remove_file(&errlog);
            }
            panic!("staging broken (no sleeper line — R12 fallback swept {swept})");
        }
    };
    assert!(
        kill_tick_gated(sleeper, stick),
        "sleeper kill must land (staging?)"
    );
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        match task_starttime_checked(sleeper) {
            Ok(Some(now)) if now == stick => {}
            Ok(_) => break,
            Err(error) => panic!("sleeper death unreadable: {error}"),
        }
        assert!(Instant::now() < end, "sleeper must die by our kill");
        std::thread::sleep(Duration::from_millis(10));
    }
    let errlog = parse_r22006_errlog(&stdout).expect("staging broken (no errlog line?)");
    let evidence = std::fs::read_to_string(&errlog).expect("errlog readable (staging?)");
    let _ = std::fs::remove_file(&errlog);
    assert!(out.status.success(), "probe must complete\n{stderr}");
    assert!(
        stderr.contains("R22006-KILL-DONE"),
        "probe must cite completion\n{stderr}"
    );
    assert_eq!(
        parse_r22006_code(&stdout),
        Some(3),
        "kill-denied publisher must exit 3 (unresolved, not 2)\n{evidence}"
    );
    assert!(
        evidence.contains("UNRESOLVED-CUSTODY"),
        "must cite unresolved custody\n{evidence}"
    );
    assert!(
        evidence.contains(&format!("sleeper={sleeper}")),
        "must name the sleeper pid\n{evidence}"
    );
    assert!(
        evidence.contains(&format!("kill_errno={}", libc::EPERM)),
        "must cite the kill errno\n{evidence}"
    );
    assert!(
        evidence.contains("reaped=false"),
        "must report unreaped\n{evidence}"
    );
}

/// R22-006 wait-denied probe (toolchain twin, fresh image):
/// mirror of the lib probe — the publisher denies `wait4`
/// to itself via its hook, then faults at its wait step.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn publisher_guard_denied_wait_reports_unresolved_probe() {
    use std::io::BufRead as _;
    let errlog = std::env::temp_dir().join(format!(
        "scopebase-r22006-wait-twin-{}-{}.log",
        std::process::id(),
        errlog_nonce()
    ));
    println!("R22006-ERRLOG {}", errlog.display());
    let errfile = std::fs::File::create(&errlog).expect("errlog creatable (staging)");
    let dur = r22014_sleep_dur("987");
    let mut publisher = std::process::Command::new(pair_publisher_bin())
        .arg(&dur)
        .arg("wait")
        .env("SCOPEBASE_PUBLISHER_DENY_WAIT", "1")
        .env("SCOPEBASE_PUBLISHER_FAULT_STEP", "wait")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(errfile)
        .spawn()
        .expect("publisher spawns");
    let mut _tpguard = SilentChildGuard::new(publisher.id() as i32);
    let mut line = String::new();
    std::io::BufReader::new(publisher.stdout.take().expect("publisher stdout"))
        .read_line(&mut line)
        .expect("pair readable");
    let (sleeper, stick) = try_parse_published_pair(line.trim(), "denied publication")
        .expect("pair must parse (valid transmit)");
    let mut _tsguard = SilentChildGuard::new_expected(sleeper, stick);
    assert!(
        _tsguard.tick.is_some(),
        "wait-denied twin probe: sleeper birth pinned at sighting"
    );
    // R22-014 fault leg (twin): die before transmitting
    // (same as lib — the swept count races here).
    if std::env::var("SCOPEBASE_R22014_EARLY_DEATH").is_ok() {
        std::process::exit(42);
    }
    println!("R22006-SLEEPER {sleeper} {stick}");
    let status = publisher.wait().expect("publisher waitable");
    _tpguard.disarm();
    println!("R22006-CODE {}", status.code().unwrap_or(-999));
    let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match task_starttime_checked(sleeper) {
            Ok(Some(now)) if now == stick => {}
            Ok(_) => break,
            Err(error) => panic!("sleeper drain unreadable: {error}"),
        }
        assert!(
            std::time::Instant::now() < end,
            "staging broken (orphaned zombie never drained?)"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    _tsguard.disarm();
    eprintln!("R22006-WAIT-DONE");
}

/// R22-006 wait-denied wrapper (toolchain twin): mirror of
/// the lib wrapper (fresh image; init reaps the orphaned
/// zombie). Duration 987 is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn publisher_guard_denied_wait_reports_unresolved() {
    if std::env::var("SCOPEBASE_R22006_DENY_WAIT_TWIN").is_ok() {
        publisher_guard_denied_wait_reports_unresolved_probe();
        return;
    }
    let out = run_fresh_probe_bounded(
        "SCOPEBASE_R22006_DENY_WAIT_TWIN",
        "publisher_guard_denied_wait_reports_unresolved",
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    // Custody FIRST (R12 twin): same as lib — sweep,
    // clean, fail loud before any verdict.
    let (sleeper, _stick) = match parse_r22006_sleeper(&stdout) {
        Some(pair) => pair,
        None => {
            let swept = r22006_fallback_sweep_sleep(&r22014_sleep_dur("987"));
            if let Some(errlog) = parse_r22006_errlog(&stdout) {
                let _ = std::fs::remove_file(&errlog);
            }
            panic!("staging broken (no sleeper line — R12 fallback swept {swept})");
        }
    };
    let errlog = parse_r22006_errlog(&stdout).expect("staging broken (no errlog line?)");
    let evidence = std::fs::read_to_string(&errlog).expect("errlog readable (staging?)");
    let _ = std::fs::remove_file(&errlog);
    assert!(
        !evidence.contains("deny-wait install failed"),
        "staging broken (seccomp unavailable?)\n{evidence}"
    );
    assert!(out.status.success(), "probe must complete\n{stderr}");
    assert!(
        stderr.contains("R22006-WAIT-DONE"),
        "probe must cite completion\n{stderr}"
    );
    assert_eq!(
        parse_r22006_code(&stdout),
        Some(3),
        "wait-denied publisher must exit 3 (unresolved, not 2)\n{evidence}"
    );
    assert!(
        evidence.contains("UNRESOLVED-CUSTODY"),
        "must cite unresolved custody\n{evidence}"
    );
    assert!(
        evidence.contains(&format!("sleeper={sleeper}")),
        "must name the sleeper pid\n{evidence}"
    );
    assert!(
        evidence.contains("kill_errno=none"),
        "kill must have landed (none = sent)\n{evidence}"
    );
    assert!(
        evidence.contains("reaped=false"),
        "must report unreaped\n{evidence}"
    );
}

/// R22-014/R12 fault leg, kill shape (toolchain twin):
/// mirror of the lib leg (the probe dies pre-transmit;
/// the fallback sweeps exactly 1 sleep-842 — restaged
/// from the GREEN 986 — then fails loud).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn r22006_kill_fallback_sweeps_untransmitted_sleeper() {
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("publisher_guard_denied_kill_reports_unresolved")
        .arg("--nocapture")
        .env("SCOPEBASE_R22014_EARLY_DEATH", "1")
        .env("SCOPEBASE_R22014_SLEEP_DUR", "842")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("leg child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "leg must fail loud (no sleeper line)\n{stderr}"
    );
    assert!(
        stderr.contains("R12 fallback swept 1"),
        "fallback must sweep the untransmitted sleeper\n{stderr}"
    );
    assert!(
        sleep_pids_with_dur("842").is_empty(),
        "no live sleep-842 may survive the fallback"
    );
}

/// R22-014/R12 fault leg, wait shape (toolchain twin):
/// mirror of the lib leg (restaged under sleep-843; the
/// swept count races 0/1 — assert the fallback ran +
/// loud fail + none live).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn r22006_wait_fallback_sweeps_untransmitted_sleeper() {
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("publisher_guard_denied_wait_reports_unresolved")
        .arg("--nocapture")
        .env("SCOPEBASE_R22014_EARLY_DEATH", "1")
        .env("SCOPEBASE_R22014_SLEEP_DUR", "843")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("leg child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "leg must fail loud (no sleeper line)\n{stderr}"
    );
    assert!(
        stderr.contains("R12 fallback swept"),
        "fallback must run on the missing line\n{stderr}"
    );
    assert!(
        sleep_pids_with_dur("843").is_empty(),
        "no live sleep-843 may survive the fallback"
    );
}

/// R22-015 (toolchain twin): mirror of the lib pub-cell
/// judge — verdict FIRST (a failed verdict panics WITHOUT
/// touching stderr), then the bounded drain, then the
/// diagnostic asserts.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn judge_pub_cell_toolchain(
    step: &str,
    elapsed: std::time::Duration,
    outcome: Option<(std::process::ExitStatus, bool, bool)>,
    stderr_pipe: Option<std::process::ChildStderr>,
    marker: &str,
) {
    let (status, stranded, post_empty) = outcome.unwrap_or_else(|| {
        panic!(
            "PUB-{step}: publisher hung (fault ignored?) after {elapsed:?} \
             (stderr undrained — verdict-first)"
        )
    });
    assert!(
        !stranded,
        "PUB-{step}: group must be ESRCH-empty (stranded sleeper; drain refused)"
    );
    assert!(
        post_empty,
        "PUB-{step}: group must prove ESRCH-empty after retire (squatter?; drain refused)"
    );
    let err = drain_pipe_bounded_toolchain(stderr_pipe, std::time::Duration::from_secs(5), step);
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "PUB-{step}: must fail promptly, took {elapsed:?}\nstderr: {err}"
    );
    assert_eq!(
        status.code(),
        Some(2),
        "PUB-{step}: must exit 2, got {status:?}\nstderr: {err}"
    );
    assert!(
        err.contains(marker),
        "PUB-{step}: stderr must name the failed step ({marker:?}), got {err:?}"
    );
}

/// R22-015 (toolchain twin): mirror of the lib bounded
/// pipe drain (nonblocking + deadline + 1MB cap; wedge
/// past the deadline panics loud with a partial preview).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn drain_pipe_bounded_toolchain(
    pipe: Option<std::process::ChildStderr>,
    timeout: std::time::Duration,
    what: &str,
) -> String {
    use std::io::Read as _;
    use std::os::unix::io::AsRawFd as _;
    const CAP: usize = 1024 * 1024;
    let Some(mut pipe) = pipe else {
        return String::new();
    };
    // SAFETY: fcntl O_NONBLOCK on our own pipe fd only.
    let flags = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0, "PUB-{what}: fcntl F_GETFL failed");
    let set = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
    assert_eq!(set, 0, "PUB-{what}: fcntl O_NONBLOCK failed");
    let mut buf: Vec<u8> = Vec::new();
    let mut total: usize = 0;
    let mut capped = false;
    let end = std::time::Instant::now() + timeout;
    loop {
        let mut chunk = [0u8; 8192];
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if buf.len() < CAP {
                    let room = CAP - buf.len();
                    buf.extend_from_slice(&chunk[..n.min(room)]);
                } else {
                    capped = true;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= end {
                    let preview = String::from_utf8_lossy(&buf[..buf.len().min(500)]).into_owned();
                    panic!(
                        "PUB-{what}: stderr drain wedged past {timeout:?} (a writer \
                         survived the verdict?!) — partial ({total} bytes): {preview:?}",
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(error) => panic!("PUB-{what}: stderr drain failed: {error}"),
        }
    }
    let mut out = String::from_utf8_lossy(&buf).into_owned();
    if capped {
        out.push_str("\n[TRUNCATED at 1MB]");
    }
    out
}

/// R22-015 (toolchain twin): mirror of the lib judge
/// regression — verdict-first (fast stranded-panic),
/// bounded wedge-panic (~5s), positive (returns).
/// Durations 9 and 10 are unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn judge_pub_cell_verdict_first_and_bounded() {
    use std::panic::AssertUnwindSafe;
    use std::time::{Duration, Instant};
    let exit2 = || {
        std::process::Command::new("sh")
            .arg("-c")
            .arg("exit 2")
            .status()
            .expect("exit-2 fabricates")
    };
    let message_of = |payload: Box<dyn std::any::Any + Send>| {
        payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("")
            .to_string()
    };
    let mut writer1 = std::process::Command::new("sh")
        .arg("-c")
        .arg("echo PUBMARK >&2; exec sleep 9")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("writer1 spawns");
    let mut _w1guard = SilentChildGuard::new(writer1.id() as i32);
    let pipe1 = writer1.stderr.take();
    let start = Instant::now();
    let verdict1 = std::panic::catch_unwind(AssertUnwindSafe(|| {
        judge_pub_cell_toolchain(
            "t",
            Duration::from_millis(100),
            Some((exit2(), true, false)),
            pipe1,
            "PUBMARK",
        )
    }));
    let leg1_time = start.elapsed();
    let _ = writer1.kill();
    let _ = writer1.wait();
    _w1guard.disarm();
    let message1 = match verdict1 {
        Ok(()) => panic!("leg 1 must panic (stranded verdict)"),
        Err(payload) => message_of(payload),
    };
    assert!(
        message1.contains("stranded"),
        "leg 1 must cite the verdict, got: {message1}"
    );
    assert!(
        leg1_time < Duration::from_secs(5),
        "leg 1 must fail fast (verdict-first — no drain), took {leg1_time:?}"
    );
    let mut writer2 = std::process::Command::new("sh")
        .arg("-c")
        .arg("echo PUBMARK >&2; exec sleep 10")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("writer2 spawns");
    let mut _w2guard = SilentChildGuard::new(writer2.id() as i32);
    let pipe2 = writer2.stderr.take();
    let start = Instant::now();
    let verdict2 = std::panic::catch_unwind(AssertUnwindSafe(|| {
        judge_pub_cell_toolchain(
            "t",
            Duration::from_millis(100),
            Some((exit2(), false, true)),
            pipe2,
            "PUBMARK",
        )
    }));
    let leg2_time = start.elapsed();
    let _ = writer2.kill();
    let _ = writer2.wait();
    _w2guard.disarm();
    let message2 = match verdict2 {
        Ok(()) => panic!("leg 2 must panic (wedged drain)"),
        Err(payload) => message_of(payload),
    };
    assert!(
        message2.contains("wedged"),
        "leg 2 must cite the wedge, got: {message2}"
    );
    assert!(
        leg2_time >= Duration::from_secs(5) && leg2_time < Duration::from_secs(30),
        "leg 2 must bound (~5s deadline), took {leg2_time:?}"
    );
    let mut writer3 = std::process::Command::new("sh")
        .arg("-c")
        .arg("echo PUBMARK >&2")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("writer3 spawns");
    let mut _w3guard = SilentChildGuard::new(writer3.id() as i32);
    let pipe3 = writer3.stderr.take();
    judge_pub_cell_toolchain(
        "t",
        Duration::from_millis(100),
        Some((exit2(), false, true)),
        pipe3,
        "PUBMARK",
    );
    let _ = writer3.wait();
    _w3guard.disarm();
}

/// R21-007 + R21-010-tails + R21-009-pair-setup (holistic —
/// ONE test, twin mirror): every post-birth producer step
/// fails prompt + loud + discharged; the receiver setup
/// retires the unknown-sleeper group on pre-parse failure;
/// the pair-setup tails never murder or steal planted
/// replacements. Publisher cells (pause/stat/comm/tick/
/// wait/epipe): each fresh self-grouped spawn must exit 2
/// promptly (≪ its sleep) with the group ESRCH-empty (the
/// sleeper retired by the publisher's own guard — never
/// orphaned). Receiver cells (eof/mangle): a pre-transmit
/// failure must surface as PROMPT EOF (never wedge the read
/// on the held pipe) and a torn pair must fail loud with the
/// parse cause — both with the unknown-sleeper group retired
/// (zombie-leader pin for eof, live-leader pin for mangle).
/// Tail cells (live/zombie plants): the gated tail spares a
/// live replacement and steals no zombie status. Durations
/// 942-950 and 952 are unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn pair_setup_holistic_retirement() {
    use std::time::{Duration, Instant};
    // One cell runner (env cells + the real-path EPIPE cell
    // share it): bounded wait, observe-before-cleanup
    // (sample group, retire leftovers, drain stderr —
    // post-cleanup so a stranded sleeper cannot wedge the
    // read), then judge code + step-fidelity + promptness +
    // group-empty.
    let run_pub_cell =
        |step: &str, secs: &str, envs: &[(&str, &str)], drop_read: bool, marker: &str| {
            let mut publisher = spawn_self_grouped_publisher(secs, "wait", envs);
            if drop_read {
                drop(publisher.stdout.take());
            }
            let pubpid = publisher.id() as i32;
            let mut _tpguard = SilentChildGuard::new(pubpid);
            // Birth tick at spawn (live-unreaped — nothing
            // reaped yet — so this first read names OUR
            // birth; every decision below re-verifies it).
            // R22-002 (twin mirror): decide while pinned,
            // reap after (the old shape reaped via try_wait
            // FIRST and then killpg'd the unpinned number).
            let pubtick = task_starttime_checked(pubpid)
                .unwrap_or_else(|error| panic!("PUB-{step}: publisher stat readable: {error}"))
                .unwrap_or_else(|| panic!("PUB-{step}: publisher visible"));
            // Leader-state poll (pin-verified every poll —
            // tick mismatch/gone is an invariant violation
            // (nothing reaps yet); unreadable polls through
            // (transient outage) and fails loud only when
            // persistent (unverifiable — refuse to kill
            // blindly).
            let start = Instant::now();
            let hung = loop {
                match task_starttime_checked(pubpid) {
                    Ok(Some(now)) if now == pubtick => {
                        if task_state(pubpid) == Some('Z') {
                            break false;
                        }
                    }
                    Ok(_) => panic!(
                        "PUB-{step}: leader reaped before observation \
                         (pin violated — impossible: nothing reaps yet)"
                    ),
                    Err(_) => {}
                }
                if start.elapsed() >= Duration::from_secs(10) {
                    match task_starttime_checked(pubpid) {
                        Ok(Some(now)) if now == pubtick => break true,
                        Ok(_) => panic!(
                            "PUB-{step}: leader reaped before observation \
                             (pin violated — impossible: nothing reaps yet)"
                        ),
                        Err(error) => panic!(
                            "PUB-{step}: leader unobservable for 10s \
                             (outage?): {error} — refusing to kill blindly"
                        ),
                    }
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            let elapsed = start.elapsed();
            // Both branches killpg with the leader unreaped
            // (pin held — re-verified inside) and reap
            // through the handle only after the decision.
            let outcome = if hung {
                let _ = retire_hung_publisher_group(&mut publisher, pubpid, pubtick);
                None
            } else {
                Some(retire_exited_publisher_group(
                    &mut publisher,
                    pubpid,
                    pubtick,
                ))
            };
            _tpguard.disarm();
            judge_pub_cell_toolchain(step, elapsed, outcome, publisher.stderr.take(), marker);
        };
    // Real pause-timeout path (absent flag + short deadline
    // hook — the 30s default would hang RED).
    let pause_flag = format!("/tmp/scopebase-r21holistic-absent-{}", std::process::id());
    run_pub_cell(
        "pause",
        "942",
        &[
            ("SCOPEBASE_PUBLISHER_PAUSE_FILE", pause_flag.as_str()),
            ("SCOPEBASE_PUBLISHER_PAUSE_TIMEOUT_MS", "200"),
        ],
        false,
        "pause flag never appeared",
    );
    // Fault-hook cells (each forced error branch post-spawn).
    for (step, secs) in [
        ("stat", "943"),
        ("comm", "944"),
        ("tick", "945"),
        ("wait", "946"),
    ] {
        run_pub_cell(
            step,
            secs,
            &[("SCOPEBASE_PUBLISHER_FAULT_STEP", step)],
            false,
            &format!("fault: {step}"),
        );
    }
    // Real EPIPE path (no env): the read end drops at once —
    // the transmit write must fail loud, not panic, and the
    // sleep must be retired, not stranded.
    run_pub_cell("epipe", "947", &[], true, "stdout broken");
    // Receiver pre-parse-failure runner: the setup shape
    // under test — try-parse, and on failure group-retire
    // BEFORE any reap (the leader is still unreaped, so the
    // killpg is pinned), then loud with the cause.
    // Observe-before-cleanup (sample group, retire
    // leftovers), then judge cause + group-empty.
    let run_recv_fail = |step: &str,
                         publisher: &mut std::process::Child,
                         pubpid: i32,
                         line: &str,
                         cause_sub: &str| {
        let failed =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || match try_parse_published_pair(line, "holistic publication") {
                    Ok(_) => panic!("RECV-{step}: torn pair must not parse"),
                    Err(cause) => {
                        let status = retire_unparsed_publisher_group(publisher);
                        panic!("RECV-{step}: setup failed ({cause}) — group retired ({status:?})");
                    }
                },
            ));
        // R22-002 (twin mirror): the post-reap leftover
        // killpg is DELETED (the leader is reaped — pin
        // released — so custody of the group is unprovable
        // and a killpg would be unpinned murder-bait; the
        // pinned killpg already ran inside the retire).
        // Anything still present fails the empty assert
        // below — loud, never certified. RED/neuter runs may
        // strand the unknown sleeper (unkillable-by-us
        // post-reap) and leak the leader zombie to process
        // exit (accepted — zombies auto-reap at exit; GREEN
        // runs never reach here non-empty).
        let empty = await_group_empty(pubpid, Duration::from_millis(500));
        let error = failed
            .err()
            .unwrap_or_else(|| panic!("RECV-{step}: must fail loud (the torn pair parsed?!)"));
        let message = error.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(
            message.contains(cause_sub),
            "RECV-{step}: cause must name the failure ({cause_sub:?}), got {message:?}"
        );
        assert!(
            empty,
            "RECV-{step}: group must be ESRCH-empty (unknown sleeper stranded)"
        );
    };
    // RECV-eof: the publisher fails pre-transmit (real pause
    // path) — the read must see EOF PROMPTLY (the
    // publisher's guard closed the pipe; pre-fix the read
    // wedged the full sleep) and the zombie-leader group
    // must retire with the loud parse cause.
    {
        use std::io::BufRead as _;
        let mut publisher = spawn_self_grouped_publisher(
            "948",
            "wait",
            &[
                ("SCOPEBASE_PUBLISHER_PAUSE_FILE", pause_flag.as_str()),
                ("SCOPEBASE_PUBLISHER_PAUSE_TIMEOUT_MS", "200"),
            ],
        );
        let pubpid = publisher.id() as i32;
        let mut _tpguard = SilentChildGuard::new(pubpid);
        let start = Instant::now();
        let mut line = String::new();
        let bytes = std::io::BufReader::new(publisher.stdout.take().expect("publisher stdout"))
            .read_line(&mut line)
            .expect("eof readable");
        let elapsed = start.elapsed();
        assert_eq!(bytes, 0, "RECV-eof: failed publisher must transmit nothing");
        assert!(
            elapsed < Duration::from_secs(5),
            "RECV-eof: EOF must arrive promptly, took {elapsed:?}"
        );
        run_recv_fail("eof", &mut publisher, pubpid, &line, "missing pid");
        _tpguard.disarm();
    }
    // RECV-mangle: real transmit, test-side torn pair (tick
    // dropped — the torn-write class) — the live-leader
    // group must retire with the loud parse cause (the
    // stranger stays unknown throughout).
    {
        use std::io::BufRead as _;
        let mut publisher = spawn_self_grouped_publisher("949", "wait", &[]);
        let pubpid = publisher.id() as i32;
        let mut _tpguard = SilentChildGuard::new(pubpid);
        let mut line = String::new();
        std::io::BufReader::new(publisher.stdout.take().expect("publisher stdout"))
            .read_line(&mut line)
            .expect("pair readable");
        let mangled = line
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        assert!(!mangled.is_empty(), "RECV-mangle: pair must transmit");
        run_recv_fail("mangle", &mut publisher, pubpid, &mangled, "missing tick");
        _tpguard.disarm();
    }
    // TAIL cells (own fns: a vacuous plant skips only its
    // cell — the R17-003 rule).
    tail_live_plant_cell();
    tail_zombie_plant_cell();
}

/// R21-010-tails (holistic cell, twin mirror): live-plant
/// arm — retire OUR pair, plant a live replacement on the
/// freed publisher number, run the tail with the STALE tick
/// → the replacement is spared (live, same birth, still our
/// unreaped child) and the tail is prompt (never a blocking
/// wait). Own fn so a vacuous plant skips ONLY this cell.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn tail_live_plant_cell() {
    use std::io::BufRead as _;
    use std::time::{Duration, Instant};
    {
        let _hold = match steer_hold() {
            Some(hold) => hold,
            None => {
                eprintln!("TAIL-live: vacuous (no reuse control)");
                return;
            }
        };
        let mut publisher = spawn_self_grouped_publisher("950", "wait", &[]);
        let pubpid = publisher.id() as i32;
        let mut _tpguard = SilentChildGuard::new(pubpid);
        let mut line = String::new();
        std::io::BufReader::new(publisher.stdout.take().expect("publisher stdout"))
            .read_line(&mut line)
            .expect("pair readable");
        let (stranger, stick) = parse_published_pair(line.trim(), "tail publication");
        let pubtick = task_starttime_checked(pubpid)
            .expect("publisher stat readable")
            .expect("publisher visible");
        let mut _tsguard = SilentChildGuard::new_expected(stranger, stick);
        assert!(
            _tsguard.tick.is_some(),
            "TAIL-live: stranger birth pinned at sighting"
        );
        // Retire OUR pair explicitly (loud): stranger first
        // (its death releases the publisher's wait tail),
        // then reap the publisher.
        assert!(
            retire_tick_gated_toolchain_child(stranger, stick),
            "TAIL-live: stranger retire readable"
        );
        assert!(
            await_task_gone_reaping(stranger, stick, Duration::from_secs(5)),
            "TAIL-live: stranger must drain"
        );
        _tsguard.disarm();
        let start = Instant::now();
        let status = loop {
            match publisher.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if start.elapsed() >= Duration::from_secs(5) {
                        panic!("TAIL-live: publisher must exit after its sleep dies");
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("TAIL-live: publisher wait failed: {error:?}"),
            }
        };
        assert!(status.success(), "TAIL-live: publisher must exit clean");
        _tpguard.disarm();
        // Plant a live replacement on the freed number
        // (vacuous under contention — the R17-003 rule).
        let (mut kid, mut plant_guard) = match plant_replacement(pubpid, pubtick) {
            Some(pair) => pair,
            None => {
                eprintln!("TAIL-live: vacuous (plant contended)");
                return;
            }
        };
        let retick = task_starttime_checked(pubpid)
            .expect("replacement readable")
            .expect("replacement live");
        // THE tail (stale tick — the exact call the
        // pair-setup tails make after OUR birth retired).
        let start = Instant::now();
        let _ = retire_tick_gated_toolchain_child(pubpid, pubtick);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "TAIL-live: tail must be prompt (never blocking)"
        );
        assert_eq!(
            task_starttime_checked(pubpid).expect("replacement readable"),
            Some(retick),
            "TAIL-live: replacement murdered?!"
        );
        // Settle (death is async — an instant sample
        // misreads murder as survival): the plant must stay
        // live with an empty pending mask across the FULL
        // window (a murdered plant flips Z in ms; a spared
        // one never receives a signal).
        assert!(settle_spared(pubpid), "TAIL-live: replacement murdered?!");
        assert!(
            matches!(kid.try_wait(), Ok(None)),
            "TAIL-live: replacement status stolen?!"
        );
        // Cleanup (loud): kill+reap the plant.
        let _ = kid.kill();
        let start = Instant::now();
        loop {
            match kid.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    if start.elapsed() >= Duration::from_secs(5) {
                        panic!("TAIL-live: plant must reap");
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("TAIL-live: plant wait failed: {error:?}"),
            }
        }
        plant_guard.disarm();
    }
}

/// R21-010-tails (holistic cell, twin mirror): zombie-plant
/// arm — same staging, but the plant settles to an unreaped
/// zombie before the tail runs with the stale tick → WE
/// still reap it (the tail's WNOHANG never fires on
/// mismatch). Own fn so a vacuous plant skips ONLY this
/// cell.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn tail_zombie_plant_cell() {
    use std::io::BufRead as _;
    use std::time::{Duration, Instant};
    {
        let _hold = match steer_hold() {
            Some(hold) => hold,
            None => {
                eprintln!("TAIL-zombie: vacuous (no reuse control)");
                return;
            }
        };
        let mut publisher = spawn_self_grouped_publisher("952", "wait", &[]);
        let pubpid = publisher.id() as i32;
        let mut _tpguard = SilentChildGuard::new(pubpid);
        let mut line = String::new();
        std::io::BufReader::new(publisher.stdout.take().expect("publisher stdout"))
            .read_line(&mut line)
            .expect("pair readable");
        let (stranger, stick) = parse_published_pair(line.trim(), "tail publication");
        let pubtick = task_starttime_checked(pubpid)
            .expect("publisher stat readable")
            .expect("publisher visible");
        let mut _tsguard = SilentChildGuard::new_expected(stranger, stick);
        assert!(
            _tsguard.tick.is_some(),
            "TAIL-zombie: stranger birth pinned at sighting"
        );
        assert!(
            retire_tick_gated_toolchain_child(stranger, stick),
            "TAIL-zombie: stranger retire readable"
        );
        assert!(
            await_task_gone_reaping(stranger, stick, Duration::from_secs(5)),
            "TAIL-zombie: stranger must drain"
        );
        _tsguard.disarm();
        let start = Instant::now();
        let status = loop {
            match publisher.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if start.elapsed() >= Duration::from_secs(5) {
                        panic!("TAIL-zombie: publisher must exit after its sleep dies");
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("TAIL-zombie: publisher wait failed: {error:?}"),
            }
        };
        assert!(status.success(), "TAIL-zombie: publisher must exit clean");
        _tpguard.disarm();
        let (mut kid, mut plant_guard) = match plant_replacement(pubpid, pubtick) {
            Some(pair) => pair,
            None => {
                eprintln!("TAIL-zombie: vacuous (plant contended)");
                return;
            }
        };
        assert!(
            settle_replacement_zombie(&mut kid, pubpid),
            "TAIL-zombie: staging broken (plant never zombified)"
        );
        // THE tail (stale tick).
        let start = Instant::now();
        let _ = retire_tick_gated_toolchain_child(pubpid, pubtick);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "TAIL-zombie: tail must be prompt (never blocking)"
        );
        // The zombie is intact: WE reap it (not stolen).
        match kid.try_wait() {
            Ok(Some(status)) => assert!(
                !status.success(),
                "TAIL-zombie: plant must be our SIGKILLed zombie"
            ),
            other => panic!("TAIL-zombie: status stolen?! got {other:?}"),
        }
        plant_guard.disarm();
    }
}

/// R22-001 leg 1 (toolchain twin): replacement zombie
/// squatting the discharged pgid number before entry —
/// mirror of the lib regression (steered self-grouped
/// retake; the observation must report non-empty and the
/// owner must retain the status). RED (old -pgid drain):
/// reaps the plant + reports empty. Duration 960 is unique
/// to this test. Leg 2 (mid-probe release + join) is the
/// sibling test below (no steering — always runs).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn group_observation_never_reaps_replacement_children() {
    use std::io::BufRead as _;
    use std::time::{Duration, Instant};
    let _hold = match steer_hold() {
        Some(hold) => hold,
        None => {
            eprintln!("R22001-leg1: vacuous (no reuse control)");
            return;
        }
    };
    let mut publisher = spawn_self_grouped_publisher("960", "wait", &[]);
    let pubpid = publisher.id() as i32;
    let mut _tpguard = SilentChildGuard::new(pubpid);
    let mut line = String::new();
    std::io::BufReader::new(publisher.stdout.take().expect("publisher stdout"))
        .read_line(&mut line)
        .expect("pair readable");
    let (stranger, stick) = parse_published_pair(line.trim(), "r22001 publication");
    let pubtick = task_starttime_checked(pubpid)
        .expect("publisher stat readable")
        .expect("publisher visible");
    let mut _tsguard = SilentChildGuard::new_expected(stranger, stick);
    assert!(
        _tsguard.tick.is_some(),
        "R22001-leg1: stranger birth pinned at sighting"
    );
    // Retire OUR pair explicitly (leader reaped via its
    // handle — pin RELEASED).
    assert!(
        retire_tick_gated_toolchain_child(stranger, stick),
        "R22001-leg1: stranger retire readable"
    );
    assert!(
        await_task_gone_reaping(stranger, stick, Duration::from_secs(5)),
        "R22001-leg1: stranger must drain"
    );
    let start = Instant::now();
    let status = loop {
        match publisher.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= Duration::from_secs(5) {
                    panic!("R22001-leg1: publisher must exit after its sleep dies");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("R22001-leg1: publisher wait failed: {error:?}"),
        }
    };
    assert!(status.success(), "R22001-leg1: publisher must exit clean");
    _tpguard.disarm();
    _tsguard.disarm();
    // Plant a SELF-GROUPED replacement on the freed pgid
    // number (steered retake + S100-vacuity, as
    // plant_replacement — with the group flag).
    let mut kid = match steer_sleep_onto(pubpid, true) {
        Some(kid) => kid,
        None => {
            eprintln!("R22001-leg1: vacuous (plant contended)");
            return;
        }
    };
    let mut plant_guard = SilentChildGuard::new(pubpid);
    let retick = match task_starttime_checked(pubpid) {
        Ok(Some(tick)) => tick,
        _ => {
            let _ = kid.kill();
            let _ = kid.wait();
            plant_guard.disarm();
            eprintln!("R22001-leg1: vacuous (plant unreadable)");
            return;
        }
    };
    if retick == pubtick {
        let _ = kid.kill();
        let _ = kid.wait();
        plant_guard.disarm();
        eprintln!("R22001-leg1: vacuous (same-tick retake — S100)");
        return;
    }
    assert!(
        task_pgrp_matches(&pubpid.to_string(), pubpid),
        "R22001-leg1: plant must self-group onto the recycled number"
    );
    assert!(
        settle_replacement_zombie(&mut kid, pubpid),
        "R22001-leg1: staging broken (plant never zombified)"
    );
    // THE observation (pin released — the plant is a
    // squatter, unreaped, owner handle held).
    let empty = await_group_empty(pubpid, Duration::from_secs(1));
    // Tail pattern: tick re-read first (mismatch = stolen
    // (reaped) — disarm before asserting, the number is
    // not-ours now).
    if task_starttime_checked(pubpid) != Ok(Some(retick)) {
        plant_guard.disarm();
    }
    assert!(
        !empty,
        "R22001-leg1: replacement group present — must not certify empty"
    );
    // Owner retains the status (reap proves no steal).
    match kid.try_wait() {
        Ok(Some(status)) => assert!(
            !status.success(),
            "R22001-leg1: plant must be our SIGKILLed zombie"
        ),
        other => panic!("R22001-leg1: status stolen?! got {other:?}"),
    }
    plant_guard.disarm();
}

/// R22-001 leg 2 (toolchain twin, after the last original
/// drain — mid-probe release + join): mirror of the lib
/// regression (no steering — a join, not a retake — always
/// runs). RED (old -pgid drain): steals mid-probe +
/// certifies empty. GREEN: false + intact statuses.
/// Durations 961/962 are unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn group_observation_never_reaps_joined_mid_probe() {
    use std::os::unix::process::CommandExt as _;
    use std::time::Duration;
    let mut leader_cmd = std::process::Command::new("/bin/sleep");
    leader_cmd
        .arg("961")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: setpgid on self pre-exec, no userspace state.
    unsafe {
        leader_cmd.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let mut leader = leader_cmd.spawn().expect("leader spawns");
    let lpid = leader.id() as i32;
    let mut lguard = SilentChildGuard::new(lpid);
    let ltick = task_starttime_checked(lpid)
        .expect("leader stat readable")
        .expect("leader visible");
    assert!(
        task_pgrp_matches(&lpid.to_string(), lpid),
        "R22001-leg2: leader must self-group"
    );
    // The plant joins OUR group pre-exec (setpgid on an
    // exec'd child is refused — the join must happen before
    // the image loads).
    let mut plant_cmd = std::process::Command::new("/bin/sleep");
    plant_cmd
        .arg("962")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: setpgid-join pre-exec, no userspace state.
    unsafe {
        plant_cmd.pre_exec(move || {
            if libc::setpgid(0, lpid) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let mut plant = plant_cmd.spawn().expect("plant spawns");
    let ppid = plant.id() as i32;
    let mut pguard = SilentChildGuard::new(ppid);
    let ptick = task_starttime_checked(ppid)
        .expect("plant stat readable")
        .expect("plant visible");
    assert!(
        task_pgrp_matches(&ppid.to_string(), lpid),
        "R22001-leg2: plant grouped"
    );
    // Probe threaded (1 s window — every main action below
    // lands inside with huge margins).
    let probe = std::thread::spawn(move || await_group_empty(lpid, Duration::from_secs(1)));
    std::thread::sleep(Duration::from_millis(50));
    // Kill the leader (zombie, pin STILL held — the probe
    // must not steal it: its status belongs to the handle).
    assert!(
        kill_tick_gated(lpid, ltick),
        "R22001-leg2: leader kill readable"
    );
    // Settle window (the old drain certainly polled — 1 ms
    // polls; a >100 ms scheduling stall is the only miss,
    // and the plant leg below still REDs).
    std::thread::sleep(Duration::from_millis(100));
    // The last original drain (owner reaps — pin released
    // mid-probe).
    let leader_status = leader.try_wait();
    if !matches!(leader_status, Ok(None)) {
        lguard.disarm();
    }
    // Zombify the joined plant (owner holds).
    // Settle accepts Z OR gone: on RED runs the old drain
    // may reap the zombie before this poll sees Z (gone
    // then is RED evidence, not broken staging); a plant
    // still LIVE past the bound is broken staging (the kill
    // failed).
    let _ = plant.kill();
    let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match task_state(ppid) {
            Some('Z') | None => break,
            Some(_) => {}
        }
        assert!(
            std::time::Instant::now() < end,
            "R22001-leg2: staging broken (plant never zombified)"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let empty = probe.join().expect("probe bounded");
    if task_starttime_checked(ppid) != Ok(Some(ptick))
        || !task_pgrp_matches(&ppid.to_string(), lpid)
    {
        // Occupant changed (stolen + recycled, or
        // re-grouped) — disarm before asserting.
        pguard.disarm();
    }
    assert!(
        !empty,
        "R22001-leg2: replacement zombie present — must not certify empty"
    );
    match leader_status {
        Ok(Some(status)) => assert!(
            !status.success(),
            "R22001-leg2: leader must be our SIGKILLed zombie (status belongs to the handle)"
        ),
        other => panic!("R22001-leg2: leader status stolen?! got {other:?}"),
    }
    match plant.try_wait() {
        Ok(Some(status)) => assert!(
            !status.success(),
            "R22001-leg2: plant must be our SIGKILLed zombie"
        ),
        other => panic!("R22001-leg2: plant status stolen?! got {other:?}"),
    }
    pguard.disarm();
}

/// R22-002 working paths (toolchain twin, no steering —
/// always runs): mirror of the lib regression (hung retires
/// a live publisher; exited records stranded + retires a
/// zombie sh-leader with a live sleep orphaned to init).
/// RED (neuter — the fns postdate the bug; skipping the
/// killpg strands and the settle times out). Duration 966
/// (hung publisher) and 968 (stranded sleep) are unique to
/// this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn hung_and_exited_branches_retire_while_pinned() {
    use std::time::{Duration, Instant};
    // Hung cell: live publisher, real bin.
    {
        let mut publisher = spawn_self_grouped_publisher("966", "wait", &[]);
        let pubpid = publisher.id() as i32;
        let pubtick = task_starttime_checked(pubpid)
            .expect("publisher stat readable")
            .expect("publisher visible");
        let start = Instant::now();
        let status = retire_hung_publisher_group(&mut publisher, pubpid, pubtick);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "R22002-hung: retire must be prompt"
        );
        assert!(!status.success(), "R22002-hung: leader must be SIGKILLed");
        assert!(
            await_group_empty(pubpid, Duration::from_secs(1)),
            "R22002-hung: group must be ESRCH-empty"
        );
    }
    // Exited cell: zombie sh-leader (pin held) + live sleep
    // orphaned to init (stranded, not ours).
    {
        use std::os::unix::process::CommandExt as _;
        let mut leader_cmd = std::process::Command::new("/bin/sh");
        leader_cmd
            .arg("-c")
            .arg("sleep 968 & wait")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // SAFETY: setpgid on self pre-exec, no userspace state.
        unsafe {
            leader_cmd.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let mut leader = leader_cmd.spawn().expect("leader spawns");
        let lpid = leader.id() as i32;
        let mut lguard = SilentChildGuard::new(lpid);
        let ltick = task_starttime_checked(lpid)
            .expect("leader stat readable")
            .expect("leader visible");
        assert!(
            task_pgrp_matches(&lpid.to_string(), lpid),
            "R22002-exited: leader must self-group"
        );
        // Discover the sleep (the non-leader member — only
        // two members ever exist here).
        let (spid, stick) = {
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                let others: Vec<(i32, u64)> = enumerate_group_members(lpid)
                    .iter()
                    .filter(|member| member.pid != lpid)
                    .filter_map(|member| member.birth.map(|(_, tick)| (member.pid, tick)))
                    .collect();
                if others.len() == 1 {
                    break others[0];
                }
                assert!(
                    Instant::now() < end,
                    "R22002-exited: staging broken (sleep never appeared)"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        };
        // Kill the leader to a zombie (pin HELD — unreaped);
        // the sleep orphans to init (live, not ours —
        // ECHILD for us, exactly like production).
        assert!(
            kill_tick_gated(lpid, ltick),
            "R22002-exited: leader kill readable"
        );
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            if task_state(lpid) == Some('Z') {
                break;
            }
            assert!(
                Instant::now() < end,
                "R22002-exited: staging broken (leader never zombified)"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let start = Instant::now();
        let (status, stranded, post_empty) =
            retire_exited_publisher_group(&mut leader, lpid, ltick);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "R22002-exited: retire must be prompt"
        );
        assert!(stranded, "R22002-exited: stranding must be recorded");
        assert!(!status.success(), "R22002-exited: leader must be SIGKILLed");
        assert!(post_empty, "R22002-exited: group must prove ESRCH-empty");
        assert!(
            await_task_gone_reaping(spid, stick, Duration::from_secs(5)),
            "R22002-exited: stranded sleep must drain"
        );
        lguard.disarm();
    }
}

/// R22-002 refusal paths (toolchain twin, steered squatters —
/// vacuous under contention): mirror of the lib regression
/// (discharged number + live self-grouped squatter + stale
/// tick → loud pin-lost refusal WITHOUT killing, squatter
/// settled-spared, both branches). RED (neuter — skipping
/// the re-pin murders the squatter). Duration 967
/// (publisher staging) is unique to this test (the squatter
/// is the steered sleep-31 standin).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn hung_and_exited_branches_refuse_discharged_numbers() {
    use std::io::BufRead as _;
    use std::time::{Duration, Instant};
    // Stage per cell: spawn, retire OUR pair explicitly (pin
    // RELEASED), steer a live self-grouped squatter onto
    // the freed number.
    macro_rules! stage_discharged {
        ($cell:expr) => {{
            let mut publisher = spawn_self_grouped_publisher("967", "wait", &[]);
            let pubpid = publisher.id() as i32;
            let mut line = String::new();
            std::io::BufReader::new(publisher.stdout.take().expect("publisher stdout"))
                .read_line(&mut line)
                .expect("pair readable");
            let (stranger, stick) = parse_published_pair(line.trim(), "r22002 publication");
            let pubtick = task_starttime_checked(pubpid)
                .expect("publisher stat readable")
                .expect("publisher visible");
            assert!(
                retire_tick_gated_toolchain_child(stranger, stick),
                "R22002-{}: stranger retire readable",
                $cell
            );
            assert!(
                await_task_gone_reaping(stranger, stick, Duration::from_secs(5)),
                "R22002-{}: stranger must drain",
                $cell
            );
            let start = Instant::now();
            loop {
                match publisher.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {
                        if start.elapsed() >= Duration::from_secs(5) {
                            panic!("R22002-{}: publisher must exit", $cell);
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("R22002-{}: wait failed: {error:?}", $cell),
                }
            }
            let mut squatter = match steer_sleep_onto(pubpid, true) {
                Some(kid) => kid,
                None => {
                    eprintln!("R22002-{}: vacuous (squatter contended)", $cell);
                    return;
                }
            };
            let mut squatter_guard = SilentChildGuard::new(pubpid);
            let squat_tick = match task_starttime_checked(pubpid) {
                Ok(Some(tick)) => tick,
                _ => {
                    let _ = squatter.kill();
                    let _ = squatter.wait();
                    squatter_guard.disarm();
                    eprintln!("R22002-{}: vacuous (squatter unreadable)", $cell);
                    return;
                }
            };
            if squat_tick == pubtick {
                let _ = squatter.kill();
                let _ = squatter.wait();
                squatter_guard.disarm();
                eprintln!("R22002-{}: vacuous (same-tick retake — S100)", $cell);
                return;
            }
            assert!(
                task_pgrp_matches(&pubpid.to_string(), pubpid),
                "R22002-{}: squatter must self-group onto the recycled number",
                $cell
            );
            (
                publisher,
                pubpid,
                pubtick,
                squatter,
                squatter_guard,
                squat_tick,
            )
        }};
    }
    let _hold = match steer_hold() {
        Some(hold) => hold,
        None => {
            eprintln!("R22002-refuse: vacuous (no reuse control)");
            return;
        }
    };
    // Hung cell: stale handle + stale tick on a live
    // squatter's number → refusal (no killpg).
    {
        let (mut publisher, pubpid, pubtick, mut squatter, mut squatter_guard, squat_tick) =
            stage_discharged!("hung");
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            retire_hung_publisher_group(&mut publisher, pubpid, pubtick);
        }));
        let error = match failed {
            Ok(_) => panic!("R22002-hung: must refuse loud"),
            Err(error) => error,
        };
        let message = error.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(
            message.contains("pin lost"),
            "R22002-hung: refusal must name the lost pin, got {message:?}"
        );
        assert!(settle_spared(pubpid), "R22002-hung: squatter murdered?!");
        assert_eq!(
            task_starttime_checked(pubpid).expect("squatter readable"),
            Some(squat_tick),
            "R22002-hung: squatter birth must persist"
        );
        let _ = squatter.kill();
        let start = Instant::now();
        loop {
            match squatter.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    if start.elapsed() >= Duration::from_secs(5) {
                        panic!("R22002-hung: squatter must reap");
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("R22002-hung: squatter wait failed: {error:?}"),
            }
        }
        squatter_guard.disarm();
    }
    // Exited cell: same staging, the exited branch.
    {
        let (mut publisher, pubpid, pubtick, mut squatter, mut squatter_guard, squat_tick) =
            stage_discharged!("exited");
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            retire_exited_publisher_group(&mut publisher, pubpid, pubtick);
        }));
        let error = match failed {
            Ok(_) => panic!("R22002-exited: must refuse loud"),
            Err(error) => error,
        };
        let message = error.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(
            message.contains("pin lost"),
            "R22002-exited: refusal must name the lost pin, got {message:?}"
        );
        assert!(settle_spared(pubpid), "R22002-exited: squatter murdered?!");
        assert_eq!(
            task_starttime_checked(pubpid).expect("squatter readable"),
            Some(squat_tick),
            "R22002-exited: squatter birth must persist"
        );
        let _ = squatter.kill();
        let start = Instant::now();
        loop {
            match squatter.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    if start.elapsed() >= Duration::from_secs(5) {
                        panic!("R22002-exited: squatter must reap");
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("R22002-exited: squatter wait failed: {error:?}"),
            }
        }
        squatter_guard.disarm();
    }
}

/// R22-003(a) plants (toolchain twin, steered — vacuous
/// under contention): the tail helper must never touch a
/// recycled number — a live plant survives unsignaled
/// (settled-spared) and a zombie plant's status stays with
/// its owner, under BOTH retired flags (true skips at the
/// verdict gate; false re-verifies by tick inside the
/// gated retire — both layers proven on one staging each).
/// RED (neuter: unconditional kill + WNOHANG waitpid —
/// murder + steal). Duration 969 (staging) is unique to
/// this test (plants are steered sleep-31 standins).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn tail_helper_skips_recycled_numbers() {
    use std::time::{Duration, Instant};
    let _hold = match steer_hold() {
        Some(hold) => hold,
        None => {
            eprintln!("R22003a: vacuous (no reuse control)");
            return;
        }
    };
    // Stage: spawn, retire OUR birth explicitly (number
    // freed), steer a plant onto it. Returns the freed
    // number + original tick + plant parts, or None when
    // vacuous.
    macro_rules! stage_plant {
        ($leg:expr, $zombie:expr) => {{
            let mut birth = std::process::Command::new("/bin/sleep")
                .arg("969")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("birth spawns");
            let pid = birth.id() as i32;
            // R22-014: guard at birth (the tick read below
            // must not strand the birth).
            let mut _bguard = SilentChildGuard::new(pid);
            let tick = task_starttime_checked(pid)
                .expect("birth stat readable")
                .expect("birth visible");
            let _ = birth.kill();
            let start = Instant::now();
            loop {
                match birth.try_wait() {
                    Ok(Some(_)) => {
                        _bguard.disarm();
                        break;
                    }
                    Ok(None) => {
                        if start.elapsed() >= Duration::from_secs(5) {
                            panic!("R22003a-{}: birth must reap", $leg);
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("R22003a-{}: wait failed: {error:?}", $leg),
                }
            }
            let mut plant = match steer_sleep_onto(pid, false) {
                Some(kid) => kid,
                None => {
                    eprintln!("R22003a-{}: vacuous (plant contended)", $leg);
                    return;
                }
            };
            let mut guard = SilentChildGuard::new(pid);
            let ptick = match task_starttime_checked(pid) {
                Ok(Some(tick)) => tick,
                _ => {
                    let _ = plant.kill();
                    let _ = plant.wait();
                    guard.disarm();
                    eprintln!("R22003a-{}: vacuous (plant unreadable)", $leg);
                    return;
                }
            };
            if ptick == tick {
                let _ = plant.kill();
                let _ = plant.wait();
                guard.disarm();
                eprintln!("R22003a-{}: vacuous (same-tick retake — S100)", $leg);
                return;
            }
            if $zombie {
                assert!(
                    settle_replacement_zombie(&mut plant, pid),
                    "R22003a-{}: staging broken (plant never zombified)",
                    $leg
                );
            }
            (pid, tick, plant, guard, ptick)
        }};
    }
    // Live leg: both flags skip, plant unsignaled.
    {
        let (pid, tick, mut plant, mut guard, ptick) = stage_plant!("live", false);
        retire_tail_unless_retired(pid, tick, true, "R22003a-live");
        retire_tail_unless_retired(pid, tick, false, "R22003a-live");
        assert!(settle_spared(pid), "R22003a-live: plant murdered?!");
        assert_eq!(
            task_starttime_checked(pid).expect("plant readable"),
            Some(ptick),
            "R22003a-live: plant birth must persist"
        );
        let _ = plant.kill();
        let _ = plant.wait();
        guard.disarm();
    }
    // Zombie leg: both flags skip, owner retains.
    {
        let (pid, tick, mut plant, mut guard, _ptick) = stage_plant!("zombie", true);
        retire_tail_unless_retired(pid, tick, true, "R22003a-zombie");
        retire_tail_unless_retired(pid, tick, false, "R22003a-zombie");
        match plant.try_wait() {
            Ok(Some(status)) => assert!(
                !status.success(),
                "R22003a-zombie: plant must be our SIGKILLed zombie"
            ),
            other => panic!("R22003a-zombie: status stolen?! got {other:?}"),
        }
        guard.disarm();
    }
}

/// R22-003(a) working path (toolchain twin, no steering —
/// always runs): the tail helper still retires a live
/// unretired birth (gated kill + bounded WNOHANG reap —
/// prompt, gone after). RED (neuter: the unretired arm
/// no-ops — the birth survives). Duration 970 is unique to
/// this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn tail_helper_retires_live_birth() {
    use std::time::{Duration, Instant};
    let birth = std::process::Command::new("/bin/sleep")
        .arg("970")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("birth spawns");
    let pid = birth.id() as i32;
    let mut guard = SilentChildGuard::new(pid);
    let tick = task_starttime_checked(pid)
        .expect("birth stat readable")
        .expect("birth visible");
    let start = Instant::now();
    retire_tail_unless_retired(pid, tick, false, "R22003a-working");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "R22003a-working: retire must be prompt"
    );
    assert!(
        await_task_gone_reaping(pid, tick, Duration::from_secs(1)),
        "R22003a-working: birth must drain"
    );
    // The gated retire reaped via raw waitpid — the handle
    // is stale (ECHILD); drop it without waiting.
    drop(birth);
    guard.disarm();
}

/// R22-003(a) wedge demo (toolchain twin, steered —
/// vacuous under contention): the OLD tail shape (blocking
/// wait on the stale number after the guard raw-reaped +
/// the number recycled to a live our-child) WEDGES — a
/// scoped thread parked in raw blocking waitpid is still
/// blocked after 2s (the sleeper lives ~15min; a prompt
/// tail returns in ms). The join then proves the waitpid
/// was genuinely parked on our number (it reaps the plant
/// — the steal half), while the NEW tail is prompt AND
/// harmless on the same live recycler. DEMO (always
/// passes — it locks the defect mechanism, not the fix;
/// the fix is locked by the skip/working tests above).
/// Duration 976 (birth) is unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn tail_blocking_wait_wedges_on_live_recycler() {
    use std::time::{Duration, Instant};
    let _hold = match steer_hold() {
        Some(hold) => hold,
        None => {
            eprintln!("R22003a-wedge: vacuous (no reuse control)");
            return;
        }
    };
    let mut birth = std::process::Command::new("/bin/sleep")
        .arg("976")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("birth spawns");
    let pid = birth.id() as i32;
    // R22-014: guard at birth (the tick read below must
    // not strand the birth).
    let mut _bguard = SilentChildGuard::new(pid);
    let tick = task_starttime_checked(pid)
        .expect("birth stat readable")
        .expect("birth visible");
    let _ = birth.kill();
    let start = Instant::now();
    loop {
        match birth.try_wait() {
            Ok(Some(_)) => {
                _bguard.disarm();
                break;
            }
            Ok(None) => {
                if start.elapsed() >= Duration::from_secs(5) {
                    panic!("R22003a-wedge: birth must reap");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("R22003a-wedge: wait failed: {error:?}"),
        }
    }
    drop(birth);
    let mut plant = match steer_sleep_onto(pid, false) {
        Some(kid) => kid,
        None => {
            eprintln!("R22003a-wedge: vacuous (plant contended)");
            return;
        }
    };
    let mut guard = SilentChildGuard::new(pid);
    match task_starttime_checked(pid) {
        Ok(Some(ptick)) if ptick != tick => {}
        _ => {
            let _ = plant.kill();
            let _ = plant.wait();
            guard.disarm();
            eprintln!("R22003a-wedge: vacuous (plant unreadable/same-tick)");
            return;
        }
    }
    // OLD shape: blocking wait on the stale number (what
    // `Child::wait` does once the status was consumed
    // externally — waitpid(number, 0) on the live recycler).
    let wedged = std::thread::spawn(move || {
        let mut status = 0;
        // SAFETY: blocking reap of the staged live plant
        // (the demo's whole point — joined below).
        let got = unsafe { libc::waitpid(pid, &mut status, 0) };
        (got, status)
    });
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        !wedged.is_finished(),
        "R22003a-wedge: old blocking wait returned?! (wedge not demonstrated)"
    );
    eprintln!("R22003a-wedge: old shape still blocked after 2s (wedge proved)");
    // NEW shape on the SAME live recycler: prompt + harmless.
    let start = Instant::now();
    retire_tail_unless_retired(pid, tick, true, "R22003a-wedge");
    retire_tail_unless_retired(pid, tick, false, "R22003a-wedge");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "R22003a-wedge: new tail must be prompt"
    );
    assert!(settle_spared(pid), "R22003a-wedge: plant murdered?!");
    // Release the wedge: the parked waitpid reaps the plant
    // (proving it was genuinely parked on our number — the
    // steal half of the old shape's harm).
    let _ = plant.kill();
    let (got, _status) = wedged.join().expect("wedge thread joins");
    assert_eq!(got, pid, "R22003a-wedge: waitpid must reap our plant");
    assert!(
        plant.try_wait().is_err(),
        "R22003a-wedge: status must have gone to the parked wait (ECHILD here)"
    );
    drop(plant);
    guard.disarm();
}

/// R19-014 (toolchain twin): sensitivity lock — the shared
/// verdict must FAIL on a live pair (missing retirement):
/// the assistance is reap-only (never kills), so survivors
/// read Some. In-process (no adoption involved); short
/// budget (a live-forever pair flips never — any budget
/// fails; 200ms keeps it fast). Cleanup rides the guards
/// (never disarmed here). Duration 77 is unique to this test
/// (both harnesses).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn stranger_staging_verdict_fails_live_pair() {
    use std::io::BufRead as _;
    #[allow(clippy::zombie_processes)]
    let mut publisher = std::process::Command::new(pair_publisher_bin())
        .arg("77")
        .arg("wait")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("publisher spawns");
    let mut line = String::new();
    std::io::BufReader::new(publisher.stdout.take().expect("publisher stdout"))
        .read_line(&mut line)
        .expect("stranger pid readable");
    let (stranger, stick) = parse_published_pair(line.trim(), "stranger publication");
    let pubpid = publisher.id() as i32;
    let pubtick = task_starttime_checked(pubpid)
        .expect("publisher stat readable")
        .expect("publisher visible");
    // Own teardown (the verdict below must NOT retire —
    // the drops here do).
    let _stranger_guard = SilentChildGuard::new_expected(stranger, stick);
    let _publisher_guard = SilentChildGuard::new(pubpid);
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        stranger_staging_verdict(stranger, stick, pubpid, pubtick, Duration::from_millis(200));
    }));
    assert!(
        failed.is_err(),
        "verdict must fail a live pair (missing retirement)"
    );
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
/// R16-011: the second replacement rides its OWN guard (the
/// stale first guard correctly spares it — including on unwind
/// — so without independent custody a failed observation or
/// assertion below would strand a perpetual pauser).
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
    // R16-011: independent custody for the second replacement
    // (the stale first guard spares it by design — unwind
    // included — so the reads and asserts below would strand
    // it without this).
    let mut second_guard = SilentChildGuard::new(seed);
    let second_tick = task_starttime_checked(seed)
        .expect("second stat readable")
        .expect("second visible");
    if second_tick == first_tick {
        kill_wait_child(seed);
        second_guard.disarm();
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
    second_guard.disarm();
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
    // R19003-FLAKE01: confine the table before any
    // exhaustion below (fresh image — the limit dies
    // with the probe).
    let _confined = confine_fd_table_for_exhaustion();
    // Stage the fixture (all fds available here). The stranger
    // mode keeps its publisher parent for loud cleanup below.
    // R16-011: staging guards (declared here, armed at each
    // birth — a failed expect/assert anywhere below unwinds
    // through retirement, never an orphaned pauser/sleeper).
    let mut staged_publisher: Option<std::process::Child> = None;
    let mut _zguard: Option<SilentChildGuard> = None;
    let mut _publisher_guard: Option<SilentChildGuard> = None;
    let mut _stranger_guard: Option<SilentChildGuard> = None;
    // R19-012: birth guard for the owned live/gone/stolen
    // arm (armed at birth below — the transmit read must
    // never run unguarded; an unguarded failure orphans an
    // infinite pauser with no owner at all).
    let mut _owned_guard: Option<SilentChildGuard> = None;
    // R20-005: transmitted birth, when a publisher named
    // one (stranger modes — the tail reuses it, never a
    // fresh read that a gap replacement would
    // self-authenticate).
    let mut transmitted: Option<u64> = None;
    // R20-005: steered-replacement state (replacement
    // tick + middleman pid) and custody, armed at
    // placement; the replacement sits ON `pid`.
    let mut _m1_guard: Option<SilentChildGuard> = None;
    let mut _m2_guard: Option<SilentChildGuard> = None;
    let mut repl_tick: Option<u64> = None;
    let mut m1pid: Option<i32> = None;
    let pid = match mode {
        "live" | "gone" | "stolen" | "observe-fail" => {
            let pid = fork_pauser();
            // R19-012: custody AT birth (own unreaped child —
            // the reservation makes the bare pin sound; a
            // failed transmit read below unwinds through
            // retirement, never an orphaned pauser).
            _owned_guard = Some(SilentChildGuard::new(pid));
            pid
        }
        "zombie" => {
            // SAFETY: fork; the child only _exits (no runtime,
            // no locks).
            let kid = unsafe { libc::fork() };
            if kid == 0 {
                unsafe { libc::_exit(0) };
            }
            assert!(kid > 0, "zombie fork");
            _zguard = Some(SilentChildGuard::new(kid));
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
        "stranger" | "stranger-replaced" => {
            let mut parent = std::process::Command::new(pair_publisher_bin())
                .arg("879")
                .arg("wait")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("publisher spawns");
            // R16-011: custody AT birth for both (the asserts
            // below unwind through retirement, never orphans).
            _publisher_guard = Some(SilentChildGuard::new(parent.id() as i32));
            let mut line = String::new();
            std::io::BufReader::new(parent.stdout.take().expect("publisher stdout"))
                .read_line(&mut line)
                .expect("grandchild pid readable");
            // R19-001: transmitted pair (no receiver
            // first-read — a gap replacement would
            // self-authenticate).
            let (stranger, stranger_tick) =
                parse_published_pair(line.trim(), "stranger publication");
            transmitted = Some(stranger_tick);
            _stranger_guard = Some(SilentChildGuard::new_expected(stranger, stranger_tick));
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
            staged_publisher = Some(parent);
            if mode == "stranger-replaced" {
                // R20-005: kill the original, then steer a
                // different-birth NON-CHILD replacement
                // (pausing middleman's grandchild sleep)
                // onto its number — the gap the tail must
                // refuse via the transmitted birth, never
                // fresh-read. Twin of the audit arm.
                // SAFETY: signal-only to the staged stranger.
                assert_eq!(
                    unsafe { libc::kill(stranger, libc::SIGKILL) },
                    0,
                    "original stranger signaled"
                );
                // The original's publisher reaps it and exits;
                // poll the number free.
                let end = Instant::now() + Duration::from_secs(10);
                loop {
                    if task_starttime_checked(stranger) == Ok(None) {
                        break;
                    }
                    assert!(Instant::now() < end, "original number must free");
                    std::thread::sleep(Duration::from_millis(1));
                }
                // Drain the original publisher itself (its zombie
                // — usually at stranger-1 by spawn order —
                // would shift every placement by one). The
                // tail below re-observes the drained handle.
                if let Some(parent) = staged_publisher.as_mut() {
                    let end = Instant::now() + Duration::from_secs(10);
                    loop {
                        if parent.try_wait().expect("parent wait").is_some() {
                            break;
                        }
                        assert!(Instant::now() < end, "publisher must exit");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                // Settle past any jiffy boundary (12ms > the
                // 10ms HZ=100 jiffy, the coarsest on x86_64):
                // the replacement birth below is then
                // provably a different tick — asserted, not
                // assumed.
                std::thread::sleep(Duration::from_millis(12));
                let last_path = "/proc/sys/kernel/ns_last_pid";
                let last_before = std::fs::read_to_string(last_path).unwrap_or_default();
                // Steer middleman→stranger-1 so its
                // grandchild lands ON stranger; retry on
                // ambient-shift misses (park + retry —
                // contention skips loud below).
                let placed: Option<(i32, u64)> = (0..20).find_map(|_| {
                    let _flock = ns_last_pid_flock();
                    if !steer_next_pid_unlocked(stranger - 1) {
                        return None;
                    }
                    // SAFETY: child syscalls-only; both
                    // retired below (miss-park or armed
                    // guards).
                    let (m1, m2) = unsafe { fork_pausing_grandchild_sleep("906") }?;
                    if m2 != stranger {
                        // Miss: park + retry (the
                        // middleman is ours — kill +
                        // reap; its grandchild zombie
                        // reparents to init on the
                        // middleman's death).
                        unsafe {
                            libc::kill(m2, libc::SIGKILL);
                            libc::kill(m1, libc::SIGKILL);
                        }
                        let end = Instant::now() + Duration::from_secs(5);
                        loop {
                            let mut st = 0;
                            // SAFETY: WNOHANG assist
                            // only — our child.
                            if unsafe { libc::waitpid(m1, &mut st, libc::WNOHANG) } == m1 {
                                break;
                            }
                            if Instant::now() >= end {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        return None;
                    }
                    let rtick = task_starttime_checked(m2).ok().flatten()?;
                    _m1_guard = Some(SilentChildGuard::new(m1));
                    _m2_guard = Some(SilentChildGuard::new_expected(m2, rtick));
                    m1pid = Some(m1);
                    Some((m2, rtick))
                });
                locked_restore_hint(&last_before);
                let (m2, rtick) = match placed {
                    Some(hit) => hit,
                    None => {
                        eprintln!("R20005-SKIP placement contended (retake race)");
                        eprintln!("R15005-CHILD-DONE mode={mode}");
                        return;
                    }
                };
                assert_ne!(
                    rtick, stranger_tick,
                    "replacement birth must differ (jiffy-settled, stage broken otherwise)"
                );
                assert_eq!(m2, stranger, "replacement must sit on the number");
                repl_tick = Some(rtick);
                eprintln!("R20005-ORIGINAL pid={stranger} tick={stranger_tick}");
                eprintln!("R20005-REPLACEMENT pid={m2} tick={rtick}");
            }
            stranger
        }
        _ => panic!("unknown probe mode {mode}"),
    };
    // R19-012: steered first-observation failure — the
    // fresh image inherits exhaustion, modeled by
    // exhausting AFTER the birth guard is armed (unwind
    // drops the exhaustion first, restoring fds before
    // the guard retires verified — never the unresolved
    // fallback). The transmit read must fail, and the
    // birth guard must retire + discharge the live pauser
    // before the failure reports. RED (no birth guard):
    // the infinite pauser survives with no owner and the
    // retirement assert fails.
    if mode == "observe-fail" {
        // R18-012 bar: genuine exhaustion ONLY (any other
        // terminal error is a broken exhauster — the
        // verdicts below would be vacuous).
        let terminal_is_emfile = std::cell::Cell::new(false);
        // Shared by reference (the closure below moves
        // the guard, so it cannot also move the cell).
        let term_flag = &terminal_is_emfile;
        let fired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _birth = _owned_guard;
            let mut steered = Vec::new();
            let terminal = loop {
                match std::fs::File::open("/dev/null") {
                    Ok(file) => steered.push(file),
                    Err(error) => break error,
                }
            };
            term_flag.set(terminal.raw_os_error() == Some(libc::EMFILE));
            assert!(!steered.is_empty(), "steered exhaustion must consume fds");
            let _tick = task_starttime_checked(pid)
                .expect("fixture stat readable")
                .expect("fixture present");
        }));
        assert!(
            terminal_is_emfile.get(),
            "steered exhaustion must end at EMFILE (broken exhauster otherwise)"
        );
        // Observe before cleanup: gone + discharged by the
        // unwind-drop (the tick is unknown — the read
        // failed — so absence + ECHILD, not tick-gated).
        let gone = task_starttime_checked(pid) == Ok(None);
        let mut status = 0;
        // SAFETY: WNOHANG discharge probe of our own child.
        let discharged = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } < 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD);
        // Cleanup (runs on RED too): waitpid-probe-first
        // retire (IR-002 — sound without the tick: ECHILD
        // skips the kill, a live owned child takes it).
        retire_child_silent(pid);
        assert!(
            fired.is_err(),
            "injection must take (transmit read must fail)"
        );
        assert!(
            gone && discharged,
            "birth guard must retire + discharge before the failure reports"
        );
        eprintln!("R19012-OBSERVE retired=1 discharged=1");
        eprintln!("R15005-CHILD-DONE mode={mode}");
        return;
    }
    // R18-004: TRANSMIT before custody — the tick read
    // here is bound (staging runs pre-exhaustion with
    // working reads; owned modes hold the reservation
    // and the stranger mode's publisher holds its child
    // in `wait`). R19-012: the transmit still precedes
    // EXPECTED-identity custody below — but the bare birth
    // guard above already holds the owned modes, so this
    // read is guarded, never first. Expected-identity
    // custody (a reap +
    // recycle between publication and acquisition refuses
    // instead of authenticating the replacement; the
    // R17-007 late-pin below is replaced by refusal, which
    // stands down per R18-003 — the dedicated recovery
    // probes keep pin() covered).
    // R20-005: stranger modes reuse the TRANSMITTED birth
    // captured above — a fresh read here would let a gap
    // replacement self-authenticate through the main
    // guards (the transmitted guard's stand-down does
    // not prevent the new grant).
    let tick = match transmitted {
        Some(birth) => birth,
        None => task_starttime_checked(pid)
            .expect("fixture stat readable")
            .expect("fixture present"),
    };
    // R16-011: staging custody for every mode (covers
    // every later assert — the drop test moves only the
    // mode guard, so this one still backstops the tails;
    // all verify silent on happy paths).
    let _staging_guard = SilentChildGuard::new_expected(pid, tick);
    // Pin BEFORE any mode-specific pre-step (gone retires
    // pre-exhaust; the pin must cite the live fixture).
    let guard = SilentChildGuard::new_expected(pid, tick);
    if mode == "stranger-replaced" {
        // The replacement sits on the number with a
        // different birth: both main guards must REFUSE
        // (transmitted mismatch) — pinned here means the
        // tail fresh-read and the replacement is doomed.
        assert!(
            _staging_guard.tick.is_none() && guard.tick.is_none(),
            "main guards must refuse the replaced birth"
        );
    }
    eprintln!("R15005-PINNED pid={pid} tick={tick}");
    // R16-004: retire+reap A (guard stale-armed), steer B onto
    // the number, zombify B unreaped (the sibling-owned zombie
    // the fallback must not reap). BEFORE exhaustion (fork
    // needs fds). Single-threaded probe: no in-process
    // contention, flock-only steering is sound.
    // R16-011: B custody (declared outside — the tail
    // disarms after reaping; skips disarm after retiring).
    let mut b_guard: Option<SilentChildGuard> = None;
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
        // R16-011: custody AT placement — the reads below
        // panic safe (B is a perpetual pauser until zombified).
        b_guard = Some(SilentChildGuard::new(sibling));
        let btick = task_starttime_checked(sibling)
            .expect("sibling stat readable")
            .expect("sibling visible");
        if btick == tick {
            kill_wait_child(sibling);
            if let Some(guard) = b_guard.as_mut() {
                guard.disarm();
            }
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
    // R20-005: the steered unwind must READ identity (RED
    // pinned kills, GREEN refused spares) — restore fds
    // first; the shared drop below then frees an empty
    // vec. (The exhaustion legs above still ran: the
    // tick-read-must-fail assert fired pre-restore.)
    let held = if mode == "stranger-replaced" {
        drop(held);
        Vec::new()
    } else {
        held
    };
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
            // R16-012: settled-live, not tick-only (a zombie
            // keeps its tick).
            assert_task_settled_live(
                pid,
                tick,
                2,
                "live fixture must survive the unresolved drop",
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
            if let Some(guard) = b_guard.as_mut() {
                guard.disarm();
            }
            eprintln!("R16004-STATUS retained pid={pid}");
        }
        "stranger" | "stranger-replaced" => {
            if mode == "stranger-replaced" {
                // R20-005: the complete path ran with refused
                // guards — the replacement (never signaled)
                // must be live. Then loud cleanup: the
                // sleeper (tick-gated — ours by placement)
                // dies-or-zombifies under the middleman, the
                // middleman is reaped (ours), the sleeper
                // zombie reparents to init (polled gone), the
                // original publisher (long exited) drains. Twin
                // of the audit tail.
                let rtick = repl_tick.expect("replacement staged");
                assert_task_settled_live(
                    pid,
                    rtick,
                    2,
                    "replacement must survive the refused path",
                );
                eprintln!("R20005-SURVIVED pid={pid} tick={rtick}");
                assert!(
                    kill_tick_gated(pid, rtick),
                    "replacement signaled (tick-gated)"
                );
                let end = Instant::now() + Duration::from_secs(5);
                loop {
                    let dead = match task_state(pid) {
                        None => true,
                        Some(state) => state == 'Z',
                    };
                    if dead {
                        break;
                    }
                    assert!(Instant::now() < end, "replacement must die");
                    std::thread::sleep(Duration::from_millis(1));
                }
                let m1 = m1pid.expect("middleman staged");
                // SAFETY: signal-only to our middleman.
                unsafe {
                    libc::kill(m1, libc::SIGKILL);
                }
                let mut status = 0;
                // SAFETY: blocking reap of our SIGKILLed
                // child — bounded by its death (µs).
                let got = unsafe { libc::waitpid(m1, &mut status, 0) };
                assert_eq!(got, m1, "middleman status drains to us");
                let end = Instant::now() + Duration::from_secs(5);
                loop {
                    if task_starttime_checked(pid) == Ok(None) {
                        break;
                    }
                    assert!(Instant::now() < end, "init must reap the orphaned zombie");
                    std::thread::sleep(Duration::from_millis(1));
                }
                let mut parent = staged_publisher.expect("publisher staged");
                let end = Instant::now() + Duration::from_secs(10);
                loop {
                    if parent.try_wait().expect("parent wait").is_some() {
                        break;
                    }
                    assert!(Instant::now() < end, "publisher must exit");
                    std::thread::sleep(Duration::from_millis(10));
                }
                eprintln!("R15005-CHILD-DONE mode={mode}");
                return;
            }
            // R16-012: settled-live, not tick-only (a zombie
            // keeps its tick).
            assert_task_settled_live(pid, tick, 2, "stranger must survive the unresolved drop");
            // Loud cleanup: kill the grandchild, reap publisher.
            // SAFETY: signal-only to the staged stranger.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            let mut parent = staged_publisher.expect("publisher staged");
            let end = Instant::now() + Duration::from_secs(10);
            loop {
                if parent.try_wait().expect("parent wait").is_some() {
                    break;
                }
                assert!(Instant::now() < end, "publisher must exit");
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

/// R19-012: a failed FIRST observation (the transmit tick
/// read, failed here by steered exhaustion modeling an
/// inherited-full table) must retire + discharge the live
/// owned pauser through the birth guard before the failure
/// reports. RED (no birth guard): the infinite pauser
/// survives with no owner and the probe fails its
/// retirement assert.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn emfile_observe_fail_retires_before_report() {
    if let Ok(mode) = std::env::var("SCOPEBASE_R15005_MODE") {
        emfile_probe_child(&mode);
        return;
    }
    let stderr = emfile_probe_spawn("observe-fail", "emfile_observe_fail_retires_before_report");
    assert!(
        stderr.contains("R19012-OBSERVE retired=1 discharged=1"),
        "observe-fail: retirement marker missing\n{stderr}"
    );
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

/// R20-005 (toolchain twin): a stranger replaced between
/// the arm checks and the common-tail acquisition must NOT
/// self-authenticate — the tail reuses the transmitted
/// birth, never a fresh read, and the different-birth
/// non-child replacement survives the complete caller
/// path. Twin of the audit
/// `audit_emfile_stranger_replacement_refuses_transmitted`.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn emfile_stranger_replacement_refuses_transmitted() {
    if let Ok(mode) = std::env::var("SCOPEBASE_R15005_MODE") {
        emfile_probe_child(&mode);
        return;
    }
    let stderr = emfile_probe_spawn(
        "stranger-replaced",
        "emfile_stranger_replacement_refuses_transmitted",
    );
    if stderr.contains("R20005-SKIP") {
        eprintln!("skip: replacement stage contended (see probe stderr)");
        return;
    }
    let pinned = emfile_probe_tagged(&stderr, "R15005-PINNED ", "stranger-replaced");
    let orig = emfile_probe_tagged(&stderr, "R20005-ORIGINAL ", "stranger-replaced");
    let repl = emfile_probe_tagged(&stderr, "R20005-REPLACEMENT ", "stranger-replaced");
    assert_eq!(
        pinned, orig,
        "transmit must reuse the transmitted birth (never fresh-read)\n{stderr}"
    );
    assert_ne!(
        repl.1, orig.1,
        "replacement must be a different birth (stage broken otherwise)\n{stderr}"
    );
    assert!(
        stderr.contains("R20005-SURVIVED"),
        "replacement must survive the complete path\n{stderr}"
    );
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
    // R17-006: custody ACROSS the restore — the flock re-take
    // below panics under EMFILE (open assert); without this a
    // restore panic strands the placed pauser. Disarmed on
    // success (the caller guards immediately — no fallible
    // ops between).
    let mut placed_guard = placed.map(SilentChildGuard::new);
    drop(_nsflock);
    locked_restore_hint(last_before);
    if let Some(guard) = placed_guard.as_mut() {
        guard.disarm();
    }
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
    // R17-006: custody ACROSS the restore (same window as the
    // pauser helper — a restore panic strands the standin).
    // Disarmed on success (the caller owns the Child handle
    // and guards immediately).
    let mut found_guard = found
        .as_ref()
        .map(|kid| SilentChildGuard::new(kid.id() as i32));
    locked_restore_hint(last_before.trim());
    if let Some(guard) = found_guard.as_mut() {
        guard.disarm();
    }
    found
}

/// R21-010-tails (twin mirror): serial hold for steering
/// (the in-process half — whole-cell hold; the caller drops
/// it at cell end). None when reuse control is unavailable
/// (the caller degrades its arm — loud eprintln, never a
/// silent pass).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn steer_hold() -> Option<std::sync::MutexGuard<'static, ()>> {
    let serial = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let last_before = match std::fs::read_to_string("/proc/sys/kernel/ns_last_pid") {
        Ok(text) => text.trim().to_string(),
        Err(_) => {
            eprintln!("skip: ns_last_pid unreadable (no reuse control)");
            return None;
        }
    };
    if !locked_steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
        eprintln!("skip: ns_last_pid unwritable (no reuse control)");
        return None;
    }
    locked_restore_hint(&last_before);
    Some(serial)
}

/// R21-010-tails (twin mirror): steer a live sleeper onto
/// the freed `want` for a DIFFERENT birth tick than
/// `orig_tick` (a same-tick retake is S100-untestable),
/// guarded from placement. Returns None when contended or
/// same-tick (the caller degrades its arm — prints the
/// reason — never skips the test: the fixed hygiene runs
/// unconditionally, only the replacement proof is
/// opportunistic). The caller owns cleanup (kill+wait) and
/// disarms the guard after. Requires the caller's serial
/// hold (see [`steer_hold`]).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn plant_replacement(want: i32, orig_tick: u64) -> Option<(std::process::Child, SilentChildGuard)> {
    let mut kid = match steer_sleep_onto(want, false) {
        Some(kid) => kid,
        None => {
            eprintln!("arm vacuous: retake contended");
            return None;
        }
    };
    let mut guard = SilentChildGuard::new(want);
    let retick = match task_starttime_checked(want) {
        Ok(Some(tick)) => tick,
        _ => {
            let _ = kid.kill();
            let _ = kid.wait();
            guard.disarm();
            eprintln!("arm vacuous: replacement unreadable");
            return None;
        }
    };
    if retick == orig_tick {
        let _ = kid.kill();
        let _ = kid.wait();
        guard.disarm();
        eprintln!("arm vacuous: same-tick retake (S100)");
        return None;
    }
    Some((kid, guard))
}

/// R21-010-tails (twin mirror): kill the owned replacement
/// and settle it to a zombie (unreaped — its status is the
/// arm's evidence). Returns false when the settle times out
/// (the caller treats the arm as failed-loud, never vacuous —
/// a SIGKILLed sleeper that never zombifies is broken
/// staging, not contention).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn settle_replacement_zombie(kid: &mut std::process::Child, pid: i32) -> bool {
    let _ = kid.kill();
    let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if matches!(task_state(pid), Some(state) if state == 'Z') {
            return true;
        }
        if std::time::Instant::now() >= end {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// R17-006: probe body (fresh image, SCOPEBASE_R17006_RESTORE)
/// — mirror of the steer-helper restore window: place a
/// pauser, guard it, exhaust fds, run the locked restore
/// (the flock open panics), unwind, restore fds, require the
/// pauser retired with its status discharged. RED (no guard):
/// the perpetual pauser strands; GREEN: the guard retires it
/// on unwind. No steering (placement mechanics orthogonal).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn steer_restore_window_probe() {
    // R19003-FLAKE01: confine the table before any
    // exhaustion below (fresh image — the limit dies
    // with the probe).
    let _confined = confine_fd_table_for_exhaustion();
    let hint = std::fs::read_to_string("/proc/sys/kernel/ns_last_pid").unwrap_or_default();
    let pauser = fork_pauser();
    let tick = task_starttime_checked(pauser)
        .expect("pauser stat readable")
        .expect("pauser visible");
    // Guard constructed outside (pin verified), dropped
    // inside on unwind; exhaustion declared LAST inside so
    // unwind drops held first (fds back), then the guard
    // retires.
    let guard = SilentChildGuard::new(pauser);
    assert_eq!(
        guard.tick,
        Some(tick),
        "construction must pin (stage broken otherwise)"
    );
    let fired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = guard;
        let mut held = Vec::new();
        while let Ok(file) = std::fs::File::open("/dev/null") {
            held.push(file);
        }
        assert!(!held.is_empty(), "exhaustion must consume fds");
        locked_restore_hint(hint.trim());
        panic!("unreachable: restore must panic under EMFILE");
    }));
    assert!(fired.is_err(), "restore must panic under EMFILE");
    // Observe before cleanup.
    let state = task_starttime_checked(pauser);
    let retired = task_retired_checked(pauser);
    // R18-007: tick-gated tail — the unwind drop above already
    // raw-reaped, so the number is fair game for retake: a
    // blind numeric kill would murder a recycled holder and a
    // blind waitpid would block on or steal a replacement's
    // status. Touch the number only while it still names the
    // expected birth.
    let restore_hygiene = || {
        let _ = retire_tick_gated_toolchain_child(pauser, tick);
    };
    // R18-007 arms (opportunistic — degrade loud when
    // unsteerable; single-threaded probe, no serial per the
    // steer exemption): retake the discharged number, run
    // the FULL tail. Arm 1 (live): bounded completion with
    // the replacement alive (RED: blind kill murders / blind
    // wait blocks). Arm 2 (zombie): status stays with its
    // owner (RED: stolen by the blind wait).
    if let Some(mut live) = steer_sleep_onto(pauser, false) {
        let mut live_guard = SilentChildGuard::new(pauser);
        let retick = task_starttime_checked(pauser)
            .expect("replacement stat readable")
            .expect("replacement visible");
        if retick != tick {
            let start = Instant::now();
            restore_hygiene();
            // R17-003: SIGKILL-settle (100ms, 10x margin).
            std::thread::sleep(Duration::from_millis(100));
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "restore hygiene must not block on a live replacement"
            );
            assert!(
                matches!(live.try_wait(), Ok(None)),
                "live replacement must survive restore hygiene"
            );
        } else {
            eprintln!("arm vacuous: same-tick retake (S100)");
        }
        let _ = live.kill();
        let _ = live.wait();
        live_guard.disarm();
    } else {
        eprintln!("arm vacuous: retake contended");
    }
    if let Some(mut zombie) = steer_sleep_onto(pauser, false) {
        let mut zombie_guard = SilentChildGuard::new(pauser);
        let retick = task_starttime_checked(pauser)
            .expect("replacement stat readable")
            .expect("replacement visible");
        if retick != tick {
            let _ = zombie.kill();
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                if task_retired_checked(pauser) == Ok(true) {
                    break;
                }
                assert!(Instant::now() < end, "replacement never zombied");
                std::thread::sleep(Duration::from_millis(10));
            }
            restore_hygiene();
            assert!(
                matches!(zombie.try_wait(), Ok(Some(_))),
                "zombie replacement status must stay with its owner"
            );
        } else {
            eprintln!("arm vacuous: same-tick retake (S100)");
            let _ = zombie.kill();
            let _ = zombie.wait();
        }
        zombie_guard.disarm();
    } else {
        eprintln!("arm vacuous: retake contended");
    }
    // Unarmed tail run (RED teardown when the arms are
    // vacuous: the original still holds its number) +
    // post-hygiene loudness (the gated primitive stands down
    // silently on mismatch): the ORIGINAL birth must be gone
    // — a recycled different-tick holder is not ours to touch
    // (child_gone, not pid_free).
    restore_hygiene();
    assert_child_gone(pauser, tick, "restore-probe pauser");
    assert_eq!(state, Ok(None), "restore panic must not strand the pauser");
    assert_eq!(retired, Ok(true), "restore panic must discharge the pauser");
    eprintln!("R17006-RESTORED retired=1");
}

/// R17-006: a restore panic between placement and the
/// caller's guard must still retire the placed pauser
/// (custody across the restore window — the flock re-take
/// panics under EMFILE). The probe mirrors the helper shape
/// (place → guard → restore); the helpers carry the same
/// guard (review-matched — the window inside the helper is
/// atomic from outside, uninjectable directly).
/// R18-008: the inline sites carry the identical custody
/// shape and are covered by this probe review-matched
/// (guard armed before restore, restore under guard):
/// gated_kill's stand-in loop (in-loop arm, spans the
/// post-restore reads and verdicts), both
/// pipe-publication REPLACE loops (post-loop pre-restore
/// arm, disarmed right after restore).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn steer_restore_panic_retires_placed_pauser() {
    if std::env::var("SCOPEBASE_R17006_RESTORE").is_ok() {
        steer_restore_window_probe();
        return;
    }
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("steer_restore_panic_retires_placed_pauser")
        .arg("--nocapture")
        .env("SCOPEBASE_R17006_RESTORE", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "probe must retire through the restore panic\n{stderr}"
    );
    assert!(
        stderr.contains("R17006-RESTORED retired=1"),
        "probe must cite the retirement\n{stderr}"
    );
}

/// R15-003: toolchain twin of the audit steered-replacement
/// test — the gated kill must spare a steered different-birth
/// pauser on a released number. Staging mirrors drop_guard
/// above (skips unless steerable); survival via settled
/// live-state (a zombie keeps its tick) plus the unchanged
/// replacement tick. Pre-fix the replacement dies (RED);
/// post-fix it survives (GREEN).
/// R16-011: initial + replacement pausers ride guards (a
/// failed observation or assertion would otherwise strand a
/// perpetual pauser).
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
    // R16-011: custody AT birth — the reads below panic safe.
    let mut owned_guard = SilentChildGuard::new(owned);
    let owned_tick = task_starttime_checked(owned)
        .expect("fixture stat readable")
        .expect("fixture visible");
    kill_wait_child(owned);
    owned_guard.disarm();
    std::thread::sleep(Duration::from_millis(50));
    let _nsflock = ns_last_pid_flock();
    let mut standin = -1;
    // R18-008: the placed stand-in takes custody AT placement
    // (R16-011's post-loop construction crossed the fallible
    // restore below unguarded — a restore panic strands the
    // handle-less pauser).
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
    // R18-008: placed (the contended exit returned above), so
    // the loop armed the guard — unwrap it for the disarms
    // below.
    let mut standin_guard = standin_guard.expect("placed stand-in guarded");
    let standin_tick = task_starttime_checked(owned)
        .expect("stand-in stat readable")
        .expect("stand-in visible");
    if standin_tick == owned_tick {
        kill_wait_child(owned);
        standin_guard.disarm();
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
    standin_guard.disarm();
}

/// R15-003 efficacy + decision guard (runs everywhere, no
/// steering): the gated kill must still ACT on matching
/// identity (a gate that never signals would pass the steered
/// test vacuously); wrong-tick and gone numbers skip; the
/// unreadable arm reports false without signaling (injected
/// read). Duration 51 is unique to this test.
/// R18-007: same efficacy for the tick-gated RETIRE twin
/// (acts on match, spares on wrong tick).
/// R16-011: each staged sleeper rides a guard (a failed
/// observation or assertion would otherwise strand it).
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
    // R16-011: custody AT birth — the reads below panic safe.
    let mut staged_guard = SilentChildGuard::new(spid);
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
    staged_guard.disarm();
    // Wrong tick on a live task: spared.
    let mut stranger = std::process::Command::new("/bin/sleep")
        .arg("51")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("stranger spawns");
    let xpid = stranger.id() as i32;
    // R16-011: custody AT birth — the reads below panic safe.
    let mut stranger_guard = SilentChildGuard::new(xpid);
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
    stranger_guard.disarm();
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
    // R16-011: custody AT birth — the reads below panic safe.
    let mut parked_guard = SilentChildGuard::new(ppid);
    let ptick = task_starttime_checked(ppid)
        .expect("parked stat readable")
        .expect("parked visible");
    assert!(
        !kill_tick_gated_with(ppid, ptick, |_| Err("injected".to_string())),
        "unreadable stat must report unproven (false)"
    );
    // R16-012: settled-live, not tick-only (a zombie keeps
    // its tick).
    assert_task_settled_live(ppid, ptick, 2, "unreadable arm must not signal");
    assert!(
        kill_tick_gated_with(ppid, ptick, |_| Ok(Some(ptick.wrapping_add(1)))),
        "mismatched scripted tick skips"
    );
    // R16-012: settled-live, not tick-only (a zombie keeps
    // its tick).
    assert_task_settled_live(ppid, ptick, 2, "mismatched arm must not signal");
    // SAFETY: retiring our own parked task by verified identity.
    unsafe {
        libc::kill(ppid, libc::SIGKILL);
    }
    let _ = parked.wait();
    parked_guard.disarm();
    // R18-007: the tick-gated RETIRE twin must still ACT on
    // matching identity (a gate that never signals+reaps
    // would pass the probe tails vacuously). Live owned
    // child, matching tick — killed and reaped.
    let mut owned = std::process::Command::new("/bin/sleep")
        .arg("51")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("owned spawns");
    let opid = owned.id() as i32;
    // R16-011: custody AT birth — the reads below panic safe.
    let mut owned_guard = SilentChildGuard::new(opid);
    let otick = task_starttime_checked(opid)
        .expect("owned stat readable")
        .expect("owned visible");
    assert!(
        retire_tick_gated_toolchain_child(opid, otick),
        "gated retire acts on matching identity"
    );
    assert!(
        !matches!(owned.try_wait(), Ok(None)),
        "owned child retired by the gated retire (reaped or ECHILD)"
    );
    owned_guard.disarm();
    // Wrong tick on a live task: spared with status retained.
    let mut spared = std::process::Command::new("/bin/sleep")
        .arg("51")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spared spawns");
    let dpid = spared.id() as i32;
    let mut spared_guard = SilentChildGuard::new(dpid);
    let dtick = task_starttime_checked(dpid)
        .expect("spared stat readable")
        .expect("spared visible");
    let dwrong = dtick.wrapping_add(1 << 32);
    assert!(
        retire_tick_gated_toolchain_child(dpid, dwrong),
        "gated retire skips a wrong tick"
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        task_starttime_checked(dpid),
        Ok(Some(dtick)),
        "wrong-tick task must survive the gated retire"
    );
    assert!(
        matches!(spared.try_wait(), Ok(None)),
        "wrong-tick owner status retained"
    );
    // SAFETY: retiring our own spared task by verified identity.
    unsafe {
        libc::kill(dpid, libc::SIGKILL);
    }
    let _ = spared.wait();
    spared_guard.disarm();
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

/// R17-008: expected-identity pin refuses on mismatch
/// (scripted reads — toolchain twin of the audit unit
/// test). Match pins; mismatch and gone refuse WITHOUT
/// retry (retrying would pin whatever arrives next);
/// transient errors retry then pin on recovery; persistent
/// errors exhaust to None.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn expected_pin_refuses_mismatch() {
    use std::cell::RefCell;
    // Match pins (single read).
    let calls = RefCell::new(0);
    let matched = |_: i32| -> Result<Option<u64>, String> {
        *calls.borrow_mut() += 1;
        Ok(Some(42))
    };
    assert_eq!(
        pin_expected_tick_with(1, 42, matched),
        Some(42),
        "matching tick must pin"
    );
    assert_eq!(*calls.borrow(), 1, "match pins on the first read");
    // Mismatch refuses without retry.
    let calls = RefCell::new(0);
    let mismatched = |_: i32| -> Result<Option<u64>, String> {
        *calls.borrow_mut() += 1;
        Ok(Some(43))
    };
    assert_eq!(
        pin_expected_tick_with(1, 42, mismatched),
        None,
        "mismatched tick must refuse"
    );
    assert_eq!(*calls.borrow(), 1, "mismatch must not retry");
    // Gone refuses without retry.
    let calls = RefCell::new(0);
    let gone = |_: i32| -> Result<Option<u64>, String> {
        *calls.borrow_mut() += 1;
        Ok(None)
    };
    assert_eq!(
        pin_expected_tick_with(1, 42, gone),
        None,
        "gone must refuse"
    );
    assert_eq!(*calls.borrow(), 1, "gone must not retry");
    // Transient errors retry, then pin on recovery.
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
        pin_expected_tick_with(1, 42, read),
        Some(42),
        "transient blips must heal by retry"
    );
    assert_eq!(*calls.borrow(), 3, "two blips then the pin");
    // Persistent errors exhaust to None.
    let persistent = |_: i32| -> Result<Option<u64>, String> { Err("stuck".to_string()) };
    assert_eq!(
        pin_expected_tick_with(1, 42, persistent),
        None,
        "persistent errors exhaust to None"
    );
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
                    Ok(leader) => {
                        // R17-004: the leader is gone (None) or
                        // recycled (Some(other)) — but the GROUP
                        // may retain live members (a sleeper
                        // survives its reaped shell). Silence here
                        // leaks the group with no custody report
                        // while the unpinned arm yells for live
                        // groups — inconsistent. Probe the group
                        // with the shared loudness decision: members
                        // present yields loud unresolved custody
                        // (NO signal — a stranger may have reformed
                        // the group, R14-006); ESRCH-gone stays
                        // silent.
                        // SAFETY: signal 0 probes existence only.
                        let probed = unsafe { libc::killpg(self.group, 0) };
                        // SAFETY: errno location for this thread.
                        let errno = unsafe { libc::__errno_location().read() };
                        if !unpinned_group_drop_loud(probed, errno) {
                            return; // Proven gone: silent.
                        }
                        let leader = if leader.is_none() { "gone" } else { "recycled" };
                        use std::io::Write as _;
                        let _ = writeln!(
                            std::io::stderr(),
                            "scopebase unresolved-group pgid={} tick={tick} leader={leader} members=present",
                            self.group
                        );
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
/// R17-004: single call (the old benign double is deduped —
/// repeat-call safety is covered with real asserts by the
/// R12-005 skip-twice and R13-003 spare-twice shapes).
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
    // R19003-FLAKE01: the confinement guard is declared BEFORE
    // the held files (drops AFTER them — the ceiling restores
    // only once the files are closed, so unwind-time guard
    // drops still see a full table; a block-scoped guard would
    // restore the ceiling before the staging reads and lose
    // the exhaustion entirely).
    let mut _confined = None;
    let mut _emfile_held = Vec::new();
    if std::env::var("SCOPEBASE_R15006_EMFILE").is_ok() {
        // Probe branch — fresh image, the limit dies with
        // the child.
        _confined = Some(confine_fd_table_for_exhaustion());
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
/// R16-009: outcome of a caveat-cited group retirement.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[derive(Debug, PartialEq, Eq)]
enum CaveatGroupOutcome {
    /// Killed within the proven lifetime; group ESRCH-verified dead.
    Retired,
    /// Refused: past the proven lifetime (a reformed stranger
    /// would pass an existence check) — caller skips loud.
    PastLifetime,
}

/// R16-009: retire a caveat-cited group number within the
/// sleeper's PROVEN lifetime. The caveat cites a NUMBER, not an
/// identity — existence alone cannot gate the kill (past the
/// sleeper's lifetime a reformed stranger group passes it and
/// would take SIGKILL). `spawned` is the parent's pre-spawn
/// timestamp (≈ birth, conservative: birth cannot precede it;
/// sleep cannot undershoot its clock without signals, and
/// nothing signals it), so `elapsed < lifetime` proves OUR
/// sleeper still holds the group. Past the lifetime the number
/// is refused (no existence probe can recover identity).
/// `reap_leader` reaps the leader handle WE hold (a zombie
/// leader pins the group number and ESRCH never arrives — nobody
/// else can reap OUR child); the caveat site passes a no-op
/// because the audited helper already consumed and reaped the
/// handle (R15-010 pump-through-handle).
/// Residual: premature death inside the lifetime (OOM on a 4KB
/// sleep) + exact-pgid reform — far narrower than S100 (the
/// parent knows no identity to check; the child under EMFILE
/// knows none to cite).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn retire_caveat_group_within_lifetime(
    pgid: i32,
    spawned: Instant,
    lifetime: Duration,
    reap_leader: impl FnOnce(),
) -> CaveatGroupOutcome {
    if spawned.elapsed() >= lifetime {
        return CaveatGroupOutcome::PastLifetime;
    }
    // SAFETY: signal-only to the staged group (proven ours by
    // the lifetime gate above — the sleeper cannot have exited
    // on its own clock yet, and nothing else signals it).
    unsafe {
        libc::killpg(pgid, libc::SIGKILL);
    }
    reap_leader();
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        // SAFETY: signal 0 probes existence only.
        if unsafe { libc::killpg(pgid, 0) } < 0 {
            break;
        }
        assert!(
            Instant::now() < end,
            "caveat group {pgid} must die within its lifetime"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    CaveatGroupOutcome::Retired
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn stranded_group_read_failure_retires_before_report() {
    // R16-009: pre-spawn timestamp for the caveat lifetime gate.
    let spawned = Instant::now();
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
    // R16-009: the kill is gated on the sleeper's proven 31s
    // lifetime (existence above proves the drop didn't kill — it
    // cannot authorize THIS kill past the lifetime). No-op
    // reaper: the audited helper already consumed and reaped the
    // leader handle.
    match retire_caveat_group_within_lifetime(pgid, spawned, Duration::from_secs(31), || {}) {
        CaveatGroupOutcome::Retired => {}
        CaveatGroupOutcome::PastLifetime => {
            eprintln!(
                "skip: caveat group {pgid} outlived its proven 31s lifetime (machine stalled; the 31s sleeper bounds the leak)"
            );
        }
    }
}

/// R16-009: the caveat cleanup must refuse a group past its
/// proven lifetime (existence alone would murder a reformed
/// stranger) and retire one within it. Negative arm: force the
/// original dead past a short lifetime, reform the number,
/// require PastLifetime + replacement survival (mutant: gate
/// removed → murders). Positive arm: a fresh group retires at
/// once (mutant: always-refuse → fails). No S100 skip: the gate
/// is time-only.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn caveat_cleanup_refuses_expired_lifetime() {
    // In-test steering: hold the serial + prove writability (skip
    // loud when unavailable).
    let _serial = STEER_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let last_before = match std::fs::read_to_string("/proc/sys/kernel/ns_last_pid") {
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
    fn spawn_grouped() -> std::process::Child {
        use std::os::unix::process::CommandExt as _;
        let mut command = std::process::Command::new("/bin/sleep");
        command
            .arg("31")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // SAFETY: setpgid on self pre-exec, no userspace state.
        unsafe {
            command.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        command.spawn().expect("grouped sleep spawns")
    }
    // R18-010: positive arm FIRST (a fresh group retires at
    // once — placement-independent, so a contended reform
    // below must SKIP only the negative arm, never suppress
    // this).
    let mut fresh = spawn_grouped();
    let fgroup = fresh.id() as i32;
    let mut fresh_guard = SilentChildGuard::new(fgroup);
    assert_eq!(
        retire_caveat_group_within_lifetime(
            fgroup,
            Instant::now(),
            Duration::from_secs(31),
            || {
                let _ = fresh.wait();
            }
        ),
        CaveatGroupOutcome::Retired,
        "fresh group must retire within its lifetime"
    );
    fresh_guard.disarm();
    // Negative arm: original dead past a SHORT lifetime, number
    // reformed — must refuse.
    let spawned = Instant::now();
    let mut original = spawn_grouped();
    let group = original.id() as i32;
    // SAFETY: signal-only to our own staged group.
    unsafe {
        libc::killpg(group, libc::SIGKILL);
    }
    let _ = original.wait();
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
    let mut reformed = match steer_sleep_onto(group, true) {
        Some(kid) => kid,
        None => {
            eprintln!("skip: reform contended");
            return;
        }
    };
    let mut reform_guard = SilentChildGuard::new(group);
    // Past the 100ms lifetime on the real clock (staging already
    // consumed part of it; stalls only push further past).
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(
        retire_caveat_group_within_lifetime(group, spawned, Duration::from_millis(100), || {}),
        CaveatGroupOutcome::PastLifetime,
        "expired lifetime must refuse the kill"
    );
    // SAFETY: signal 0 probes existence only.
    assert_eq!(
        unsafe { libc::killpg(group, 0) },
        0,
        "reformed group must survive refusal"
    );
    assert!(
        matches!(reformed.try_wait(), Ok(None)),
        "reformed leader must stay live"
    );
    // Loud cleanup (verified, ours).
    // SAFETY: signal-only to our own staged reformed group.
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
    // R18-010: positive arm moved before the reform attempt
    // (unconditional — see above).
}

/// R16-007: a pinned guard dropped with working reads must
/// discharge the leader (not just killpg the group) — the shell
/// zombie must not leak to process exit, and the group must be
/// proven dead. RED: the drop killpgs but never reaps (the
/// zombie leader keeps its tick and fails the gate); GREEN: the
/// drop reaps (number gone or recycled past the pin), with the
/// group ESRCH-dead as retirement evidence.
/// R17-002: the discharge oracle must not touch the reaped
/// handle (a recycled number would be status-stolen or
/// misread). Arm 1 (zombie replacement): discharged reported,
/// status retained. Arm 2 (live replacement, same oracle
/// shape): discharged reported, no flake.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn pinned_group_drop_discharges_leader() {
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
    locked_restore_hint(&last_before);
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
    // R17-002: the leader IS reaped — by the pinned drop's
    // raw waitpid, proven by the stat gate below — so no
    // handle `try_wait` follows (any would risk a recycled
    // holder's status).
    #[allow(clippy::zombie_processes)]
    let leader = stage.spawn().expect("spawn parked stage");
    let group = leader.id() as libc::pid_t;
    let ltick = task_starttime_checked(group)
        .expect("leader stat readable")
        .expect("leader visible");
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
    // R18-010: ORIGINAL verdicts run BEFORE the optional
    // retake arms (a contended placement must SKIP only its
    // arm — never suppress these). Leader discharged first:
    // a kill-without-reap drop leaves a zombie leader that
    // holds its number + tick and fails HERE — instead of
    // blocking placement below into a silent SKIP.
    assert_child_gone(group, ltick, "leader");
    // ...and the group ESRCH-dead (members settle through
    // init asynchronously — bounded await, not a sample).
    {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            // SAFETY: signal 0 probes existence only.
            let probed = unsafe { libc::killpg(group, 0) };
            if probed < 0 {
                // SAFETY: errno location for this thread.
                let errno = unsafe { libc::__errno_location().read() };
                if errno == libc::ESRCH {
                    break;
                }
            }
            assert!(
                Instant::now() < end,
                "group must be ESRCH-dead after the pinned drop"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    // R17-002 arm 1 (zombie): steer a zombie replacement onto
    // the discharged number, then run the oracle — it must
    // report discharged WITHOUT consuming the replacement's
    // status (RED: try_wait steals it).
    let mut zombie = match steer_sleep_onto(group, false) {
        Some(kid) => kid,
        None => {
            // R18-010: the SKIP branch re-proves the
            // precondition (defense in depth — a missing
            // reap blocks placement, so a skip with the
            // leader still naming the number fails loud
            // instead of suppressing the verdict).
            assert_child_gone(group, ltick, "leader-before-skip");
            eprintln!("skip: retake contended");
            return;
        }
    };
    let mut zombie_guard = SilentChildGuard::new(group);
    let retick = task_starttime_checked(group)
        .expect("replacement stat readable")
        .expect("replacement visible");
    if retick == ltick {
        let _ = zombie.kill();
        let _ = zombie.wait();
        zombie_guard.disarm();
        eprintln!("skip: same-tick retake (S100 — untestable this run)");
        return;
    }
    let _ = zombie.kill();
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if task_retired_checked(group) == Ok(true) {
            break;
        }
        assert!(Instant::now() < end, "replacement never zombied");
        std::thread::sleep(Duration::from_millis(10));
    }
    // Leader discharged: the number no longer names the leader
    // (R17-002: no handle touch — a try_wait here would steal a
    // recycled number's status or misread it; a zombie leader
    // keeps its tick and still fails this gate).
    assert_child_gone(group, ltick, "leader");
    assert!(
        matches!(zombie.try_wait(), Ok(Some(_))),
        "zombie replacement status must stay with its owner"
    );
    zombie_guard.disarm();
    // R17-002 arm 2 (live): same oracle shape, live
    // replacement — it must report discharged (RED: try_wait
    // Ok(None) misreads live as present).
    let mut live = match steer_sleep_onto(group, false) {
        Some(kid) => kid,
        None => {
            // R18-010: SKIP branch re-proves the precondition
            // (a missing reap blocks placement — fail loud,
            // never suppress).
            assert_child_gone(group, ltick, "leader-before-skip");
            eprintln!("skip: retake contended");
            return;
        }
    };
    let mut live_guard = SilentChildGuard::new(group);
    let retick = task_starttime_checked(group)
        .expect("replacement stat readable")
        .expect("replacement visible");
    if retick == ltick {
        let _ = live.kill();
        let _ = live.wait();
        live_guard.disarm();
        eprintln!("skip: same-tick retake (S100 — untestable this run)");
        return;
    }
    assert_child_gone(group, ltick, "leader-under-live-replacement");
    assert!(
        matches!(live.try_wait(), Ok(None)),
        "live replacement must survive the oracle"
    );
    let _ = live.kill();
    let _ = live.wait();
    live_guard.disarm();
    // Retirement evidence: group ESRCH-dead.
    // SAFETY: signal 0 probes existence only.
    let probed = unsafe { libc::killpg(group, 0) };
    // SAFETY: errno location for this thread.
    let errno = unsafe { libc::__errno_location().read() };
    assert_eq!(probed, -1, "group must be gone after the pinned drop");
    assert_eq!(errno, libc::ESRCH, "group probe must fail ESRCH-only");
}

/// R18-010: the omitted-leader-reap MUTANT scenario, pinned —
/// a kill-without-reap drop leaves a zombie leader holding
/// its number: the discharge verdict must FAIL (never SKIP),
/// and placement onto the held number must stay blocked (the
/// old order — steer first — skipped silently here). The
/// verdict failure is captured (not fatal): this test
/// requires the failure, then cleans up. Duration 87 is
/// unique to this test.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn omitted_leader_reap_fails_not_skips() {
    use std::os::unix::process::CommandExt as _;
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
    locked_restore_hint(&last_before);
    // Parked stage: self-grouped sh (leader LIVE) + sleepers.
    let mut stage = std::process::Command::new("/bin/sh");
    stage
        .arg("-c")
        .arg("sleep 87 & sleep 87")
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
    let ltick = task_starttime_checked(group)
        .expect("leader stat readable")
        .expect("leader visible");
    // The mutant: killpg ONLY (no reap — the drop under test
    // reaps; this omits it).
    // SAFETY: signal-only to our own staged group.
    unsafe {
        libc::killpg(group, libc::SIGKILL);
    }
    // Non-vacuity: the leader is a zombie holding its number
    // (killed, deliberately unreaped).
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if task_retired_checked(group) == Ok(true) {
            break;
        }
        assert!(Instant::now() < end, "leader never zombied (stage broken)");
        std::thread::sleep(Duration::from_millis(10));
    }
    // NEW ORDER: the discharge verdict runs FIRST and must
    // FAIL (captured — the failure is the requirement).
    let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_child_gone(group, ltick, "leader");
    }));
    assert!(
        verdict.is_err(),
        "omitted reap must fail the verdict (never skip)"
    );
    // ...and placement stays blocked (the old order skipped
    // silently at this steer).
    assert!(
        steer_sleep_onto(group, false).is_none(),
        "zombie-held number must block placement (old-order SKIP point)"
    );
    // Cleanup: reap the leader, retire the group dregs.
    let _ = leader.wait();
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        // SAFETY: signal 0 probes existence only.
        if unsafe { libc::killpg(group, 0) } < 0 {
            break;
        }
        assert!(Instant::now() < end, "group dregs must settle");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// R16-007: probe body (fresh image, SCOPEBASE_R16007_EMFILE) —
/// pin the guard with working reads, exhaust, force unwind so
/// the guard drops under EMFILE (persistent arm), restore,
/// verify-cleanup in-probe (no leak, no parent coupling), then
/// re-panic to fail the child.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn group_guard_persistent_probe() {
    use std::os::unix::process::CommandExt as _;
    // R19003-FLAKE01: confine the table before any
    // exhaustion below (fresh image — the limit dies
    // with the probe).
    let _confined = confine_fd_table_for_exhaustion();
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

/// R17-004: probe body (fresh image, SCOPEBASE_R17004_REAPED =
/// stray|gone) — pin the guard, reap the leader via wait,
/// unwind BEFORE explicit tree retirement without disarming.
/// The pinned drop sees a reaped leader: with a stray member
/// it must yell unresolved custody (never signal — the group
/// may be stranger-reformed); with the group gone it stays
/// silent. Post-drop the probe verifies no-signal (stray
/// alive) and the owner retires through the custody line.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn group_guard_reaped_leader_probe(stray: bool) {
    use std::os::unix::process::CommandExt as _;
    let script = if stray {
        "sleep 31 & echo $!; exit 3"
    } else {
        "exit 3"
    };
    let mut stage = std::process::Command::new("/bin/sh");
    stage
        .arg("-c")
        .arg(script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    // SAFETY: setpgid on self pre-exec, no userspace state.
    unsafe {
        stage.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let mut child = stage.spawn().expect("spawn exiting stage");
    let group = child.id() as libc::pid_t;
    let staged = task_starttime_checked(group)
        .expect("stage stat readable")
        .expect("stage visible");
    let guard = KillGroupOnDrop::new(group);
    assert_eq!(
        guard.tick,
        Some(staged),
        "construction must pin (stage broken otherwise)"
    );
    eprintln!("R17004-PINNED group={group} tick={staged}");
    let status = child.wait().expect("leader exit");
    assert!(!status.success());
    assert_eq!(status.code(), Some(3));
    // Learn the stray's pid (bg job — the no-signal oracle
    // needs a settled per-task verdict, not killpg-0: death
    // lands in ms, and a lingering zombie answers 0).
    let stray_pid = if stray {
        // ONE line, never to-EOF: the live stray inherits
        // the pipe, so read_to_string would block 31s.
        use std::io::BufRead as _;
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().expect("stage stdout piped"))
            .read_line(&mut line)
            .expect("stage stdout readable");
        Some(
            line.trim()
                .parse::<libc::pid_t>()
                .expect("stray pid parses"),
        )
    } else {
        None
    };
    let fired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = guard;
        panic!("r17004 injected post-wait failure");
    }));
    assert!(fired.is_err(), "injection must unwind");
    eprintln!("R17004-DROPPED");
    if let Some(stray_pid) = stray_pid {
        // Stranger protection: the drop must have sent NO
        // signal — the orphaned sleeper stays live with an
        // empty pending mask across the full settle window.
        assert!(
            settle_spared(stray_pid),
            "stray {stray_pid} must survive the drop (no signal)"
        );
        eprintln!("R17004-SPARED spared=1");
    }
    // Owner retires through the custody line (verified
    // cleanup — the loud arm retires nothing itself).
    retire_probe_tree(&mut child, staged);
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        // SAFETY: signal 0 probes existence only.
        if unsafe { libc::killpg(group, 0) } < 0 {
            break;
        }
        assert!(
            Instant::now() < end,
            "cleanup group {group} must die post-drop"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("r17004 injected post-wait failure (verified)");
}

/// R18-011: the stray parent gate, extracted so the
/// adopted-cleanup regression can run it against failure
/// output and require rejection (a cleanup-stage failure
/// prints every early marker — nonzero exit, the caught
/// injection's hook output, DROPPED, SPARED, the custody
/// line — so the gate MUST require the terminal verified
/// message, which prints only after the disappearance loop
/// proves discharge).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn assert_r17004_stray_gate(stderr: &str, status: &std::process::ExitStatus) {
    assert!(
        !status.success(),
        "child must fail at the injected staging panic\n{stderr}"
    );
    assert!(
        stderr.contains("r17004 injected"),
        "panic must name the injection\n{stderr}"
    );
    assert!(
        stderr.contains("r17004 injected post-wait failure (verified)"),
        "terminal verified proof must land (cleanup failure prints every early marker)\n{stderr}"
    );
    assert!(
        stderr.contains("R17004-DROPPED"),
        "unwind must pass through the guard\n{stderr}"
    );
    assert!(
        stderr.contains("R17004-SPARED spared=1"),
        "stray must survive the drop (no signal)\n{stderr}"
    );
    let mut pinned = None;
    let mut cited = None;
    let mut words = String::new();
    for line in stderr.lines() {
        if let Some(rest) = line.strip_prefix("R17004-PINNED ") {
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
            words = rest.to_owned();
        }
    }
    let pinned = pinned.expect("probe must print the pinned identity");
    let cited = cited.expect("drop must print unresolved-group custody");
    assert_eq!(cited, pinned, "custody line must cite the pinned identity");
    assert!(
        words.contains("leader=gone"),
        "custody line must name the reaped leader\n{stderr}"
    );
    assert!(
        words.contains("members=present"),
        "custody line must name the live members\n{stderr}"
    );
}

/// R17-004: a pinned guard dropped after its leader was
/// reaped, with the group retaining a live member, must
/// report explicit unresolved group custody (never silent —
/// the unpinned arm yells for live groups) and must send NO
/// signal (a stranger may have reformed the group, R14-006).
/// RED: the Ok arm returns silently; GREEN: the loud line
/// cites the pinned identity with leader=gone members=present.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn group_guard_reaped_leader_reports_live_members() {
    if std::env::var("SCOPEBASE_R17004_REAPED").as_deref() == Ok("stray") {
        group_guard_reaped_leader_probe(true);
        return;
    }
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("group_guard_reaped_leader_reports_live_members")
        .arg("--nocapture")
        .env("SCOPEBASE_R17004_REAPED", "stray")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_r17004_stray_gate(&stderr, &out.status);
}

/// R18-011: forced adoption must fail the parent gate — the
/// probe marks itself subreaper, so the stray reparents to
/// the probe instead of init; the probe kills it but never
/// reaps it, the probe-held zombie keeps killpg-0 alive, and
/// the cleanup loop fires at 5s. Every early marker still
/// lands (nonzero exit, the caught injection's hook output,
/// DROPPED, SPARED, custody line — the old gate passes this
/// output) but the terminal verified proof cannot print
/// (discharge unproven) and the gate MUST reject it.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn group_guard_adopted_cleanup_fails_parent_gate() {
    if std::env::var("SCOPEBASE_R17004_REAPED").as_deref() == Ok("adopt") {
        // SAFETY: marks only this probe process a subreaper;
        // no userspace state. Loud if refused (the mode is
        // invalid without adoption).
        let ret = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1 as libc::c_ulong, 0, 0, 0) };
        assert_eq!(ret, 0, "probe must become subreaper");
        group_guard_reaped_leader_probe(true);
        return;
    }
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("group_guard_adopted_cleanup_fails_parent_gate")
        .arg("--nocapture")
        .env("SCOPEBASE_R17004_REAPED", "adopt")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("probe child runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    // The failure mode is real: every early marker lands.
    assert!(
        !out.status.success(),
        "adopted probe must fail cleanup\n{stderr}"
    );
    assert!(
        stderr.contains("r17004 injected"),
        "caught hook output must satisfy the old substring\n{stderr}"
    );
    assert!(
        stderr.contains("R17004-DROPPED"),
        "unwind must pass through the guard\n{stderr}"
    );
    assert!(
        stderr.contains("R17004-SPARED spared=1"),
        "stray must survive the drop (no signal)\n{stderr}"
    );
    assert!(
        stderr.contains("scopebase unresolved-group"),
        "drop must yell custody\n{stderr}"
    );
    assert!(
        !stderr.contains("(verified)"),
        "terminal proof must be absent (discharge unproven)\n{stderr}"
    );
    // ...and the gate rejects exactly this output.
    let fired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_r17004_stray_gate(&stderr, &out.status);
    }));
    assert!(fired.is_err(), "gate must reject cleanup-failed output");
}

/// R17-004: ESRCH twin — a pinned guard dropped after its
/// leader was reaped, with the group fully gone, stays
/// silent (guards the yell against always-loud mutants).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
#[test]
fn group_guard_reaped_leader_silent_when_group_gone() {
    if std::env::var("SCOPEBASE_R17004_REAPED").as_deref() == Ok("gone") {
        group_guard_reaped_leader_probe(false);
        return;
    }
    let exe = std::env::current_exe().expect("own test binary");
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("group_guard_reaped_leader_silent_when_group_gone")
        .arg("--nocapture")
        .env("SCOPEBASE_R17004_REAPED", "gone")
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
        stderr.contains("R17004-DROPPED"),
        "unwind must pass through the guard\n{stderr}"
    );
    // R18-011: the terminal verified proof (prints only after
    // the disappearance loop proves discharge — without this
    // the parent accepts cleanup failure, which prints every
    // other marker above).
    assert!(
        stderr.contains("r17004 injected post-wait failure (verified)"),
        "terminal verified proof must land\n{stderr}"
    );
    assert!(
        !stderr.contains("scopebase unresolved-group"),
        "drop must stay silent on a gone group\n{stderr}"
    );
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
    // R19003-FLAKE01: confine the table before any
    // exhaustion below (fresh image — the limit dies
    // with the probe).
    let _confined = confine_fd_table_for_exhaustion();
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
