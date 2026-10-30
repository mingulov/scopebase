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
    if !steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
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
        if !steer_next_pid(stray_pid) {
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
    let _ = std::fs::write(last_path, &last_before);
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
    if !steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
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
        if !steer_next_pid(stray_pid) {
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
    let _ = std::fs::write(last_path, &last_before);
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
    if !steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
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
    let live_guard = SilentChildGuard::new(live);
    let live_tick = task_starttime_checked(live)
        .expect("pauser stat readable")
        .expect("pauser live");
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
    // R13-008: custody for the unreaped zombie — its status
    // must discharge on every exit, not just the tail cleanup.
    let zombie_guard = SilentChildGuard::new(zombie);
    let zombie_tick = task_starttime_checked(zombie)
        .expect("zombie stat readable")
        .expect("zombie present");
    // Recycled: kill an owned pauser, force a tick advance, retake
    // its number with a steered squatter (R12-005: cross-process
    // placement lock; a racing sibling spawn may steal it —
    // retried, then honestly skipped).
    let victim = fork_pauser();
    let victim_tick = task_starttime_checked(victim)
        .expect("victim stat readable")
        .expect("victim live");
    kill_wait_child(victim);
    std::thread::sleep(Duration::from_millis(50));
    let _nsflock = ns_last_pid_flock();
    let mut squatter = -1;
    // R13-008: forced placement failure skips the loop (the
    // contended exit below runs with staged fixtures).
    if forced.as_deref() != Some("placement-failure") {
        for _ in 0..100 {
            if !steer_next_pid(victim) {
                break;
            }
            let kid = fork_pauser();
            if kid == victim {
                squatter = kid;
                break;
            }
            kill_wait_child(kid);
        }
    }
    drop(_nsflock);
    let _ = std::fs::write(last_path, &last_before);
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
    let now = task_starttime_checked(victim)
        .expect("squatter stat readable")
        .expect("squatter live");
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
    // Explicit loud cleanup before every assert (the guards drop
    // silent at the end — nothing left for them on this path).
    kill_wait_child(squatter);
    kill_wait_child(live);
    // SAFETY: our own zombie child.
    let mut status = 0;
    let got = unsafe { libc::waitpid(zombie, &mut status, 0) };
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
    assert!(swept.is_empty(), "unrelated task must be spared, got: {swept:?}");
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
/// loops never nest). Lock order everywhere: STEER_SERIAL
/// first (test top), this guard second (loop top).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct NsLastPidFlock {
    fd: libc::c_int,
}

/// R12-005: take the cross-process placement lock (blocking;
/// held for milliseconds across one steer-then-spawn
/// placement loop).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn ns_last_pid_flock() -> NsLastPidFlock {
    use std::os::unix::ffi::OsStrExt as _;
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
    NsLastPidFlock { fd }
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
/// panics — a panicking Drop during unwinding aborts). Kill, then
/// bounded WNOHANG reap; every error ignored. Numeric kill+wait
/// is exact here: these are OUR unreaped children, whose numbers
/// cannot recycle under us. The loud paths retire explicitly
/// (kill_wait_child / asserted waits) first, so a guard firing
/// means an exit that skipped explicit cleanup.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn retire_child_silent(pid: i32) {
    // SAFETY: signal-only to an owned child; errors ignored.
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

/// R13-008: Drop guard retiring an owned fixture child on every
/// exit (early return or panic). Covers pausers (retire) and
/// zombies (discharge status — the kill also reaches a child hung
/// before its immediate exit; an already-exited zombie answers
/// ESRCH and is simply reaped).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct SilentChildGuard {
    pid: i32,
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl SilentChildGuard {
    fn new(pid: i32) -> Self {
        SilentChildGuard { pid }
    }
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl Drop for SilentChildGuard {
    fn drop(&mut self) {
        retire_child_silent(self.pid);
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
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn steer_next_pid(want: i32) -> bool {
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
    if !steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
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
            if !steer_next_pid(p_pid) {
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
            let _ = steer_next_pid(num + 1);
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
    if !steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
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
            if !steer_next_pid(p_pid) {
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
    let _ = std::fs::write(last_path, &last_before);
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
    if !steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
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
        if !steer_next_pid(p_pid) {
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
        owner = Some(cand);
        break;
    }
    let mut owner = match owner {
        Some(owner) => owner,
        None => panic!("steering broken: P={p_pid} free but unretaken"),
    };
    // Different birth (else the zombie could be a P remnant —
    // vacuous), then zombie-state proof with the owner UNTOUCHED
    // (a reap here would be ours, not the settler's).
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
            let _ = steer_next_pid(num + 1);
            restored = std::fs::read_to_string(last_path)
                .map(|text| text.trim() == last_before)
                .unwrap_or(false);
        }
    }
    assert!(restored, "allocator hint must restore after steering");
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
    if !steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
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
        if !steer_next_pid(holder) {
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
    let _ = std::fs::write(last_path, &last_before);
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
    if !steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
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
            if !steer_next_pid(id) {
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
    let _ = std::fs::write(last_path, &last_before);
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
    if !steer_next_pid(last_before.parse::<i32>().unwrap_or(0) + 1) {
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
            if !steer_next_pid(id) {
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
    let _ = std::fs::write(last_path, &last_before);
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
    struct KillOnDrop(i32);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            kill_wait_child(self.0);
        }
    }
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
    let _ours_guard = KillOnDrop(ours_id);
    let ours_tick = task_starttime_checked(ours_id)
        .expect("ours stat readable")
        .expect("ours visible");
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
    let _plain_guard = KillOnDrop(plain_id);
    let plain_tick = task_starttime_checked(plain_id)
        .expect("plain stat readable")
        .expect("plain visible");
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
    assert!(
        probe_group_kill_allowed(ours_id, ours_tick),
        "freed number must allow the group signal"
    );
    kill_wait_child(plain_id);
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
/// assertion by 26s. Drop-after-success is a harmless nop
/// (kill on an empty group is ESRCH).
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
struct KillGroupOnDrop {
    group: libc::pid_t,
}

#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
impl Drop for KillGroupOnDrop {
    fn drop(&mut self) {
        // SAFETY: signal-only to the test's own group;
        // best-effort (failure paths must not panic).
        unsafe {
            libc::killpg(self.group, libc::SIGKILL);
        }
    }
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
    // R12-005: pin before any wait (retirement identity gate).
    let staged = task_starttime_checked(child.id() as i32)
        .expect("stage stat readable")
        .expect("stage visible");
    let status = child.wait().expect("stage exit");
    assert!(!status.success());
    assert_eq!(status.code(), Some(3));
    let group = child.id() as libc::pid_t;
    // IR1: the 31s sleeper dies with the test on every path
    // (failed asserts unwind through this guard).
    let _guard = KillGroupOnDrop { group };
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
            return;
        }
        assert!(
            Instant::now() < end,
            "stranded group {group} survived retirement"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// R11-016(b2): retire a probe's whole process group plus
/// the probe itself, then reap. The probe's pgid is its pid
/// (every probe groups itself on entry), so stranded
/// group-mates (a live holder) die with it. Best-effort and
/// idempotent: ESRCH/ECHILD mean already gone, never a hang.
/// Used on timeout AND on failure exit (a failed probe may
/// strand its group) — always before reporting failure.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
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
/// R13-003: group-signal decision for `retire_probe_tree`,
/// extracted for direct unit coverage (a mid-call recycle is
/// unplantable without steering, but every decision state is
/// plantable as a current state). True while the number names
/// our probe, names nothing (freed or unreadable — our
/// strays alone in the group), or names a live foreigner
/// OUTSIDE the group (getpgid proves the signal cannot reach
/// it). False only for a live foreign SELF-GROUPED holder.
#[cfg(all(target_os = "linux", feature = "linux-fixtures"))]
fn probe_group_kill_allowed(id: i32, expected: u64) -> bool {
    // None covers freed AND unreadable (unproven, never
    // foreign — the group signal still retires our strays).
    let holder_tick = task_starttime_checked(id).ok().flatten();
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
