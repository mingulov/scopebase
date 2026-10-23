// SPDX-License-Identifier: Apache-2.0
//! TC02: bounded nested-build helper. One pinned tool, explicit bounds.
//!
//! Donor slices (p11scope-ws w000 @ 6f97aa47, frozen tree):
//! `evidence/llvm-toolchain-review-20260922/kernel-oracle/prepare.py`
//! (lines 122-126: argument-array subprocess, `timeout=20`, piped
//! capture with per-case logs; line 114 is core-dump `setrlimit`, not
//! ported) and `evidence/llvm-toolchain-review-20260922/
//! kernel-oracle/run.py` (lines 56-57, 63-66: whole-matrix wall-clock
//! budget, bytecode hash re-verified before execution, `timeout=10`).
//! Whole donor files are user-authored (TC01). ADAPT to Rust with typed
//! bound errors; no upstream lines copied. Grant: OWNER-2026-10-23.
//!
//! [`run_pinned`] resolves `tool_id` in the [`CompilerClosure`][crate::
//! toolchain::CompilerClosure] first and refuses unknown ids before any
//! spawn. The child runs with an argument array (never a shell string),
//! an explicit environment plus forced `CARGO_NET_OFFLINE=true`, and
//! byte/time/work caps. Overruns abort with [`ErrorKind::LimitExceeded`];
//! the child is killed, never awaited past its bound.
use scopebase_bpf::{ErrorKind, OperationError, Stage};
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::object::invalid;
use crate::toolchain::CompilerClosure;

/// Explicit byte/time/work bounds for one nested tool run.
///
/// All fields are independent caps with no unlimited sentinel. A zero byte
/// cap admits only a silent stream; a zero arg/env cap admits only an empty
/// list. Any representable value is valid configuration; exceeding a cap at
/// admission or during the run aborts with [`ErrorKind::LimitExceeded`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NestedBounds {
    /// Maximum captured stdout bytes.
    pub max_stdout_bytes: usize,
    /// Maximum captured stderr bytes.
    pub max_stderr_bytes: usize,
    /// Maximum wall-clock milliseconds from spawn to settlement.
    pub timeout_ms: u64,
    /// Maximum argument entries (excluding the tool path).
    pub max_args: usize,
    /// Maximum explicit environment entries.
    pub max_env: usize,
}

/// Settled output of a nested tool that exited with status zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedOutput {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl NestedOutput {
    /// Exit status code. Always `Some(0)`; any other exit is an error.
    pub fn code(&self) -> Option<i32> {
        self.code
    }
    /// Whether the tool exited zero. Always true for a returned value.
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
    /// Captured stdout bytes.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }
    /// Captured stderr bytes.
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

#[derive(Debug)]
struct Detail(&'static str);

impl std::fmt::Display for Detail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tc02 nested build: {}", self.0)
    }
}

impl std::error::Error for Detail {}

fn backend(error: std::io::Error, stage: Stage) -> OperationError {
    OperationError::new(
        ErrorKind::Backend,
        stage,
        error.raw_os_error(),
        Some(Box::new(Detail("tool backend failure"))),
    )
}

fn bound_exceeded(message: &'static str, stage: Stage) -> OperationError {
    OperationError::new(
        ErrorKind::LimitExceeded,
        stage,
        None,
        Some(Box::new(Detail(message))),
    )
}

pub(crate) fn has_nul(value: &OsStr) -> bool {
    // NUL is ASCII, so lossy conversion is exact for this check on any
    // platform while other non-UTF8 bytes pass through untouched.
    value.to_string_lossy().contains('\0')
}

pub(crate) fn is_proxy_key(key: &OsStr) -> bool {
    key.to_string_lossy().to_ascii_lowercase().contains("proxy")
}

/// Execute one closure-pinned tool at an offline local path under bounds.
///
/// Admission order is fixed and side-effect free: closure lookup, arg/env
/// work caps, request shape (NUL, `=` in env keys, proxy/offline env),
/// then spawn. `tool_path` is caller-resolved offline bytes; the closure
/// proves the pin, never a download location. The child inherits the
/// working directory but no environment: only `env` plus forced
/// `CARGO_NET_OFFLINE=true` is present.
///
/// Errors: unknown id is `InvalidInput/Admission`; arg/env count overruns
/// are `LimitExceeded/Admission` with the attempted count; malformed or
/// network-bearing requests are `InvalidInput/Admission`; a missing
/// executable is `InvalidInput/Execute`; other spawn failures, nonzero
/// exits, signals and output-reader failures are `Backend/Execute`;
/// stdout/stderr overruns are `LimitExceeded/Execute` with the observed
/// byte count (stdout takes precedence when both overrun, and overrun
/// reports take precedence over reader failures); wall-clock expiry is
/// `LimitExceeded/Execute` with no byte count. Overrun or expired
/// children are killed before return.
pub fn run_pinned(
    closure: &CompilerClosure,
    tool_id: &str,
    tool_path: &Path,
    args: &[OsString],
    env: &[(OsString, OsString)],
    bounds: &NestedBounds,
) -> Result<NestedOutput, OperationError> {
    if closure.find(tool_id).is_none() {
        return Err(invalid("tool id not pinned in closure"));
    }
    if args.len() > bounds.max_args {
        return Err(
            bound_exceeded("argument count over bound", Stage::Admission)
                .with_required_size(args.len()),
        );
    }
    if env.len() > bounds.max_env {
        return Err(
            bound_exceeded("environment count over bound", Stage::Admission)
                .with_required_size(env.len()),
        );
    }
    if tool_path.as_os_str().is_empty() || has_nul(tool_path.as_os_str()) {
        return Err(invalid("tool path"));
    }
    if args.iter().any(|arg| has_nul(arg)) {
        return Err(invalid("argument bytes"));
    }
    for (key, value) in env {
        if key.is_empty() || has_nul(key) || has_nul(value) {
            return Err(invalid("environment bytes"));
        }
        if key.to_string_lossy().contains('=') {
            return Err(invalid("environment key"));
        }
        if is_proxy_key(key) {
            return Err(invalid("network proxy environment refused"));
        }
        if key == "CARGO_NET_OFFLINE" && value != "true" {
            return Err(invalid("offline environment refused"));
        }
    }

    let mut child = std::process::Command::new(tool_path)
        .args(args)
        .env_clear()
        .envs(env.iter().map(|(key, value)| (key, value)))
        .env("CARGO_NET_OFFLINE", "true")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                OperationError::new(
                    ErrorKind::InvalidInput,
                    Stage::Execute,
                    error.raw_os_error(),
                    Some(Box::new(Detail("tool executable missing"))),
                )
            } else {
                backend(error, Stage::Execute)
            }
        })?;

    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stdout_hit = Arc::new(AtomicBool::new(false));
    let stderr_hit = Arc::new(AtomicBool::new(false));
    let stdout_reader = spawn_capped_reader(stdout, bounds.max_stdout_bytes, stdout_hit.clone());
    let stderr_reader = spawn_capped_reader(stderr, bounds.max_stderr_bytes, stderr_hit.clone());
    let deadline = Instant::now() + Duration::from_millis(bounds.timeout_ms);

    loop {
        if stdout_hit.load(Ordering::SeqCst) || stderr_hit.load(Ordering::SeqCst) {
            kill_and_wait(&mut child)?;
            let (out, err) = join_readers(stdout_reader, stderr_reader)?;
            return Err(capped_error(&out, &err));
        }
        match child
            .try_wait()
            .map_err(|error| backend(error, Stage::Execute))?
        {
            Some(status) => {
                let (out, err) = join_readers(stdout_reader, stderr_reader)?;
                if out.overrun || err.overrun {
                    return Err(capped_error(&out, &err));
                }
                if out.read_error || err.read_error {
                    return Err(reader_failed());
                }
                if status.success() {
                    return Ok(NestedOutput {
                        code: status.code(),
                        stdout: out.data,
                        stderr: err.data,
                    });
                }
                return Err(OperationError::new(
                    ErrorKind::Backend,
                    Stage::Execute,
                    None,
                    Some(Box::new(Detail("tool exited nonzero or signaled"))),
                ));
            }
            None => {
                if Instant::now() >= deadline {
                    kill_and_wait(&mut child)?;
                    let (out, err) = join_readers(stdout_reader, stderr_reader)?;
                    if out.overrun || err.overrun {
                        return Err(capped_error(&out, &err));
                    }
                    if out.read_error || err.read_error {
                        return Err(reader_failed());
                    }
                    return Err(bound_exceeded("wall-clock timeout", Stage::Execute));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

pub(crate) struct CappedOutput {
    pub data: Vec<u8>,
    pub observed: usize,
    pub overrun: bool,
    pub read_error: bool,
}

pub(crate) fn spawn_capped_reader<R: Read + Send + 'static>(
    mut stream: R,
    cap: usize,
    hit: Arc<AtomicBool>,
) -> std::thread::JoinHandle<CappedOutput> {
    std::thread::spawn(move || {
        let mut data = Vec::new();
        let mut observed = 0usize;
        let mut chunk = [0u8; 8192];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => {
                    return CappedOutput {
                        data,
                        observed,
                        overrun: false,
                        read_error: false,
                    };
                }
                Ok(count) => {
                    observed += count;
                    if observed > cap {
                        let room = cap.saturating_add(1).saturating_sub(data.len());
                        data.extend_from_slice(&chunk[..count.min(room)]);
                        hit.store(true, Ordering::SeqCst);
                        return CappedOutput {
                            data,
                            observed,
                            overrun: true,
                            read_error: false,
                        };
                    }
                    data.extend_from_slice(&chunk[..count]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    return CappedOutput {
                        data,
                        observed,
                        overrun: false,
                        read_error: true,
                    };
                }
            }
        }
    })
}

pub(crate) fn join_readers(
    stdout: std::thread::JoinHandle<CappedOutput>,
    stderr: std::thread::JoinHandle<CappedOutput>,
) -> Result<(CappedOutput, CappedOutput), OperationError> {
    let failed = || {
        OperationError::new(
            ErrorKind::Backend,
            Stage::Execute,
            None,
            Some(Box::new(Detail("output reader failed"))),
        )
    };
    Ok((
        stdout.join().map_err(|_| failed())?,
        stderr.join().map_err(|_| failed())?,
    ))
}

pub(crate) fn kill_and_wait(child: &mut Child) -> Result<(), OperationError> {
    let _ = child.kill();
    child
        .wait()
        .map_err(|error| backend(error, Stage::Execute))?;
    Ok(())
}

/// Output-reader failure: a mid-stream read failed, so the partial bytes
/// are untrustworthy and never returned as success.
fn reader_failed() -> OperationError {
    OperationError::new(
        ErrorKind::Backend,
        Stage::Execute,
        None,
        Some(Box::new(Detail("output reader failed"))),
    )
}

/// Byte-overrun error with the observed count. Stdout takes precedence
/// when both streams overrun so the report is deterministic.
fn capped_error(stdout: &CappedOutput, stderr: &CappedOutput) -> OperationError {
    if stdout.overrun {
        bound_exceeded("stdout over bound", Stage::Execute).with_required_size(stdout.observed)
    } else {
        bound_exceeded("stderr over bound", Stage::Execute).with_required_size(stderr.observed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scripted reader: yields one partial chunk, then a hard read error.
    struct FailAfterPartial {
        sent: bool,
    }

    impl Read for FailAfterPartial {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.sent {
                self.sent = true;
                let chunk = b"partial";
                buf[..chunk.len()].copy_from_slice(chunk);
                return Ok(chunk.len());
            }
            Err(std::io::Error::other("scripted read failure"))
        }
    }

    #[test]
    fn mid_stream_read_error_is_not_silent_eof() {
        let hit = Arc::new(AtomicBool::new(false));
        let out = spawn_capped_reader(FailAfterPartial { sent: false }, 1 << 20, hit)
            .join()
            .unwrap();
        assert_eq!(out.data, b"partial");
        assert!(!out.overrun);
        assert!(
            out.read_error,
            "a mid-stream read failure must be reported, not treated as EOF"
        );
    }
}
