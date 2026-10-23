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
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
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
struct Detail(String);

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
        Some(Box::new(Detail("tool backend failure".to_string()))),
    )
}

fn bound_exceeded(message: impl Into<String>, stage: Stage) -> OperationError {
    OperationError::new(
        ErrorKind::LimitExceeded,
        stage,
        None,
        Some(Box::new(Detail(message.into()))),
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
    run_pinned_with_builders(
        closure,
        tool_id,
        tool_path,
        args,
        env,
        bounds,
        std::thread::Builder::new().name("invoke-stdout".to_string()),
        std::thread::Builder::new().name("invoke-stderr".to_string()),
    )
}

/// S33: test-only entry point with injectable reader-thread builders,
/// so the second-reader-failure branch is forced (a denied builder),
/// not wished for. Production callers use [`run_pinned`].
#[doc(hidden)]
// Eight args: run_pinned's six plus the two injected builders; a
// struct would obscure the one-to-one delegation.
#[allow(clippy::too_many_arguments)]
pub fn run_pinned_with_builders(
    closure: &CompilerClosure,
    tool_id: &str,
    tool_path: &Path,
    args: &[OsString],
    env: &[(OsString, OsString)],
    bounds: &NestedBounds,
    stdout_builder: std::thread::Builder,
    stderr_builder: std::thread::Builder,
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

    let mut command = std::process::Command::new(tool_path);
    command
        .args(args)
        .env_clear()
        .envs(env.iter().map(|(key, value)| (key, value)))
        .env("CARGO_NET_OFFLINE", "true")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // S33: the tool leads a fresh process group, so retirement can
    // SIGKILL forked descendants holding pipes — not just the child.
    // SAFETY: setpgid is async-signal-safe; the parent confirms the
    // group below, so a failure here is harmless.
    #[cfg(unix)]
    unsafe {
        command.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            OperationError::new(
                ErrorKind::InvalidInput,
                Stage::Execute,
                error.raw_os_error(),
                Some(Box::new(Detail("tool executable missing".to_string()))),
            )
        } else {
            backend(error, Stage::Execute)
        }
    })?;

    // S33: the tool leads a fresh process group (its own pid), so
    // retirement reaches forked descendants holding pipes. The
    // parent side of the standard double-call runs here; the child
    // side ran in pre_exec.
    claim_tool_group(child.id());
    let group = Some(child.id());
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stdout_hit = Arc::new(AtomicBool::new(false));
    let stderr_hit = Arc::new(AtomicBool::new(false));
    // R06: reader-thread spawn is fallible. A denied spawn kills
    // the already-spawned child (and joins a half-started sibling
    // reader) instead of panicking; the error is Backend/Execute
    // like every other output-reader failure.
    let stdout_reader = match spawn_capped_reader_on(
        stdout_builder,
        stdout,
        bounds.max_stdout_bytes,
        stdout_hit.clone(),
    ) {
        Ok(handle) => handle,
        Err(error) => {
            kill_tool_tree(group, &mut child);
            return Err(backend(error, Stage::Execute));
        }
    };
    let stderr_reader = match spawn_capped_reader_on(
        stderr_builder,
        stderr,
        bounds.max_stderr_bytes,
        stderr_hit.clone(),
    ) {
        Ok(handle) => handle,
        Err(error) => {
            // S33: the sibling reader settles bounded (a silent
            // descendant holding stdout must not hang cleanup), and
            // an unsettled reader joins the spawn error in the
            // report instead of vanishing with a bare `let _`.
            kill_tool_tree(group, &mut child);
            let spawn = backend(error, Stage::Execute);
            match settle_one(stdout_reader, "stdout") {
                Ok(_) => return Err(spawn),
                Err(unsettled) => {
                    return Err(OperationError::new(
                        ErrorKind::Backend,
                        Stage::Execute,
                        spawn.raw_os_error(),
                        Some(Box::new(Detail(format!(
                            "reader spawn failed ({spawn}); {unsettled}"
                        )))),
                    ));
                }
            }
        }
    };
    // R05 sweep note: this addition cannot overflow. `timeout_ms` is a
    // u64 of MILLISECONDS: even u64::MAX is ~584M years, and now()+that
    // stays far inside the Instant range (verified: checked_add at MAX
    // returns Some). Only raw `Duration` params (audit/target sites)
    // can carry an unrepresentable span.
    let deadline = Instant::now() + Duration::from_millis(bounds.timeout_ms);

    loop {
        if stdout_hit.load(Ordering::SeqCst) || stderr_hit.load(Ordering::SeqCst) {
            kill_tool_group(group);
            kill_and_wait(&mut child)?;
            let (out, err) = settle_pair(stdout_reader, stderr_reader)?;
            return Err(capped_error(&out, &err));
        }
        match child
            .try_wait()
            .map_err(|error| backend(error, Stage::Execute))?
        {
            Some(status) => {
                // S33: the child is reaped but its forked descendants
                // may hold the pipes; settle bounded either way.
                kill_tool_group(group);
                let (out, err) = settle_pair(stdout_reader, stderr_reader)?;
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
                    Some(Box::new(Detail(
                        "tool exited nonzero or signaled".to_string(),
                    ))),
                ));
            }
            None => {
                if Instant::now() >= deadline {
                    kill_tool_group(group);
                    kill_and_wait(&mut child)?;
                    let (out, err) = settle_pair(stdout_reader, stderr_reader)?;
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

/// Default-named wrapper; production passes explicit builders to
/// the seam below, so this exists only for the unit tests.
#[cfg(test)]
pub(crate) fn spawn_capped_reader<R: Read + Send + 'static>(
    stream: R,
    cap: usize,
    hit: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<CappedOutput>> {
    spawn_capped_reader_on(
        std::thread::Builder::new().name("invoke-reader".to_string()),
        stream,
        cap,
        hit,
    )
}

/// R06 seam: the caller supplies the thread builder, so tests can
/// force a genuine spawn failure (e.g. a zero stack size) without
/// touching process limits. Production passes named builders.
pub(crate) fn spawn_capped_reader_on<R: Read + Send + 'static>(
    builder: std::thread::Builder,
    mut stream: R,
    cap: usize,
    hit: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<CappedOutput>> {
    builder.spawn(move || {
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

/// S33: bound on output-reader settlement after the tool tree is
/// killed. SIGKILLed pipes EOF near-instantly; only a daemonized
/// escapee beyond the process group can burn this, and then the
/// reader detaches with an explicit unsettled error instead of
/// hanging the caller.
const SETTLE_BOUND: Duration = Duration::from_secs(10);

/// S33: parent side of the tool-group double-call. The child called
/// setpgid(0, 0) in pre_exec; this call wins the race when the child
/// has not run yet. EACCES means the child already exec'd, so its
/// own call established the group; ESRCH means it already exited and
/// nothing will ever need the group. Only EINTR retries.
fn claim_tool_group(child: u32) {
    #[cfg(not(unix))]
    let _ = child;
    #[cfg(unix)]
    loop {
        // SAFETY: setpgid on an owned unreaped child pid.
        let result = unsafe { libc::setpgid(child as libc::pid_t, child as libc::pid_t) };
        if result == 0 {
            return;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return;
    }
}

/// S33: SIGKILL the tool process group: the child plus any forked
/// descendants holding pipes. Idempotent (ESRCH is fine); not
/// available off unix, where settlement still bounds the wait.
fn kill_tool_group(group: Option<u32>) {
    #[cfg(unix)]
    if let Some(group) = group {
        // SAFETY: signal our own fresh tool group.
        unsafe {
            libc::killpg(group as libc::pid_t, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    let _ = group;
}

/// S33: retire the whole tool tree, ignoring errors: the group
/// first (descendants), then the child handle itself.
fn kill_tool_tree(group: Option<u32>, child: &mut Child) {
    kill_tool_group(group);
    let _ = kill_and_wait(child);
}

/// S33: join one output reader within the settlement bound. A reader
/// still blocked past the bound (a daemonized descendant beyond the
/// SIGKILLed group) is detached — its handle dropped without join —
/// and reported as unsettled with its stream name, so unresolved
/// output ownership is explicit, never a silent hang or a silently
/// abandoned thread.
fn settle_one(
    handle: std::thread::JoinHandle<CappedOutput>,
    name: &'static str,
) -> Result<CappedOutput, OperationError> {
    settle_before(handle, name, Instant::now() + SETTLE_BOUND)
}

/// S33: join one reader before a deadline. Shared by the bound-taking
/// single/pair wrappers, so the detach path is identical everywhere.
fn settle_before(
    handle: std::thread::JoinHandle<CappedOutput>,
    name: &'static str,
    end: Instant,
) -> Result<CappedOutput, OperationError> {
    loop {
        if handle.is_finished() {
            return handle.join().map_err(|_| reader_failed());
        }
        if Instant::now() >= end {
            drop(handle);
            return Err(unsettled(name));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// S33: settle both readers under one bound.
fn settle_pair(
    stdout: std::thread::JoinHandle<CappedOutput>,
    stderr: std::thread::JoinHandle<CappedOutput>,
) -> Result<(CappedOutput, CappedOutput), OperationError> {
    // One shared deadline: a second stuck reader must not double the
    // bound. Poll-then-join keeps the pairing with `join_readers`'
    // stdout-first error precedence.
    let end = Instant::now() + SETTLE_BOUND;
    let out = settle_before(stdout, "stdout", end)?;
    let err = settle_before(stderr, "stderr", end)?;
    Ok((out, err))
}

/// S33: unsettled-reader error. Partial bytes already collected are
/// untrustworthy (truncated by detachment) and never returned.
fn unsettled(name: &'static str) -> OperationError {
    OperationError::new(
        ErrorKind::Backend,
        Stage::Execute,
        None,
        Some(Box::new(Detail(format!(
            "output reader unsettled: {name} still blocked after tool kill"
        )))),
    )
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
            Some(Box::new(Detail("output reader failed".to_string()))),
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
        Some(Box::new(Detail("output reader failed".to_string()))),
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
            .expect("reader spawns")
            .join()
            .unwrap();
        assert_eq!(out.data, b"partial");
        assert!(!out.overrun);
        assert!(
            out.read_error,
            "a mid-stream read failure must be reported, not treated as EOF"
        );
    }

    /// S33: a reader blocked on a held pipe detaches at the bound
    /// with an explicit unsettled error instead of hanging the
    /// caller. The socketpair stands in for a descendant-held pipe;
    /// the short test deadline pins the detach path in ~0.2s, not
    /// the 10s production bound.
    #[cfg(target_os = "linux")]
    #[test]
    fn settle_detaches_blocked_reader_at_bound() {
        use std::os::unix::net::UnixStream;
        let (read_end, held) = UnixStream::pair().unwrap();
        let hit = Arc::new(AtomicBool::new(false));
        let handle = spawn_capped_reader(read_end, 1 << 20, hit).unwrap();
        let start = Instant::now();
        let Err(error) = settle_before(handle, "stdout", start + Duration::from_millis(200)) else {
            panic!("blocked reader must detach, not join");
        };
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "detach is bounded"
        );
        assert_eq!(error.kind(), scopebase_bpf::ErrorKind::Backend);
        assert_eq!(error.stage(), scopebase_bpf::Stage::Execute);
        drop(held);
    }

    /// R06: a denied reader-thread spawn surfaces as `Err` instead of
    /// panicking the caller. An absurd stack size makes pthread attr
    /// setup fail deterministically (EINVAL, no threads or limits
    /// touched); small sizes merely round up and still spawn.
    #[cfg(target_os = "linux")]
    #[test]
    fn reader_spawn_failure_is_typed_error() {
        let hit = Arc::new(AtomicBool::new(false));
        let denied = std::thread::Builder::new().stack_size(usize::MAX);
        // Control: the default builder spawns (its reader is joined
        // and dropped; FailAfterPartial ends in a read error, which
        // is fine here since only spawn success is asserted).
        let control = spawn_capped_reader(FailAfterPartial { sent: false }, 1 << 20, hit.clone());
        assert!(
            control.is_ok(),
            "default reader spawn must succeed, both branches asserted"
        );
        let _ = control.unwrap().join();
        let denied_err =
            spawn_capped_reader_on(denied, FailAfterPartial { sent: false }, 1 << 20, hit);
        assert!(
            denied_err.is_err(),
            "absurd-stack reader spawn must fail, not panic or spawn"
        );
    }
}
