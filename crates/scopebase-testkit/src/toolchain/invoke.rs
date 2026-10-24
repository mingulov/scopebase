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
///
/// Preconditions (S85-round6): the caller must not auto-reap children
/// (`SIGCHLD` set to `SIG_IGN` or `SA_NOCLDWAIT`) and must not run
/// competing waiters on the tool pid — either recycles the pid/pgid
/// numbers the group retirement relies on. Auto-reap is refused up
/// front (`InvalidInput/Admission`); reset the `SIGCHLD` disposition
/// around the call. A caller seccomp filter denying `waitid` and/or
/// signaling is tolerated: observation outage retires bounded with
/// explicit fallout instead of hanging.
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
        None,
        None,
    )
}

/// S33: test-only entry point with injectable reader-thread builders,
/// so the second-reader-failure branch is forced (a denied builder),
/// not wished for. Production callers use [`run_pinned`].
/// S67-round4: `observe_gate` runs once after both readers spawn and
/// before the first observation, so the WNOWAIT-denial branch runs
/// with a proven-started tool (the gate waits for the fixture's
/// pidfile). Production passes None.
#[doc(hidden)]
// Nine args: run_pinned's six plus the two injected builders plus
// the two test gates; a struct would obscure the delegation.
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
    stderr_gate: Option<Box<dyn FnOnce() + Send>>,
    observe_gate: Option<Box<dyn FnOnce() + Send>>,
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

    // S85-round6: refuse auto-reap up front. An auto-reaped child
    // never becomes our zombie, so its pid/pgid numbers recycle on
    // exit — and a waitid filter turns the ECHILD proof into an
    // indistinguishable EPERM, which round-5 misread as "reservation
    // intact" and signaled. No run may start unprovable.
    #[cfg(unix)]
    if sigchld_auto_reaps() {
        return Err(invalid(
            "SIGCHLD auto-reap refused: tool group reservation unprovable",
        ));
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
    // S85-round6: retained reservation authority. The spawn-time
    // pidfd (Linux) pins OUR leader task; group effects consult it
    // instead of trusting the observation errno. Auto-reap was
    // refused above, so without a competing waiter (caller contract)
    // the leader cannot be reaped before we reap it.
    let authority = ToolAuthority {
        #[cfg(target_os = "linux")]
        pidfd: crate::fixture::linux::seccomp::pidfd_open_raw(child.id() as libc::pid_t).ok(),
    };
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
            // S86-round6: the already-spawned tool retires bounded
            // (never the blocking retire), with group and signal
            // fallout chained instead of dropped.
            let group_fallout = signal_tool_group(group, &authority).err();
            let retired = kill_and_wait_deadline(&mut child, Instant::now() + CLEANUP_GRACE);
            return Err(primary_failure(
                backend(error, Stage::Execute),
                "tool reader spawn failed",
                combine_fallout(group_fallout, retired.err()),
                None,
            ));
        }
    };
    // S33-round3: test-only gate before the second reader spawn, so
    // the failure branch runs with a proven-live descendant (the
    // gate waits for the fixture's pidfile). Production passes None.
    if let Some(gate) = stderr_gate {
        gate();
    }
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
            // S86-round6: the tool retires bounded here too, with
            // group fallout riding the retirement leg.
            let group_fallout = signal_tool_group(group, &authority).err();
            let retired = kill_and_wait_deadline(&mut child, Instant::now() + CLEANUP_GRACE);
            let spawn = backend(error, Stage::Execute);
            let settled = settle_one(stdout_reader, "stdout");
            return Err(primary_failure(
                spawn,
                "tool reader spawn failed",
                combine_fallout(group_fallout, retired.err()),
                settled.err(),
            ));
        }
    };
    // R05 sweep note: this addition cannot overflow. `timeout_ms` is a
    // u64 of MILLISECONDS: even u64::MAX is ~584M years, and now()+that
    // stays far inside the Instant range (verified: checked_add at MAX
    // returns Some). Only raw `Duration` params (audit/target sites)
    // can carry an unrepresentable span.
    let deadline = Instant::now() + Duration::from_millis(bounds.timeout_ms);
    // S67-round4: test-only gate before the first observation (see
    // the `stderr_gate` precedent above). Production passes None.
    if let Some(gate) = observe_gate {
        gate();
    }

    loop {
        if stdout_hit.load(Ordering::SeqCst) || stderr_hit.load(Ordering::SeqCst) {
            // S86-round6: bounded retirement on the overrun path too:
            // a kill-proof overrun tool must not hang cleanup. The
            // overrun stays the verdict; retirement and settlement
            // fallout ride along instead of preempting or vanishing.
            let group_fallout = signal_tool_group(group, &authority).err();
            let retired = kill_and_wait_deadline(&mut child, deadline);
            let settled = settle_pair(stdout_reader, stderr_reader);
            let retire_leg = combine_fallout(group_fallout, retired.err());
            let (primary, settle_leg) = match settled {
                Ok((out, err)) => (capped_error(&out, &err), None),
                // Settlement failed: the overrun verdict stands (the
                // flags prove it; the byte count is unobservable
                // without outputs), with the settlement diagnosis
                // riding the settle leg.
                Err(settle) => {
                    let blind = if stdout_hit.load(Ordering::SeqCst) {
                        bound_exceeded("stdout over bound", Stage::Execute)
                    } else {
                        bound_exceeded("stderr over bound", Stage::Execute)
                    };
                    (blind, Some(settle))
                }
            };
            return Err(primary_failure(
                primary,
                "tool output overrun",
                retire_leg,
                settle_leg,
            ));
        }
        let observed = match exited_no_reap(&child) {
            Ok(observed) => observed,
            Err(error) => {
                // S67-round4: a failed observation (e.g. a caller
                // filter denying the WNOWAIT waitid while allowing
                // reap and signaling) must still retire the tool and
                // settle the readers — never drop a live Child and
                // two reader handles with no recovery path.
                // S85-round5: classify reservation loss BEFORE any
                // group effect. ECHILD means the leader was reaped
                // out from under us (SIGCHLD auto-reap or a
                // competing waiter in this process): the pid AND
                // pgid numbers are reusable, so neither the group
                // nor the child handle may be signaled. Settle the
                // readers (safe: our own threads, bounded) and
                // report unresolved custody.
                if reservation_lost(&error) {
                    let observation = backend(error, Stage::Execute);
                    let settled = settle_pair(stdout_reader, stderr_reader);
                    return Err(observe_failure(
                        observation,
                        Some(custody_unresolved()),
                        settled.err(),
                    ));
                }
                let observation = backend(error, Stage::Execute);
                // S85-round6: the group signal is authority-gated
                // (never trusted on the EPERM errno alone), and its
                // fallout rides the retirement leg. S86-round6: every
                // post-spawn path retires bounded now (overrun and
                // wall-clock expiry keep the run deadline; spawn
                // failure and post-expiry cleanup use CLEANUP_GRACE).
                let group_fallout = signal_tool_group(group, &authority).err();
                let retired = kill_and_wait_deadline(&mut child, deadline);
                let settled = settle_pair(stdout_reader, stderr_reader);
                return Err(observe_failure(
                    observation,
                    combine_fallout(group_fallout, retired.err()),
                    settled.err(),
                ));
            }
        };
        match observed {
            Some(_) => {
                // S51: the leader is observed-but-unreaped — a
                // zombie that keeps its pid AND its process-group
                // membership reserved. Kill the group FIRST (while
                // the number cannot be reused), then reap. The old
                // try_wait-then-killpg order reaped first: with the
                // group empty, the pgid number was free for reuse
                // and the SIGKILL could hit a new same-UID group.
                // S85-round6: the group signal is authority-gated;
                // withheld/refused fallout chains onto every error
                // return below (only one `.take()` runs).
                let mut group_fallout = signal_tool_group(group, &authority).err();
                let status = child.wait().map_err(|error| {
                    primary_failure(
                        backend(error, Stage::Execute),
                        "tool execution failed",
                        group_fallout.take(),
                        None,
                    )
                })?;
                // S33: forked descendants may hold the pipes;
                // settle bounded either way.
                let (out, err) = settle_pair(stdout_reader, stderr_reader).map_err(|settle| {
                    primary_failure(settle, "tool execution failed", group_fallout.take(), None)
                })?;
                if out.overrun || err.overrun {
                    return Err(primary_failure(
                        capped_error(&out, &err),
                        "tool execution failed",
                        group_fallout.take(),
                        None,
                    ));
                }
                if out.read_error || err.read_error {
                    return Err(primary_failure(
                        reader_failed(),
                        "tool execution failed",
                        group_fallout.take(),
                        None,
                    ));
                }
                if status.success() {
                    // A withheld group signal with an otherwise clean
                    // run is still unresolved descendant custody (a
                    // pipeless daemonized descendant may survive) —
                    // fail closed, never silently leak.
                    if let Some(fallout) = group_fallout.take() {
                        return Err(fallout);
                    }
                    return Ok(NestedOutput {
                        code: status.code(),
                        stdout: out.data,
                        stderr: err.data,
                    });
                }
                return Err(primary_failure(
                    OperationError::new(
                        ErrorKind::Backend,
                        Stage::Execute,
                        None,
                        Some(Box::new(Detail(
                            "tool exited nonzero or signaled".to_string(),
                        ))),
                    ),
                    "tool execution failed",
                    group_fallout.take(),
                    None,
                ));
            }
            None => {
                if Instant::now() >= deadline {
                    // S86-round6: the run deadline expired, so
                    // retirement gets its own cleanup grace — bounded
                    // either way, with fallout chained.
                    let group_fallout = signal_tool_group(group, &authority).err();
                    let retired =
                        kill_and_wait_deadline(&mut child, Instant::now() + CLEANUP_GRACE);
                    let settled = settle_pair(stdout_reader, stderr_reader);
                    let retire_leg = combine_fallout(group_fallout, retired.err());
                    let (primary, settle_leg) = match settled {
                        Ok((out, err)) if out.overrun || err.overrun => {
                            (capped_error(&out, &err), None)
                        }
                        Ok((out, err)) if out.read_error || err.read_error => {
                            (reader_failed(), None)
                        }
                        Ok(_) => (bound_exceeded("wall-clock timeout", Stage::Execute), None),
                        // Settlement failed: the timeout verdict
                        // stands, with the settlement diagnosis riding
                        // the settle leg.
                        Err(settle) => (
                            bound_exceeded("wall-clock timeout", Stage::Execute),
                            Some(settle),
                        ),
                    };
                    return Err(primary_failure(
                        primary,
                        "tool timeout",
                        retire_leg,
                        settle_leg,
                    ));
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

/// S51: observe (without reaping) whether `child` has exited. On
/// unix a WNOWAIT wait leaves an exited child as a zombie, which
/// keeps both its pid and its process-group membership reserved —
/// so a group signal issued after this observation cannot hit a
/// reused pgid. The caller must reap (or kill) the child
/// afterwards. Off unix this is `try_wait` (no group signal is
/// ever sent there, so no reservation hazard exists).
fn exited_no_reap(
    child: &std::process::Child,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        // WNOWAIT is a waitid(2) facility (waitpid rejects it with
        // EINVAL); WEXITED reports only dead children, never stops.
        // SAFETY: waitid with a valid siginfo out-pointer for an
        // owned child pid; the union accessors below read the
        // child-wait fields of a waitid-filled siginfo.
        unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            let result = libc::waitid(
                libc::P_PID,
                child.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            );
            if result < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if info.si_pid() == 0 {
                return Ok(None);
            }
            let raw = match info.si_code {
                code if code == libc::CLD_EXITED => info.si_status() << 8,
                code if code == libc::CLD_KILLED => info.si_status() & 0x7f,
                code if code == libc::CLD_DUMPED => (info.si_status() & 0x7f) | 0x80,
                _ => {
                    return Err(std::io::Error::other("unexpected waitid child state"));
                }
            };
            Ok(Some(std::process::ExitStatus::from_raw(raw)))
        }
    }
    #[cfg(not(unix))]
    {
        child.try_wait()
    }
}

/// S33: SIGKILL the tool process group: the child plus any forked
/// descendants holding pipes. Idempotent (ESRCH is fine); not
/// available off unix, where settlement still bounds the wait.
/// S86-round6: cleanup grace for post-spawn retirement after the run
/// deadline expired (timeout path) or never started (reader-spawn
/// failure). Matches the 10s reader-settlement bound: cleanup stays
/// in the same order as the run's own bounds, never unbounded.
const CLEANUP_GRACE: Duration = Duration::from_secs(10);

/// S85-round6: retained reservation authority for one tool run. The
/// value itself proves the spawn-time checks ran; on Linux it
/// additionally pins the leader through a spawn-time pidfd, immune
/// to pid-number reuse.
struct ToolAuthority {
    /// Spawn-time pidfd of the leader (Linux only). `None` when the
    /// birth open failed — pre-pidfd kernel, or the leader already
    /// reaped by a competing waiter — and group effects are then
    /// withheld: without the pin, a masked observation cannot prove
    /// the pgid number is still ours.
    #[cfg(target_os = "linux")]
    pidfd: Option<std::os::fd::RawFd>,
}

#[cfg(target_os = "linux")]
impl Drop for ToolAuthority {
    fn drop(&mut self) {
        if let Some(fd) = self.pidfd.take() {
            // SAFETY: fd owned by this authority.
            unsafe {
                libc::close(fd);
            }
        }
    }
}

/// S85-round6: true when `SIGCHLD` currently auto-reaps children —
/// `SIG_IGN` disposition or `SA_NOCLDWAIT`. An auto-reaped child
/// never becomes our zombie, so its pid/pgid numbers recycle the
/// moment it exits. Read-back only; touches no process state.
/// (A caller racing disposition changes against group effects
/// defeats any check — same contract as competing waiters.)
/// Twin of the audit preflight detector (unix-wide here, x86_64-only
/// there — different cfg homes, same logic); keep the two in sync.
#[cfg(unix)]
fn sigchld_auto_reaps() -> bool {
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: sigaction read-back (act NULL) for this process.
    let rc = unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut old) };
    // A failed read-back fails closed: unknown disposition is
    // treated as auto-reap.
    rc != 0 || old.sa_sigaction == libc::SIG_IGN || (old.sa_flags & libc::SA_NOCLDWAIT) != 0
}

/// S85-round6: probe the pinned leader through its pidfd (signal 0).
/// `Ok(true)` — our task is present (alive or zombie; a zombie still
/// reserves pid AND pgid). `Ok(false)` — our task was reaped
/// (ESRCH through the pin names OUR child, never a recycled
/// number). `Err` — the probe itself failed (denied filter,
/// unexpected errno): authority unprovable, fail closed.
#[cfg(target_os = "linux")]
fn pidfd_alive(fd: std::os::fd::RawFd) -> Result<bool, i32> {
    // SAFETY: pidfd_send_signal(pidfd, 0, NULL, 0).
    let sent = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd as libc::c_long,
            0 as libc::c_long,
            0 as libc::c_long,
            0 as libc::c_long,
        )
    };
    if sent == 0 {
        return Ok(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(errno) => Err(errno),
        None => Err(-1),
    }
}

/// S85-round6: withheld-group-signal fallout. The numeric group was
/// deliberately NOT signaled; descendants beyond the leader are
/// unresolved — reported, never silently abandoned.
fn group_unresolved(why: &str) -> OperationError {
    OperationError::new(
        ErrorKind::Backend,
        Stage::Execute,
        None,
        Some(Box::new(Detail(format!(
            "tool group not signaled ({why}); descendant custody unresolved"
        )))),
    )
}

/// S86-round6: refused-group-signal fallout. The `killpg` was
/// attempted under valid authority but refused; its errno rides
/// along instead of being ignored.
fn group_signal_refused(error: std::io::Error) -> OperationError {
    OperationError::new(
        ErrorKind::Backend,
        Stage::Execute,
        error.raw_os_error(),
        Some(Box::new(Detail(format!(
            "tool group signal refused ({error}); descendant custody unresolved"
        )))),
    )
}

/// S85-round6: signal the tool group under retained reservation
/// authority — never on the observation errno alone. The round-5
/// rule trusted any non-ECHILD errno as "reservation intact", but a
/// waitid filter turns ECHILD into an indistinguishable EPERM: with
/// auto-reap, that EPERM hides a reaped leader and the signal hits a
/// recycled pgid. The gate is now: no auto-reap engaged right now
/// (numbers cannot recycle without a reap), and on Linux a pidfd
/// proving OUR leader still holds its group membership (which also
/// detects competing-waiter reaps a filter would hide). Withheld and
/// refused signals return errors; only a signaled group (or no group
/// signal off unix) returns `Ok`.
#[cfg(unix)]
fn signal_tool_group(group: Option<u32>, authority: &ToolAuthority) -> Result<(), OperationError> {
    let Some(pgid) = group else {
        return Ok(());
    };
    if sigchld_auto_reaps() {
        return Err(group_unresolved("SIGCHLD auto-reap engaged"));
    }
    #[cfg(target_os = "linux")]
    match authority.pidfd {
        None => {
            return Err(group_unresolved("no pidfd authority for the leader"));
        }
        Some(fd) => match pidfd_alive(fd) {
            Ok(true) => {}
            Ok(false) => {
                return Err(group_unresolved("leader reaped under a masked observation"));
            }
            Err(errno) => {
                return Err(group_unresolved(&format!(
                    "leader authority unprovable (errno {errno})"
                )));
            }
        },
    }
    // SAFETY: signal our own reserved tool group: auto-reap is off
    // (no reap without us, so no number reuse), and on Linux the
    // pidfd proves OUR leader still holds the membership.
    let sent = unsafe { libc::killpg(pgid as libc::pid_t, libc::SIGKILL) };
    if sent == 0 {
        Ok(())
    } else {
        Err(group_signal_refused(std::io::Error::last_os_error()))
    }
}

/// Off unix there is no group signal, so no reservation hazard exists.
#[cfg(not(unix))]
fn signal_tool_group(group: Option<u32>, authority: &ToolAuthority) -> Result<(), OperationError> {
    let _ = (group, authority);
    Ok(())
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

/// S86-round6: merge two retirement-leg fallouts (group signal +
/// child retire) into one leg, preserving both chains. `None` when
/// both are clean — clean retirement stays silent.
fn combine_fallout(
    first: Option<OperationError>,
    second: Option<OperationError>,
) -> Option<OperationError> {
    match (first, second) {
        (None, None) => None,
        (Some(one), None) | (None, Some(one)) => Some(one),
        (Some(first), Some(second)) => Some(OperationError::new(
            first.kind(),
            first.stage(),
            first.raw_os_error(),
            Some(Box::new(Detail(format!(
                "{} | {}",
                chain_text(&first),
                chain_text(&second)
            )))),
        )),
    }
}

/// S86-round6: attach retirement and settlement fallout to a failure
/// primary, preserving the primary's kind, stage, errno and required
/// size. Clean legs return the primary unchanged — wrapping is
/// invisible when there is no fallout (existing verdicts keep their
/// exact shape).
fn primary_failure(
    primary: OperationError,
    context: &str,
    retire: Option<OperationError>,
    settle: Option<OperationError>,
) -> OperationError {
    if retire.is_none() && settle.is_none() {
        return primary;
    }
    // The primary rides with its full chain: Display alone would
    // drop a settlement diagnosis ("output reader unsettled:
    // stdout...") living in its source.
    let mut detail = format!("{context} ({})", chain_text(&primary));
    if let Some(retire) = retire {
        detail.push_str(&format!(
            "; tool retirement failed ({})",
            chain_text(&retire)
        ));
    }
    if let Some(settle) = settle {
        detail.push_str(&format!("; {}", chain_text(&settle)));
    }
    let mut combined = OperationError::new(
        primary.kind(),
        primary.stage(),
        primary.raw_os_error(),
        Some(Box::new(Detail(detail))),
    );
    if let Some(size) = primary.required_size() {
        combined = combined.with_required_size(size);
    }
    combined
}

/// S67-round4: combine an observation failure with bounded-retirement
/// fallout. Clean retirement returns the observation error unchanged;
/// an unretired tool or unsettled readers join the report, so
/// unresolved ownership is explicit, never silently dropped.
fn observe_failure(
    observation: OperationError,
    retire: Option<OperationError>,
    settle: Option<OperationError>,
) -> OperationError {
    primary_failure(observation, "tool observation failed", retire, settle)
}

/// S87-round5: the full cause chain of a fallout error, head first.
/// [`OperationError`]'s Display omits its source, so interpolating
/// the head alone drops the unsettled reader's stream name and
/// custody diagnosis (both live in the source).
fn chain_text(error: &OperationError) -> String {
    let mut parts = vec![error.to_string()];
    let mut next = std::error::Error::source(error);
    while let Some(source) = next {
        parts.push(source.to_string());
        next = std::error::Error::source(source);
    }
    parts.join(" | ")
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

/// S85-round5: ECHILD from the no-reap observation means the leader
/// is no longer our child — reaped out from under the run (auto-reap
/// is refused up front since round-6; a competing waiter in this
/// process is the remaining cause, a caller-contract violation). Its
/// pid and pgid numbers are reusable: no signal may be sent to
/// either.
/// S85-round6 correction: any OTHER failure (EPERM denial,
/// unexpected child state) leaves the reservation UNPROVEN, not
/// intact — a filter masks ECHILD as EPERM. Non-ECHILD failures
/// route to the authority gate ([`signal_tool_group`]), never to a
/// blind group signal. Off unix there is no group signal, so no
/// reservation hazard exists.
#[cfg(unix)]
fn reservation_lost(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::ECHILD)
}
#[cfg(not(unix))]
fn reservation_lost(_error: &std::io::Error) -> bool {
    false
}

/// S85-round5: unresolved-custody fallout. The leader escaped
/// observation (see [`reservation_lost`]): the group was
/// deliberately NOT signaled, so descendants beyond the leader are
/// unresolved — reported, never silently abandoned.
fn custody_unresolved() -> OperationError {
    OperationError::new(
        ErrorKind::Backend,
        Stage::Execute,
        None,
        Some(Box::new(Detail(
            "child reservation lost: process group not signaled, tool custody unresolved"
                .to_string(),
        ))),
    )
}

/// S86-round5: retire the tool before a deadline. The signal error
/// is explicit (a denied kill is recorded, not ignored), and the
/// reap polls bounded — a kill-proof long-running tool reports
/// unresolved retirement at the deadline instead of blocking past
/// the configured timeout.
fn kill_and_wait_deadline(child: &mut Child, end: Instant) -> Result<(), OperationError> {
    let signal = child.kill().err();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {
                if Instant::now() >= end {
                    return Err(retire_unresolved(signal));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(backend(error, Stage::Execute)),
        }
    }
}

/// S86-round5: bounded-retirement fallout. The tool is still alive
/// at the deadline; a refused signal rides along with its errno.
fn retire_unresolved(signal: Option<std::io::Error>) -> OperationError {
    let errno = signal.as_ref().and_then(|error| error.raw_os_error());
    let detail = match &signal {
        Some(error) => {
            format!("tool still alive after bounded retirement (signal refused: {error})")
        }
        None => "tool still alive after bounded retirement".to_string(),
    };
    OperationError::new(
        ErrorKind::Backend,
        Stage::Execute,
        errno,
        Some(Box::new(Detail(detail))),
    )
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

    /// S51: the no-reap observation leaves an exited child as a
    /// reserved zombie (still in /proc, state Z, group intact)
    /// until the caller reaps it — the reservation a group signal
    /// issued between observe and reap relies on. `try_wait`
    /// cannot provide this: it reaps, freeing the pgid number.
    #[cfg(unix)]
    #[test]
    fn no_reap_observation_keeps_leader_reserved() {
        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .expect("true spawns");
        let pid = child.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let observed = loop {
            match exited_no_reap(&child).expect("observation runs") {
                Some(status) => break status,
                None => {
                    assert!(std::time::Instant::now() < deadline, "true never exited");
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        };
        assert!(observed.success());
        // Still reserved: present in /proc as a zombie with its
        // group membership intact.
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .expect("unreaped child still reserved in /proc");
        let state = stat
            .rsplit(')')
            .next()
            .unwrap_or("")
            .trim_start()
            .chars()
            .next();
        assert_eq!(state, Some('Z'), "expected zombie, stat: {stat}");
        let group = unsafe { libc::getpgid(pid as libc::pid_t) };
        assert!(group > 0, "zombie leader keeps its group");
        child.wait().expect("reap runs");
        assert!(
            std::fs::read_to_string(format!("/proc/{pid}/stat")).is_err(),
            "reaped pid must be gone"
        );
    }

    /// S67-round4: the observation-failure combiner returns the
    /// observation error unchanged on clean retirement, and joins
    /// unretired-tool / unsettled-reader fallout into the report
    /// otherwise — unresolved ownership is explicit, with the
    /// observation errno preserved. Fallout errors ride as their
    /// `Display` (stage/kind/errno, like the spawn-failure
    /// combiner), so distinguishing errnos prove inclusion.
    #[test]
    fn observe_failure_combines_retirement_fallout() {
        use std::error::Error as _;
        let observation = backend(std::io::Error::from_raw_os_error(1), Stage::Execute);
        // Clean retirement: unchanged.
        let clean = observe_failure(
            backend(std::io::Error::from_raw_os_error(1), Stage::Execute),
            None,
            None,
        );
        assert_eq!(clean.kind(), ErrorKind::Backend);
        assert_eq!(clean.stage(), Stage::Execute);
        assert_eq!(clean.raw_os_error(), Some(1));
        // Retirement fallout joins the report.
        let retire = backend(std::io::Error::from_raw_os_error(3), Stage::Execute);
        let settle = backend(std::io::Error::from_raw_os_error(5), Stage::Execute);
        let combined = observe_failure(observation, Some(retire), Some(settle));
        assert_eq!(combined.kind(), ErrorKind::Backend);
        assert_eq!(combined.stage(), Stage::Execute);
        assert_eq!(
            combined.raw_os_error(),
            Some(1),
            "observation errno is preserved"
        );
        let detail = format!("{}", combined.source().expect("combined detail"));
        assert!(
            detail.contains("tool observation failed"),
            "observation leads: {detail}"
        );
        assert!(
            detail.contains("tool retirement failed"),
            "unretired tool joins: {detail}"
        );
        assert!(
            detail.contains("os error 3") && detail.contains("os error 5"),
            "both fallout errors ride along: {detail}"
        );
        // Settle-only fallout still rebuilds (no silent drop).
        let settle_only = observe_failure(
            backend(std::io::Error::from_raw_os_error(1), Stage::Execute),
            None,
            Some(backend(
                std::io::Error::from_raw_os_error(5),
                Stage::Execute,
            )),
        );
        let detail = format!("{}", settle_only.source().expect("settle detail"));
        assert!(
            detail.contains("os error 5") && !detail.contains("tool retirement failed"),
            "settle-only fallout is exact: {detail}"
        );
    }

    /// S87-round5: the combiner preserves a real unsettled error's
    /// stream name and custody diagnosis on both fallout legs — not
    /// just the sourceless Display head. Pre-fix only
    /// "scopebase-bpf Execute/Backend" rode along.
    #[test]
    fn observe_failure_preserves_unsettled_chain() {
        use std::error::Error as _;
        let observation = || backend(std::io::Error::from_raw_os_error(1), Stage::Execute);
        let combined = observe_failure(observation(), None, Some(unsettled("stdout")));
        let detail = format!("{}", combined.source().expect("settle detail"));
        assert!(
            detail.contains("stdout") && detail.contains("unsettled"),
            "settle leg keeps stream and diagnosis: {detail}"
        );
        let combined = observe_failure(observation(), Some(unsettled("stderr")), None);
        let detail = format!("{}", combined.source().expect("retire detail"));
        assert!(
            detail.contains("stderr") && detail.contains("unsettled"),
            "retire leg keeps stream and diagnosis: {detail}"
        );
    }

    /// S85-round5: only ECHILD means PROVEN lost reservation.
    /// S85-round6 correction: EPERM (a caller waitid filter) and
    /// sourceless errors no longer mean "reserved" — they mean
    /// UNPROVEN (a filter masks ECHILD as EPERM). Non-ECHILD
    /// failures route to the authority gate, never to a blind group
    /// signal; see `signal_tool_group` and the combined
    /// auto-reap/denial driver test.
    #[cfg(unix)]
    #[test]
    fn reservation_lost_classifies_echild_only() {
        assert!(reservation_lost(&std::io::Error::from_raw_os_error(
            libc::ECHILD
        )));
        assert!(!reservation_lost(&std::io::Error::from_raw_os_error(
            libc::EPERM
        )));
        assert!(!reservation_lost(&std::io::Error::other(
            "unexpected waitid child state"
        )));
    }

    /// S85-round5: the unresolved-custody fallout names the lost
    /// reservation, the withheld group signal, and the unresolved
    /// tool custody — the S85 auto-reap control asserts these.
    #[test]
    fn custody_unresolved_names_withheld_signal() {
        use std::error::Error as _;
        let detail = format!("{}", custody_unresolved().source().expect("custody detail"));
        assert!(
            detail.contains("reservation")
                && detail.contains("not signaled")
                && detail.contains("unresolved"),
            "custody fallout is explicit: {detail}"
        );
    }

    /// S86-round6: the generic combiner preserves the primary's
    /// kind, stage, errno and required size (an overrun verdict keeps
    /// its `LimitExceeded` and byte count under fallout), and returns
    /// the primary untouched when both legs are clean.
    #[test]
    fn primary_failure_preserves_primary_shape() {
        use std::error::Error as _;
        let capped = bound_exceeded("stdout over bound", Stage::Execute).with_required_size(99);
        let clean = primary_failure(
            bound_exceeded("stdout over bound", Stage::Execute).with_required_size(99),
            "tool output overrun",
            None,
            None,
        );
        assert_eq!(clean.kind(), ErrorKind::LimitExceeded);
        assert_eq!(clean.required_size(), Some(99));
        let combined = primary_failure(
            capped,
            "tool output overrun",
            Some(retire_unresolved(None)),
            Some(unsettled("stdout")),
        );
        assert_eq!(combined.kind(), ErrorKind::LimitExceeded);
        assert_eq!(combined.stage(), Stage::Execute);
        assert_eq!(combined.required_size(), Some(99));
        let detail = format!("{}", combined.source().expect("combined detail"));
        assert!(
            detail.contains("tool output overrun")
                && detail.contains("tool retirement failed")
                && detail.contains("still alive")
                && detail.contains("unsettled"),
            "context and both legs ride along: {detail}"
        );
    }

    /// S86-round6: fallout merging keeps both chains, passes single
    /// legs through, and stays silent when clean.
    #[test]
    fn combine_fallout_merges_both_chains() {
        use std::error::Error as _;
        assert!(combine_fallout(None, None).is_none());
        let solo = backend(std::io::Error::from_raw_os_error(3), Stage::Execute);
        assert!(combine_fallout(Some(solo), None).is_some());
        let first = group_unresolved("probe");
        let second = retire_unresolved(None);
        let merged = combine_fallout(Some(first), Some(second)).expect("merges");
        let detail = format!("{}", merged.source().expect("merged detail"));
        assert!(
            detail.contains("not signaled") && detail.contains("still alive"),
            "both chains ride along: {detail}"
        );
    }

    /// S85-round6: a fresh test process does not auto-reap (read-only
    /// check — setting dispositions process-wide would race parallel
    /// tests, so positives live in the confined denial driver, not
    /// here).
    #[cfg(unix)]
    #[test]
    fn sigchld_disposition_defaults_to_no_auto_reap() {
        assert!(!sigchld_auto_reaps());
    }

    /// Spawn `/bin/sleep 30` as its own process-group leader, via
    /// the production `pre_exec` idiom: post-exec `setpgid` from the
    /// parent fails EACCES, so the child must claim its group itself
    /// (`claim_tool_group` alone would silently leave it in ours,
    /// and a withhold regression would then hit nothing — a vacuous
    /// tripwire).
    #[cfg(target_os = "linux")]
    fn spawn_grouped_sleep() -> std::process::Child {
        use std::os::unix::process::CommandExt as _;
        let mut command = std::process::Command::new("/bin/sleep");
        // SAFETY: setpgid is async-signal-safe; the parent does not
        // depend on its result (a failure surfaces in the test).
        unsafe {
            command.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        command.arg("30").spawn().expect("grouped sleep spawns")
    }

    /// S85-round6: a pidfd-pinned live leader in its own group is
    /// signaled — authority holds, the group dies.
    #[cfg(target_os = "linux")]
    #[test]
    fn signal_tool_group_kills_reserved_group() {
        let mut child = spawn_grouped_sleep();
        let id = child.id();
        let authority = ToolAuthority {
            pidfd: Some(
                crate::fixture::linux::seccomp::pidfd_open_raw(id as libc::pid_t)
                    .expect("pidfd opens on owned child"),
            ),
        };
        signal_tool_group(Some(id), &authority).expect("reserved group signaled");
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait().expect("try_wait runs") {
                Some(status) => {
                    assert!(!status.success(), "signaled tool did not exit zero");
                    break;
                }
                None => {
                    assert!(Instant::now() < end, "group signal had no effect");
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    /// S85-round6: without a pidfd pin the group signal is withheld
    /// and the live leader survives — no blind numeric signal.
    #[cfg(target_os = "linux")]
    #[test]
    fn signal_tool_group_withholds_without_pidfd() {
        use std::error::Error as _;
        // A real group: a withhold regression would kill the leader
        // and trip the aliveness assertion below.
        let mut child = spawn_grouped_sleep();
        let id = child.id();
        let authority = ToolAuthority { pidfd: None };
        let refused = signal_tool_group(Some(id), &authority).expect_err("withheld");
        let detail = format!("{}", refused.source().expect("withheld detail"));
        assert!(
            detail.contains("not signaled") && detail.contains("unresolved"),
            "withheld signal is explicit: {detail}"
        );
        assert!(
            child.try_wait().expect("try_wait runs").is_none(),
            "withheld signal must spare the leader"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    /// S85-round6: a pidfd proving the leader reaped (ESRCH through
    /// the pin — the competing-waiter case a filter would hide)
    /// withholds the group signal instead of hitting a recycled pgid.
    #[cfg(target_os = "linux")]
    #[test]
    fn signal_tool_group_withholds_reaped_leader() {
        use std::error::Error as _;
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("sleep spawns");
        let id = child.id();
        let authority = ToolAuthority {
            pidfd: Some(
                crate::fixture::linux::seccomp::pidfd_open_raw(id as libc::pid_t)
                    .expect("pidfd opens on owned child"),
            ),
        };
        // Reap the leader out from under the pin (what a competing
        // waiter does): the pin now proves absence.
        let _ = child.kill();
        let _ = child.wait();
        let refused = signal_tool_group(Some(id), &authority).expect_err("reaped leader withholds");
        let detail = format!("{}", refused.source().expect("withheld detail"));
        assert!(
            detail.contains("reaped under a masked observation"),
            "reaped leader is explicit: {detail}"
        );
    }

    /// S86-round6: a killpg refused under valid authority (nonexistent
    /// pgid — 99999999 exceeds any pid_max) reports its errno instead
    /// of being ignored.
    #[cfg(target_os = "linux")]
    #[test]
    fn signal_tool_group_reports_refused_killpg() {
        use std::error::Error as _;
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("sleep spawns");
        let authority = ToolAuthority {
            pidfd: Some(
                crate::fixture::linux::seccomp::pidfd_open_raw(child.id() as libc::pid_t)
                    .expect("pidfd opens on owned child"),
            ),
        };
        let refused = signal_tool_group(Some(99_999_999), &authority).expect_err("refused killpg");
        assert_eq!(refused.raw_os_error(), Some(libc::ESRCH));
        let detail = format!("{}", refused.source().expect("refused detail"));
        assert!(
            detail.contains("signal refused") && detail.contains("unresolved"),
            "refused signal is explicit: {detail}"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    /// S86-round5: bounded retirement reaps a signaled tool. The
    /// deadline-exceeded leg needs denied signals (irreversible in
    /// a test process), so it is pinned by the S86 driver control,
    /// not here.
    #[test]
    fn bounded_retirement_reaps_signaled_tool() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("sleep spawns");
        let end = Instant::now() + Duration::from_secs(10);
        kill_and_wait_deadline(&mut child, end).expect("signaled sleep reaps");
    }

    /// S86-round5: the bounded-retirement fallout carries the
    /// refused signal's errno and names the live tool — the S86
    /// signal-denial control asserts these.
    #[test]
    fn retire_unresolved_carries_signal_errno() {
        use std::error::Error as _;
        let error = retire_unresolved(Some(std::io::Error::from_raw_os_error(1)));
        assert_eq!(error.raw_os_error(), Some(1));
        let detail = format!("{}", error.source().expect("retire detail"));
        assert!(
            detail.contains("still alive") && detail.contains("signal refused"),
            "retire fallout is explicit: {detail}"
        );
        let silent = retire_unresolved(None);
        assert_eq!(silent.raw_os_error(), None);
        let detail = format!("{}", silent.source().expect("silent detail"));
        assert!(
            detail.contains("still alive") && !detail.contains("signal refused"),
            "no signal error means no signal claim: {detail}"
        );
    }

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
