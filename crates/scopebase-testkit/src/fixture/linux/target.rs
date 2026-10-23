// SPDX-License-Identifier: Apache-2.0
//! Owned TT04 target processes: stopped, mapping and exec-transition.
//!
//! `stopped` PORTs P src/discovery/test_subject.rs @2c2713e6:1-129
//! (`OwnedMapper::ready`/`from_child`/Drop plus `poll_fd`: readiness
//! acknowledgement over a pipe, SIGSTOP, waitid stop verification with
//! WNOWAIT custody preservation, kill+wait Drop). `mapping` (fork+mmap
//! with a syscall-only child and a sample pipe) and `exec_transition`
//! (readiness, commanded exec, exe-link barrier) are NEW per the frozen
//! TT04 fork/exec/exit fixture design. D03 scoped grant (2026-10-23)
//! covers GPL-source to Apache-2.0 destination inside this workspace;
//! donor files/terms untouched.
use super::fork;
use std::fmt;
use std::fs::File;
use std::io::Read as _;
use std::io::Write as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd, RawFd};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

/// Fixture construction/operation failure with the exact stage.
#[derive(Debug, Clone)]
pub struct TargetError(String);

impl TargetError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TargetError {}

/// PORT P test_subject.rs:106-129: poll one fd for readability with an
/// EINTR-resilient deadline. True means readable, false means timeout.
pub fn poll_fd(fd: RawFd, timeout: Duration) -> std::io::Result<bool> {
    // R05: an unrepresentable timeout is a typed refusal, never an
    // `Instant + Duration` panic. Checked before the fd is touched.
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "poll timeout overflows deadline",
        )
    })?;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout_ms = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd names one initialized descriptor for this process.
        let result = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
        if result > 0 {
            return Ok(true);
        }
        if result == 0 {
            return Ok(false);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
    }
}

fn read_exact_deadline(
    file: &mut File,
    mut buf: &mut [u8],
    deadline: Instant,
) -> Result<(), TargetError> {
    while !buf.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(TargetError::new("fixture read deadline expired"));
        }
        let ready = poll_fd(file.as_raw_fd(), remaining)
            .map_err(|e| TargetError::new(format!("fixture poll failed: {e}")))?;
        if !ready {
            return Err(TargetError::new("fixture read deadline expired"));
        }
        match file.read(buf) {
            Ok(0) => return Err(TargetError::new("fixture closed its pipe")),
            Ok(n) => buf = &mut buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(TargetError::new(format!("fixture read: {e}"))),
        }
    }
    Ok(())
}

/// R27: byte-exact `ready\n` acknowledgement with a deadline.
/// Silent (no bytes), partial (fewer than six before the deadline),
/// and malformed acknowledgements are distinct typed refusals, each
/// leaving the spawn guard armed so the child is retired.
fn await_ready<R: std::io::Read + std::os::fd::AsRawFd>(
    output: &mut R,
    deadline: Instant,
) -> Result<(), TargetError> {
    let mut line = [0u8; 6];
    let mut filled = 0;
    while filled < line.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero()
            || !poll_fd(output.as_raw_fd(), remaining)
                .map_err(|e| TargetError::new(format!("fixture poll: {e}")))?
        {
            return Err(TargetError::new("fixture readiness deadline expired"));
        }
        let mut byte = [0];
        output
            .read_exact(&mut byte)
            .map_err(|e| TargetError::new(format!("fixture readiness: {e}")))?;
        line[filled] = byte[0];
        filled += 1;
    }
    if &line != b"ready\n" {
        return Err(TargetError::new(
            "unexpected fixture readiness acknowledgement",
        ));
    }
    Ok(())
}

fn wait_pid_exited(pid: libc::pid_t, timeout: Duration) -> Result<i32, TargetError> {
    // R05: checked before any waitpid call.
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| TargetError::new("fixture wait timeout overflows deadline"))?;
    loop {
        let mut status = 0;
        // SAFETY: valid status out-pointer for an owned child.
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(TargetError::new(format!("waitpid failed: {error}")));
        }
        if result == pid {
            if libc::WIFEXITED(status) {
                return Ok(libc::WEXITSTATUS(status));
            }
            if libc::WIFSIGNALED(status) {
                return Ok(-libc::WTERMSIG(status));
            }
            // Stopped but not reaped: keep waiting for the terminal state.
        }
        if Instant::now() >= deadline {
            return Err(TargetError::new("fixture wait deadline expired"));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// R27: kill/reap custody for a raw-fork child, armed immediately
/// after fork and transferred (disarmed) only on successful
/// construction. Any error return drops the guard, which SIGKILLs
/// and reaps within a bounded wait: no live strand, no zombie.
struct ChildGuard {
    pid: Option<libc::pid_t>,
}

impl ChildGuard {
    fn armed(pid: libc::pid_t) -> Self {
        Self { pid: Some(pid) }
    }

    fn disarm(mut self) {
        self.pid = None;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.pid.take() {
            // SAFETY: signal an owned, unreaped child.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let _ = wait_pid_exited(pid, Duration::from_secs(5));
        }
    }
}

/// R27: kill/reap custody for a spawned child, armed immediately
/// after spawn; the only exit is [`SpawnGuard::take`], which moves
/// the live child to its owner on successful construction.
struct SpawnGuard(Option<Child>);

impl SpawnGuard {
    fn take(&mut self) -> Option<Child> {
        self.0.take()
    }
}

impl Drop for SpawnGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) if Instant::now() >= end => break,
                    Ok(None) => std::thread::sleep(Duration::from_millis(1)),
                }
            }
        }
    }
}

enum TargetKind {
    /// PORT: acknowledged, SIGSTOP-verified shell (stable mappings).
    Stopped { child: Child },
    /// NEW: raw-fork child with one private mapping and a sample pipe.
    Mapping {
        pid: libc::pid_t,
        range: (u64, u64),
        mapped_len: usize,
        cmd: File,
        out: File,
    },
    /// NEW: shell that execs sleep on command.
    Exec { child: Child, stdin: ChildStdin },
}

/// An owned target process. The guard retains all child custody until
/// Drop (SIGKILL plus reap for every variant).
pub struct OwnedTarget {
    kind: TargetKind,
}

impl OwnedTarget {
    /// PORT P test_subject.rs:14-28 (`OwnedMapper::ready`): an
    /// acknowledged, stopped shell whose mappings cannot change.
    pub fn stopped() -> Result<Self, TargetError> {
        let child = Command::new("sh")
            .args(["-c", "printf 'ready\\n'; read -r ignored"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| TargetError::new(format!("fixture spawn: {e}")))?;
        Self::stop_child(child, Duration::from_secs(5))
    }

    /// PORT P test_subject.rs:30-95 (`OwnedMapper::from_child`):
    /// byte-exact readiness, SIGSTOP, waitid stop acknowledgement with
    /// WNOWAIT so exit custody stays with the guard.
    fn stop_child(child: Child, timeout: Duration) -> Result<Self, TargetError> {
        let mut owned = Self {
            kind: TargetKind::Stopped { child },
        };
        let TargetKind::Stopped { child } = &mut owned.kind else {
            unreachable!("just constructed");
        };
        // R05: hardened though all call sites pass constant timeouts.
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| TargetError::new("fixture readiness timeout overflows deadline"))?;
        let mut output = child
            .stdout
            .take()
            .ok_or_else(|| TargetError::new("fixture has no readiness pipe"))?;
        for expected in b"ready\n" {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero()
                || !poll_fd(output.as_raw_fd(), remaining)
                    .map_err(|e| TargetError::new(format!("fixture poll: {e}")))?
            {
                return Err(TargetError::new("fixture readiness deadline expired"));
            }
            let mut byte = [0];
            output
                .read_exact(&mut byte)
                .map_err(|e| TargetError::new(format!("fixture readiness: {e}")))?;
            if byte[0] != *expected {
                return Err(TargetError::new(
                    "unexpected fixture readiness acknowledgement",
                ));
            }
        }
        let pid = child.id();
        // SAFETY: this unprivileged fixture owns this live, unreaped child.
        if unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) } != 0 {
            return Err(TargetError::new(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        loop {
            if Instant::now() >= deadline {
                return Err(TargetError::new(
                    "fixture stop acknowledgement deadline expired",
                ));
            }
            let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
            // SAFETY: one valid siginfo output for an owned child. WNOWAIT
            // preserves exit custody for the guard Drop, including errors.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid,
                    info.as_mut_ptr(),
                    libc::WSTOPPED | libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(TargetError::new(error.to_string()));
            }
            // SAFETY: zero-initialized storage, filled by successful waitid.
            let info = unsafe { info.assume_init() };
            // SAFETY: si_pid/si_code/si_status read the initialized union.
            if unsafe { info.si_pid() } != 0 {
                if info.si_code == libc::CLD_STOPPED && unsafe { info.si_status() } == libc::SIGSTOP
                {
                    return Ok(owned);
                }
                return Err(TargetError::new(
                    "fixture exited before its stop acknowledgement",
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// NEW: fork a child that privately maps the first page of `path`
    /// (which must hold at least 4096 bytes) and serves samples of its
    /// own mapping over a pipe. The child runs only raw syscalls.
    pub fn mapping(path: &Path) -> Result<Self, TargetError> {
        const MAP_LEN: usize = 4096;
        let file = std::fs::File::open(path)
            .map_err(|e| TargetError::new(format!("fixture open: {e}")))?;
        let size = file
            .metadata()
            .map_err(|e| TargetError::new(format!("fixture stat: {e}")))?
            .len() as usize;
        if size < MAP_LEN {
            return Err(TargetError::new(format!(
                "fixture {} holds {size} bytes, need {MAP_LEN}",
                path.display()
            )));
        }
        let mut cmd_pipe = [0; 2];
        let mut out_pipe = [0; 2];
        // SAFETY: valid out-pointers; return value checked immediately.
        if unsafe { libc::pipe(cmd_pipe.as_mut_ptr()) } != 0 {
            return Err(TargetError::new("fixture pipe failed"));
        }
        // F20: take ownership of the first pair before creating the
        // second, so a second pipe() failure closes (not leaks) the
        // first pair via these guards' Drop.
        // SAFETY: pipe() just reported success; both ends are ours.
        let cmd_owned = [
            unsafe { OwnedFd::from_raw_fd(cmd_pipe[0]) },
            unsafe { OwnedFd::from_raw_fd(cmd_pipe[1]) },
        ];
        // SAFETY: valid out-pointers; return value checked immediately.
        if unsafe { libc::pipe(out_pipe.as_mut_ptr()) } != 0 {
            return Err(TargetError::new("fixture pipe failed"));
        }
        // SAFETY: pipe() just reported success; both ends are ours.
        let out_owned = [
            unsafe { OwnedFd::from_raw_fd(out_pipe[0]) },
            unsafe { OwnedFd::from_raw_fd(out_pipe[1]) },
        ];
        // Both pairs exist: release them to the raw-fd fork protocol
        // below, which closes or File-wraps every end on all paths
        // (fork failure closes all four; otherwise the child's ends
        // close and the parent's ends become Files whose Drop closes).
        let [cmd_read, cmd_write] = cmd_owned;
        let [out_read, out_write] = out_owned;
        let cmd_pipe = [cmd_read.into_raw_fd(), cmd_write.into_raw_fd()];
        let out_pipe = [out_read.into_raw_fd(), out_write.into_raw_fd()];
        let file_fd = file.as_raw_fd();
        // SAFETY: the child below runs only raw syscalls on inherited
        // descriptors, then _exit; it never allocates, locks, or
        // returns into test code.
        unsafe {
            fork::fork_guarded(
                (file_fd, cmd_pipe[0], out_pipe[1]),
                |pid| {
                    Self::mapping_parent(
                        pid,
                        cmd_pipe[1],
                        out_pipe[0],
                        cmd_pipe[0],
                        out_pipe[1],
                        MAP_LEN,
                    )
                },
                || Self::mapping_child(),
            )
        }
    }

    /// The forked mapping child: one private mapping, then a
    /// syscall-only command loop. Diverges via `_exit`.
    fn mapping_child() -> ! {
        const MAP_LEN: usize = 4096;
        let (file_fd, cmd, out) = fork::slots();
        // SAFETY: every call below is a raw syscall on inherited
        // descriptors or stack memory; no allocation, no locks.
        unsafe {
            let addr = libc::mmap(
                std::ptr::null_mut(),
                MAP_LEN,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file_fd,
                0,
            );
            if addr == libc::MAP_FAILED {
                let msg = b"mmap-fail\n";
                libc::write(out, msg.as_ptr() as *const _, msg.len());
                libc::_exit(3);
            }
            let ready = b"ready\n";
            libc::write(out, ready.as_ptr() as *const _, ready.len());
            let words = [addr as u64, MAP_LEN as u64];
            libc::write(
                out,
                words.as_ptr() as *const _,
                std::mem::size_of_val(&words),
            );
            loop {
                let mut cmd_byte = [0u8; 1];
                let got = libc::read(cmd, cmd_byte.as_mut_ptr() as *mut _, 1);
                if got != 1 {
                    libc::_exit(0);
                }
                match cmd_byte[0] {
                    b's' => {
                        let mut base = addr as *const u8;
                        let mut left = MAP_LEN;
                        while left > 0 {
                            let wrote = libc::write(out, base as *const _, left);
                            if wrote <= 0 {
                                libc::_exit(0);
                            }
                            base = base.add(wrote as usize);
                            left -= wrote as usize;
                        }
                    }
                    b'x' => libc::_exit(0),
                    _ => libc::_exit(4),
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn mapping_parent(
        pid: libc::pid_t,
        cmd_write: RawFd,
        out_read: RawFd,
        cmd_read: RawFd,
        out_write: RawFd,
        map_len: usize,
    ) -> Result<Self, TargetError> {
        if pid < 0 {
            // SAFETY: ends owned by this scope.
            unsafe {
                libc::close(cmd_write);
                libc::close(out_read);
                libc::close(cmd_read);
                libc::close(out_write);
            }
            return Err(TargetError::new("fixture fork failed"));
        }
        // R27: kill/reap custody from here on: every error return
        // below drops the guard, which retires the child. Closing
        // the pipes alone would NOT stop it (it inherited writer
        // copies of every end), and nothing else would reap it.
        let guard = ChildGuard::armed(pid);
        // SAFETY: the child's ends, owned by this scope.
        unsafe {
            libc::close(cmd_read);
            libc::close(out_write);
        }
        // SAFETY: ends owned by this scope from here on.
        let cmd = unsafe { File::from_raw_fd(cmd_write) };
        let mut out = unsafe { File::from_raw_fd(out_read) };
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut line = [0u8; 6];
        read_exact_deadline(&mut out, &mut line, deadline)?;
        if &line != b"ready\n" {
            let code = wait_pid_exited(pid, Duration::from_secs(5)).unwrap_or(-99);
            return Err(TargetError::new(format!(
                "fixture child refused to map (exit {code})"
            )));
        }
        let mut words = [0u8; 16];
        read_exact_deadline(&mut out, &mut words, deadline)?;
        let addr = u64::from_le_bytes(words[0..8].try_into().unwrap());
        let len = u64::from_le_bytes(words[8..16].try_into().unwrap());
        if addr == 0 || len as usize != map_len {
            return Err(TargetError::new("fixture child mapped nothing"));
        }
        // Readiness verified: transfer custody to the target guard.
        guard.disarm();
        Ok(Self {
            kind: TargetKind::Mapping {
                pid,
                range: (addr, addr + len),
                mapped_len: len as usize,
                cmd,
                out,
            },
        })
    }

    /// NEW: a shell that acknowledges readiness, then execs `sleep` on
    /// [`OwnedTarget::trigger_exec`]. Birth is preserved across the
    /// exec while the address space is replaced.
    pub fn exec_transition() -> Result<Self, TargetError> {
        // R27: kill/reap custody from spawn on; every error return
        // below drops the guard, which retires the child (`Child`
        // itself neither kills nor reaps on drop).
        let mut guard = SpawnGuard(Some(
            Command::new("sh")
                .args(["-c", "printf 'ready\\n'; read -r line; exec sleep 300"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| TargetError::new(format!("fixture spawn: {e}")))?,
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        let child = guard.0.as_mut().expect("spawn guard armed");
        let mut output = child
            .stdout
            .take()
            .ok_or_else(|| TargetError::new("fixture has no readiness pipe"))?;
        await_ready(&mut output, deadline)?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| TargetError::new("fixture has no command pipe"))?;
        // Readiness verified: transfer custody to the target guard.
        let child = guard.take().expect("spawn guard armed");
        Ok(Self {
            kind: TargetKind::Exec { child, stdin },
        })
    }

    /// Command the exec-transition target to replace itself with sleep.
    pub fn trigger_exec(&mut self) {
        if let TargetKind::Exec { stdin, .. } = &mut self.kind {
            let _ = stdin.write_all(b"go\n");
            let _ = stdin.flush();
        }
    }

    /// Poll `/proc/<pid>/exe` until its file name is `expect`.
    /// Returns the observed link: the exe switch is the exec barrier.
    /// R05: an unrepresentable timeout is a typed refusal, never an
    /// `Instant + Duration` panic.
    pub fn wait_exe(&self, expect: &str, timeout: Duration) -> Result<String, TargetError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| TargetError::new("fixture exe timeout overflows deadline"))?;
        loop {
            let link = std::fs::read_link(format!("/proc/{}/exe", self.pid())).ok();
            let name = link
                .as_ref()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if name == expect {
                return Ok(link.map(|p| p.display().to_string()).unwrap_or_default());
            }
            if Instant::now() >= deadline {
                return Ok(name);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    pub fn pid(&self) -> u32 {
        match &self.kind {
            TargetKind::Stopped { child } => child.id(),
            TargetKind::Mapping { pid, .. } => *pid as u32,
            TargetKind::Exec { child, .. } => child.id(),
        }
    }

    /// F05: the child's mapped range. Only mapping targets have one;
    /// stopped/exec targets report `None` instead of panicking.
    pub fn range(&self) -> Option<(u64, u64)> {
        match &self.kind {
            TargetKind::Mapping { range, .. } => Some(*range),
            TargetKind::Stopped { .. } | TargetKind::Exec { .. } => None,
        }
    }

    /// Ask a mapping target to report its own mapped bytes.
    pub fn sample(&self) -> Result<Vec<u8>, TargetError> {
        let TargetKind::Mapping {
            mapped_len,
            cmd,
            out,
            ..
        } = &self.kind
        else {
            return Err(TargetError::new("only mapping targets sample"));
        };
        // Raw syscalls on the borrowed pipes; no handle duplication.
        let cmd_fd = cmd.as_raw_fd();
        let mut reply = vec![0u8; *mapped_len];
        // SAFETY: one command byte to the owned command pipe.
        let wrote = unsafe { libc::write(cmd_fd, b"s".as_ptr() as *const _, 1) };
        if wrote != 1 {
            return Err(TargetError::new("fixture sample command refused"));
        }
        let out_fd = out.as_raw_fd();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut filled = 0;
        while filled < reply.len() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(TargetError::new("fixture sample deadline expired"));
            }
            let ready = poll_fd(out_fd, remaining)
                .map_err(|e| TargetError::new(format!("fixture poll: {e}")))?;
            if !ready {
                return Err(TargetError::new("fixture sample deadline expired"));
            }
            // SAFETY: one bounded read into owned spare capacity.
            let got = unsafe {
                libc::read(
                    out_fd,
                    reply.as_mut_ptr().add(filled) as *mut _,
                    (reply.len() - filled) as libc::size_t,
                )
            };
            if got < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(TargetError::new(format!("fixture sample: {error}")));
            }
            if got == 0 {
                return Err(TargetError::new("fixture closed its sample pipe"));
            }
            filled += got as usize;
        }
        Ok(reply)
    }
}

impl Drop for OwnedTarget {
    /// PORT P test_subject.rs:97-104 custody: SIGKILL plus reap for
    /// every variant, errors swallowed (Drop must not panic).
    fn drop(&mut self) {
        match &mut self.kind {
            TargetKind::Stopped { child } | TargetKind::Exec { child, .. } => {
                let _ = child.kill();
                let _ = child.wait();
            }
            TargetKind::Mapping { pid, cmd, .. } => {
                // Ask politely, then insist; always reap.
                let _ = cmd.write_all(b"x\n");
                // SAFETY: signal an owned child.
                unsafe { libc::kill(*pid, libc::SIGKILL) };
                let _ = wait_pid_exited(*pid, Duration::from_secs(5));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R05: an unrepresentable poll timeout is a typed refusal, not
    /// an `Instant + Duration` panic. The bogus fd is never touched:
    /// the deadline check fires first.
    #[test]
    fn poll_fd_refuses_overflowing_timeout() {
        let err = poll_fd(-1, Duration::MAX).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            format!("{err}").contains("overflow"),
            "refusal must name the overflow: {err}"
        );
    }

    /// R05: same overflow refusal for the reap-poll helper. The
    /// unallocated pid is never waited on.
    #[test]
    fn wait_pid_exited_refuses_overflowing_timeout() {
        let err = wait_pid_exited(999_999_937, Duration::MAX).unwrap_err();
        assert!(
            format!("{err}").contains("overflow"),
            "refusal must name the overflow: {err}"
        );
    }

    /// R05: `wait_exe` refuses an unrepresentable timeout instead of
    /// panicking. Any live target serves: the check fires first.
    #[test]
    fn wait_exe_refuses_overflowing_timeout() {
        let target = OwnedTarget::stopped().expect("stopped target");
        let err = target.wait_exe("sleep", Duration::MAX).unwrap_err();
        assert!(
            format!("{err}").contains("overflow"),
            "refusal must name the overflow: {err}"
        );
    }

    fn pipe_pair() -> (File, File) {
        let mut ends = [0; 2];
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        // SAFETY: pipe() just reported success; both ends are ours.
        unsafe { (File::from_raw_fd(ends[0]), File::from_raw_fd(ends[1])) }
    }

    /// R27: `await_ready` distinguishes silent, partial, malformed
    /// and exact acknowledgements over a real pipe.
    #[test]
    fn await_ready_classifies_silent_partial_malformed() {
        let (mut read, mut write) = pipe_pair();
        write.write_all(b"ready\n").unwrap();
        await_ready(&mut read, Instant::now() + Duration::from_secs(5)).expect("exact acks");
        let (mut read, mut write) = pipe_pair();
        write.write_all(b"bogus\n").unwrap();
        let err = await_ready(&mut read, Instant::now() + Duration::from_secs(5)).unwrap_err();
        assert!(
            format!("{err}").contains("unexpected"),
            "malformed must name itself: {err}"
        );
        // Silent: writer open, no bytes, short deadline.
        let (mut read, _write) = pipe_pair();
        let err = await_ready(&mut read, Instant::now() + Duration::from_millis(100)).unwrap_err();
        assert!(
            format!("{err}").contains("deadline expired"),
            "silent must expire: {err}"
        );
        // Partial: three bytes, then silence.
        let (mut read, mut write) = pipe_pair();
        write.write_all(b"rea").unwrap();
        let err = await_ready(&mut read, Instant::now() + Duration::from_millis(100)).unwrap_err();
        assert!(
            format!("{err}").contains("deadline expired"),
            "partial must expire: {err}"
        );
    }

    /// R27: `read_exact_deadline` reports silence, EOF (bare or
    /// after a prefix) and success distinctly.
    #[test]
    fn read_exact_deadline_classifies_pipe_fates() {
        let (mut read, mut write) = pipe_pair();
        write.write_all(b"ready\n").unwrap();
        let mut line = [0u8; 6];
        read_exact_deadline(
            &mut read,
            &mut line,
            Instant::now() + Duration::from_secs(5),
        )
        .expect("exact reads");
        assert_eq!(&line, b"ready\n");
        // Bare EOF: writer dropped, no bytes.
        let (mut read, write) = pipe_pair();
        drop(write);
        let mut line = [0u8; 6];
        let err = read_exact_deadline(
            &mut read,
            &mut line,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains("closed its pipe"),
            "bare EOF: {err}"
        );
        // Prefix then EOF.
        let (mut read, mut write) = pipe_pair();
        write.write_all(b"rea").unwrap();
        drop(write);
        let mut line = [0u8; 6];
        let err = read_exact_deadline(
            &mut read,
            &mut line,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains("closed its pipe"),
            "prefix EOF: {err}"
        );
        // Silent: writer open, short deadline.
        let (mut read, _write) = pipe_pair();
        let mut line = [0u8; 6];
        let err = read_exact_deadline(
            &mut read,
            &mut line,
            Instant::now() + Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains("deadline expired"),
            "silent: {err}"
        );
    }

    /// R27: `SpawnGuard` kills and fully reaps a live child when
    /// construction fails (no strand, no zombie).
    #[test]
    fn spawn_guard_retires_live_child() {
        let child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("sleep spawns");
        let pid = child.id();
        drop(SpawnGuard(Some(child)));
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "spawn guard left {pid} alive or zombie"
        );
    }

    /// R27: `ChildGuard` kills and fully reaps a live raw pid when
    /// construction fails.
    #[test]
    fn child_guard_retires_live_pid() {
        let child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("sleep spawns");
        let pid = child.id() as libc::pid_t;
        // Custody passes to the guard alone.
        std::mem::forget(child);
        drop(ChildGuard::armed(pid));
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "child guard left {pid} alive or zombie"
        );
    }
}
