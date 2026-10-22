// SPDX-License-Identifier: Apache-2.0
//! Test-only parent fault recorder. Postfork child uses raw async-safe calls only.
use std::{
    cell::RefCell,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
#[derive(Default)]
struct Faults {
    pipe_calls: usize,
    pipe_fail: usize,
    fork_fail: bool,
    handshake_fail: bool,
    wait_eintr: usize,
    wait_error: bool,
    live_fds: usize,
    waits: Vec<i32>,
    kills: Vec<i32>,
}
thread_local! {static STATE:RefCell<Faults>=RefCell::new(Faults::default());}
struct Pipe(OwnedFd);
impl AsRawFd for Pipe {
    fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}
impl Drop for Pipe {
    fn drop(&mut self) {
        STATE.with(|s| s.borrow_mut().live_fds -= 1);
    }
}
fn pipes() -> io::Result<[Pipe; 2]> {
    let fail = STATE.with(|s| {
        let mut s = s.borrow_mut();
        s.pipe_calls += 1;
        s.pipe_calls == s.pipe_fail
    });
    if fail {
        return Err(io::Error::from_raw_os_error(libc::EMFILE));
    }
    let mut p = [-1; 2];
    if unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful pipe2 returns two fresh owned descriptors; adopt before
    // any subsequent fallible acquisition or fork. Recorder is parent-only.
    let pair = unsafe {
        [
            Pipe(OwnedFd::from_raw_fd(p[0])),
            Pipe(OwnedFd::from_raw_fd(p[1])),
        ]
    };
    STATE.with(|s| s.borrow_mut().live_fds += 2);
    Ok(pair)
}
fn wait(pid: i32) -> io::Result<i32> {
    let fault = STATE.with(|s| {
        let mut s = s.borrow_mut();
        s.waits.push(pid);
        if s.wait_eintr > 0 {
            s.wait_eintr -= 1;
            Some(libc::EINTR)
        } else if s.wait_error {
            Some(libc::EIO)
        } else {
            None
        }
    });
    if let Some(n) = fault {
        return Err(io::Error::from_raw_os_error(n));
    }
    let mut status = 0;
    let n = unsafe { libc::waitpid(pid, &mut status, 0) };
    if n == pid {
        Ok(status)
    } else {
        Err(io::Error::last_os_error())
    }
}
pub struct Child {
    pub pid: i32,
    quit: Pipe,
    ready: Pipe,
    reaped: bool,
}
impl Child {
    pub fn start() -> Self {
        Self::try_start().expect("owned child setup")
    }
    fn try_start() -> io::Result<Self> {
        let [q_read, q_write] = pipes()?;
        let [r_read, r_write] = pipes()?;
        let q = [q_read.as_raw_fd(), q_write.as_raw_fd()];
        let r = [r_read.as_raw_fd(), r_write.as_raw_fd()];
        if STATE.with(|s| s.borrow().fork_fail) {
            return Err(io::Error::from_raw_os_error(libc::EAGAIN));
        }
        // SAFETY: this child branch never touches Rust/thread-local/allocator state.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            unsafe {
                libc::close(q[1]);
                libc::close(r[0]);
                let b = [1u8];
                if libc::write(r[1], b.as_ptr().cast(), 1) != 1 {
                    libc::_exit(91)
                }
                let mut stop = [0u8];
                if libc::read(q[0], stop.as_mut_ptr().cast(), 1) != 1 {
                    libc::_exit(92)
                }
                libc::_exit(0)
            }
        }
        // Parent establishes the exact child owner before fallible handshake work.
        drop(q_read);
        drop(r_write);
        let child = Self {
            pid,
            quit: q_write,
            ready: r_read,
            reaped: false,
        };
        if STATE.with(|s| s.borrow().handshake_fail) {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        let mut byte = [0];
        let n = unsafe { libc::read(child.ready.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
        if n != 1 || byte != [1] {
            return Err(io::Error::other("child ready handshake"));
        }
        Ok(child)
    }
    fn reap(&mut self) -> io::Result<i32> {
        for _ in 0..16 {
            match wait(self.pid) {
                Ok(status) => {
                    self.reaped = true;
                    return Ok(status);
                }
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other("bounded interrupted wait exhausted"))
    }
    fn try_finish(&mut self) -> io::Result<()> {
        if self.reaped {
            return Ok(());
        }
        let byte = [1u8];
        let n = unsafe { libc::write(self.quit.as_raw_fd(), byte.as_ptr().cast(), 1) };
        if n != 1 {
            return Err(io::Error::last_os_error());
        }
        let s = self.reap()?;
        if !libc::WIFEXITED(s) || libc::WEXITSTATUS(s) != 0 {
            return Err(io::Error::other(format!("child exit {s}")));
        }
        Ok(())
    }
    pub fn finish(&mut self) {
        self.try_finish().expect("owned child exit/reap");
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        STATE.with(|s| s.borrow_mut().kills.push(self.pid));
        let killed = unsafe { libc::kill(self.pid, libc::SIGKILL) };
        let e = if killed < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        let outcome = if killed == 0 || e == Some(libc::ESRCH) {
            self.reap().map(|_| ())
        } else {
            Err(io::Error::from_raw_os_error(e.unwrap_or(libc::EIO)))
        };
        if let Err(error) = outcome {
            eprintln!(
                "UNRESOLVED owned child custody pid={} kill_errno={e:?} wait={error}",
                self.pid
            );
            if !std::thread::panicking() {
                panic!("owned child retirement not confirmed");
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn reset() {
        STATE.with(|s| {
            assert_eq!(s.borrow().live_fds, 0);
            *s.borrow_mut() = Faults::default();
        });
    }
    #[test]
    fn parent_acquisition_faults_close_owned_pipes() {
        reset();
        STATE.with(|s| s.borrow_mut().pipe_fail = 2);
        assert!(Child::try_start().is_err());
        STATE.with(|s| assert_eq!(s.borrow().live_fds, 0));
        reset();
        STATE.with(|s| s.borrow_mut().fork_fail = true);
        assert!(Child::try_start().is_err());
        STATE.with(|s| assert_eq!(s.borrow().live_fds, 0));
        reset();
        STATE.with(|s| s.borrow_mut().handshake_fail = true);
        assert!(Child::try_start().is_err());
        STATE.with(|s| {
            let s = s.borrow();
            assert_eq!(s.live_fds, 0);
            assert_eq!(s.kills.len(), 1);
            assert_eq!(s.waits.last(), s.kills.last());
        });
        reset();
    }
    #[test]
    fn interrupted_wait_only_retires_after_exact_success() {
        reset();
        let mut child = Child::start();
        let pid = child.pid;
        STATE.with(|s| s.borrow_mut().wait_eintr = 1);
        assert!(!child.reaped);
        child.finish();
        assert!(child.reaped);
        STATE.with(|s| assert_eq!(s.borrow().waits, [pid, pid]));
        drop(child);
        reset();
    }
    #[test]
    fn unexpected_wait_retains_unresolved_owner() {
        reset();
        let mut child = Child::start();
        let pid = child.pid;
        STATE.with(|s| s.borrow_mut().wait_error = true);
        let e = child.try_finish().unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EIO));
        assert!(!child.reaped);
        STATE.with(|s| s.borrow_mut().wait_error = false);
        child.reap().unwrap();
        assert!(child.reaped);
        STATE.with(|s| assert!(s.borrow().waits.iter().all(|p| *p == pid)));
        drop(child);
        reset();
    }
}
