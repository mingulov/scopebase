// SPDX-License-Identifier: Apache-2.0
//! TT04 FS10 audit subject: run one production NoNew mapping
//! observation in a traceable child process, optionally planting a
//! transient target-backed mmap violation.
//!
//! Usage: scopebase-tt04-audit-subject observe --target PATH --pid PID
//!   --range START-END [--plant-violation] --report PATH
//!   scopebase-tt04-audit-subject thread-plant --target PATH --report PATH
//!   scopebase-tt04-audit-subject fork-exec-survivor --signal PATH
//!   scopebase-tt04-audit-subject nondumpable-map --target PATH --report PATH
//!   scopebase-tt04-audit-subject trap-ack --report PATH
//!   scopebase-tt04-audit-subject mremap-anon --report PATH
//!   scopebase-tt04-audit-subject mremap-file --target PATH --report PATH
//!   scopebase-tt04-audit-subject nonleader-exec --target PATH --report PATH
//!   (self-execs post-exec-map --target PATH --report PATH on a worker)
//!
//! Exit 0 after writing `verdict=...` to the report for every completed
//! observation (any production outcome, including MappingFailure,
//! counts as observed); exit 2 on usage/setup errors. NEW per the
//! frozen FS10 design; the traced phase is the real production
//! `observe_mapping`, never a model.
//!
//! F15: `thread-plant` maps one target page transiently from a worker
//! thread (the main thread never touches the target), proving the
//! tracer follows threads. Writes `worker=0` and exits 0.
//!
//! R25: `fork-exec-survivor` forks a child that sleeps 200ms, writes
//! `hi` to the signal file and exits, while the parent immediately
//! execs `true`: the child is live across the parent's exec, so a
//! tracer that forgets it returns before the signal lands.
//!
//! R28: `nondumpable-map` clears its own dumpability, then maps one
//! target page transiently: fd and maps identity reads deny even to
//! the same-uid tracer, so the success is unattributable. Writes
//! `mapped=ok` and exits 0, proving the map really happened.
//!
//! R30: `trap-ack` installs a SIGTRAP handler that writes `trapped`
//! to the report, raises SIGTRAP once, and exits 0: a tracer that
//! swallows genuine traps leaves the report empty.
//!
//! S30: `mremap-anon` grows one anonymous page to two with
//! MREMAP_MAYMOVE (ordinary allocator activity the audit must
//! classify anonymous, never unattributed); `mremap-file` grows one
//! target-backed page to two (the file identity must survive the
//! remap). Both write `mremapped=ok` and exit 0.
//!
//! S06: `nonleader-exec` spawns a worker that execs this same binary
//! as `post-exec-map`, which maps one target page transiently and
//! writes `mapped=ok`. The main thread is killed by the exec, so a
//! tracer that keeps the old leader's syscall phase inverts every
//! post-exec classification. `leader-exec` is the same map after a
//! plain leader exec (no renumber): the self-synchronization must
//! hold on both paths.
use scopebase_linux::{
    control::OperationControl,
    file::{HeldFile, ProcFdResolver, SymlinkPolicy},
    mapping::{
        MapRange, MappingLimits, MappingOutcome, MappingPolicy, MappingPool, MappingPoolLimits,
        MappingRequest,
    },
    process::{ObserverEpoch, Pid, ProcLimits, ProcessObservation},
    procfs::ParseLimits,
};
use scopebase_testkit::cli;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

fn usage() -> ! {
    // R04: usage goes through the fallible writer; a dead stderr
    // still exits 2 without a second panic.
    cli::err_line(
        "usage: scopebase-tt04-audit-subject observe --target PATH --pid PID \
         --range START-END [--plant-violation] --report PATH | \
         thread-plant --target PATH --report PATH | \
         fork-exec-survivor --signal PATH --marker PATH | \
         exec-marker --file PATH | \
         nondumpable-map --target PATH --report PATH | \
         trap-ack --report PATH | \
         mremap-anon --report PATH | \
         mremap-file --target PATH --report PATH | \
         nonleader-exec --target PATH --report PATH | \
         leader-exec --target PATH --report PATH | \
         post-exec-map --target PATH --report PATH",
    );
    std::process::exit(2);
}

fn flag_value(argv: &[String], name: &str) -> Option<String> {
    argv.windows(2).find_map(|pair| {
        if pair[0] == name {
            Some(pair[1].clone())
        } else {
            None
        }
    })
}

/// F15: map one target page transiently on a worker thread.
/// Returns the worker's exit status (0 clean; 10/11/12 worker body
/// failures; 13 join failure; R06: 14 NUL in target, 15 spawn
/// refused). Every nonzero code exits 2 from main: setup failure,
/// never a panic.
fn thread_plant(target: &str) -> i32 {
    let path = match std::ffi::CString::new(target) {
        Ok(path) => path,
        Err(_) => return 14,
    };
    let worker = match std::thread::Builder::new()
        .name("plant-worker".to_string())
        .spawn(move || {
            // SAFETY: NUL-terminated admitted path; all results checked.
            // The main thread never touches the target: every
            // target-backed mmap below belongs to this worker.
            unsafe {
                let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
                if fd < 0 {
                    return 10;
                }
                let addr = libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    fd,
                    0,
                );
                if addr == libc::MAP_FAILED {
                    libc::close(fd);
                    return 11;
                }
                let _ = (addr as *const u8).read_volatile();
                if libc::munmap(addr, 4096) != 0 {
                    libc::close(fd);
                    return 12;
                }
                libc::close(fd);
            }
            0
        }) {
        Ok(worker) => worker,
        // R06: EAGAIN/denied spawn is a setup error, not a panic.
        Err(_) => return 15,
    };
    worker.join().unwrap_or(13)
}

/// S47: the post-exec leg of the survivor rendezvous. Create the
/// marker file and exit 0. The marker proves the tracer processed
/// the parent's exec event: a ptraced exec stops the tracee, so no
/// post-exec byte runs before the tracer resumes it. Codes mirror
/// `thread_plant` (14 NUL, 10 open, 11 write, 12 close).
fn exec_marker(file: &str) -> i32 {
    let path = match std::ffi::CString::new(file) {
        Ok(path) => path,
        Err(_) => return 14,
    };
    // SAFETY: NUL-terminated admitted path; all results checked.
    unsafe {
        let fd = libc::open(
            path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if fd < 0 {
            return 10;
        }
        let msg = b"exec\n";
        if libc::write(fd, msg.as_ptr() as *const _, msg.len()) < 0 {
            libc::close(fd);
            return 11;
        }
        if libc::close(fd) != 0 {
            return 12;
        }
    }
    0
}

/// R25/S47: fork a signalling child, then exec the marker leg in the
/// parent. The child (syscalls only after fork) polls for the
/// marker — which exists only after the tracer processed the
/// parent's exec — then stops itself, writes `hi` to the signal
/// file once resumed, and exits 0. The stop is the discrimination:
/// a tracer that pruned the child at exec never resumes it, so the
/// signal never lands; a tracer that tracks it resumes the
/// group-stop and the write follows. Bounded: 5ms polls for at most
/// 30s, then `_exit(2)`. Diverges: the parent image is replaced,
/// the child `_exit`s; exit 2 on setup failure.
fn fork_exec_survivor(signal: &str, marker: &str) -> ! {
    let path = match std::ffi::CString::new(signal) {
        Ok(path) => path,
        Err(_) => std::process::exit(2),
    };
    let gate = match std::ffi::CString::new(marker) {
        Ok(path) => path,
        Err(_) => std::process::exit(2),
    };
    // S47: re-exec through the kernel's own link, so no argv or
    // current-dir lookup can divert the post-exec leg.
    let exe = c"/proc/self/exe";
    // SAFETY: single-threaded here; the child runs syscalls only.
    let forked = unsafe { libc::fork() };
    if forked < 0 {
        cli::err_line("audit subject setup failed at fork");
        std::process::exit(2);
    }
    if forked == 0 {
        // SAFETY: raw syscalls on stack memory only, then _exit. No
        // allocation, no locks: every path below is open, nanosleep,
        // raise (getpid + kill), write, close, _exit.
        unsafe {
            let tick = libc::timespec {
                tv_sec: 0,
                tv_nsec: 5_000_000,
            };
            let mut waited = 0;
            loop {
                let probe = libc::open(gate.as_ptr(), libc::O_RDONLY);
                if probe >= 0 {
                    libc::close(probe);
                    break;
                }
                waited += 1;
                if waited >= 6_000 {
                    libc::_exit(2);
                }
                libc::nanosleep(&tick, std::ptr::null_mut());
            }
            // The marker proves the tracer processed the exec (and
            // any pruning ran): stop until the tracer resumes us.
            libc::raise(libc::SIGSTOP);
            let fd = libc::open(
                path.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            );
            if fd >= 0 {
                let msg = b"hi\n";
                libc::write(fd, msg.as_ptr() as *const _, msg.len());
                libc::close(fd);
            }
            libc::_exit(0);
        }
    }
    // Parent: replace the image with the marker leg at once; the
    // child is polling for the file this image writes.
    let argv0 = exe.as_ptr();
    let mode = c"exec-marker".as_ptr();
    let flag = c"--file".as_ptr();
    // SAFETY: NUL-terminated argv; returns only on failure.
    unsafe {
        libc::execv(
            exe.as_ptr(),
            [argv0, mode, flag, gate.as_ptr(), std::ptr::null()].as_ptr(),
        );
    }
    cli::err_line("audit subject setup failed at exec");
    std::process::exit(2);
}

/// R28: clear dumpability, then map one target page transiently.
/// Exit codes mirror `thread_plant` (14 NUL, 10/11/12 map stages,
/// 16 prctl refused).
fn nondumpable_map(target: &str) -> i32 {
    let path = match std::ffi::CString::new(target) {
        Ok(path) => path,
        Err(_) => return 14,
    };
    // SAFETY: raw syscalls with checked results, like the plant leg.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return 16;
        }
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            return 10;
        }
        let addr = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            0,
        );
        if addr == libc::MAP_FAILED {
            libc::close(fd);
            return 11;
        }
        let _ = (addr as *const u8).read_volatile();
        if libc::munmap(addr, 4096) != 0 {
            libc::close(fd);
            return 12;
        }
        libc::close(fd);
    }
    0
}

/// R30: report fd for the SIGTRAP handler. Written before the
/// handler is installed and only read by it; atomic so the
/// handler stays async-signal-safe without locking.
static TRAP_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn trap_handler(_signal: libc::c_int) {
    // SAFETY: async-signal-safe write of a fixed message.
    unsafe {
        let msg = b"trapped\n";
        libc::write(
            TRAP_FD.load(Ordering::Relaxed),
            msg.as_ptr() as *const _,
            msg.len(),
        );
    }
}

/// R30: install a SIGTRAP handler that acknowledges to the report,
/// raise SIGTRAP once, and return 0. Exit codes mirror
/// `thread_plant` (14 NUL, 10 report open, 17 sigaction refused).
fn trap_ack(report: &str) -> i32 {
    let path = match std::ffi::CString::new(report) {
        Ok(path) => path,
        Err(_) => return 14,
    };
    // SAFETY: raw syscalls with checked results.
    unsafe {
        let fd = libc::open(
            path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if fd < 0 {
            return 10;
        }
        TRAP_FD.store(fd, Ordering::Relaxed);
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = trap_handler as *const () as usize;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGTRAP, &action, std::ptr::null_mut()) != 0 {
            libc::close(fd);
            return 17;
        }
        libc::raise(libc::SIGTRAP);
        libc::close(fd);
    }
    0
}

/// S30: grow one anonymous page to two. Exit codes mirror
/// `thread_plant` (10 mmap, 11 mremap, 12 munmap, 13 content lost).
fn mremap_anon() -> i32 {
    // SAFETY: raw syscalls with checked results.
    unsafe {
        let addr = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if addr == libc::MAP_FAILED {
            return 10;
        }
        (addr as *mut u8).write_volatile(0xA5);
        let grown = libc::mremap(addr, 4096, 8192, libc::MREMAP_MAYMOVE);
        if grown == libc::MAP_FAILED {
            libc::munmap(addr, 4096);
            return 11;
        }
        if (grown as *const u8).read_volatile() != 0xA5 {
            libc::munmap(grown, 8192);
            return 13;
        }
        if libc::munmap(grown, 8192) != 0 {
            return 12;
        }
    }
    0
}

/// S30: grow one target-backed page to two (the target must hold at
/// least two pages). Exit codes: 14 NUL, 10 open, 11 mmap, 12
/// mremap, 13 munmap.
fn mremap_file(target: &str) -> i32 {
    let path = match std::ffi::CString::new(target) {
        Ok(path) => path,
        Err(_) => return 14,
    };
    // SAFETY: NUL-terminated admitted path; all results checked.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            return 10;
        }
        let addr = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            0,
        );
        if addr == libc::MAP_FAILED {
            libc::close(fd);
            return 11;
        }
        let _ = (addr as *const u8).read_volatile();
        let grown = libc::mremap(addr, 4096, 8192, libc::MREMAP_MAYMOVE);
        if grown == libc::MAP_FAILED {
            libc::munmap(addr, 4096);
            libc::close(fd);
            return 12;
        }
        let _ = (grown as *const u8).add(4096).read_volatile();
        if libc::munmap(grown, 8192) != 0 {
            libc::close(fd);
            return 13;
        }
        libc::close(fd);
    }
    0
}

/// S06: map one target page transiently after a non-leader exec.
/// Exit codes mirror `thread_plant` (14 NUL, 10/11/12 map stages).
fn post_exec_map(target: &str) -> i32 {
    let path = match std::ffi::CString::new(target) {
        Ok(path) => path,
        Err(_) => return 14,
    };
    // SAFETY: NUL-terminated admitted path; all results checked.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            return 10;
        }
        let addr = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            0,
        );
        if addr == libc::MAP_FAILED {
            libc::close(fd);
            return 11;
        }
        let _ = (addr as *const u8).read_volatile();
        if libc::munmap(addr, 4096) != 0 {
            libc::close(fd);
            return 12;
        }
        libc::close(fd);
    }
    0
}

/// S06: spawn a worker that execs this binary as `post-exec-map`.
/// Diverges: the exec kills the calling thread, so returning means
/// setup failure (exit 2). Exit codes: 14 NUL, 15 spawn refused,
/// 18 exec refused, 19 self-exe resolution.
///
/// S06-round3: the leader spins in USERSPACE (no syscalls at all —
/// not even a clock read) while the worker execs. The counterexample
/// needs the old leader's tracer phase to be userspace when the
/// renumber lands: the former `recv_timeout` parked the leader
/// inside a futex wait, whose in-syscall phase accidentally matched
/// the exec-exit stop and let phase-preserving code pass. Ordering
/// is by atomics, not timing: the worker execs only after observing
/// SPINNING, which the leader stores after its last syscall (the
/// clone) has exited.
fn nonleader_exec(target: &str, report: &str) -> ! {
    use std::os::unix::ffi::OsStrExt as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    // S06-round3 handshake states (see above).
    const STARTING: usize = 0;
    const SPINNING: usize = 1;
    const FAILED: usize = 2;
    // Iteration bound for both spins (no clock syscalls): ~10s on a
    // modern core; the 60s audit timeout backstops pathological
    // hardware. Every exit below is loud (exit 2).
    const SPIN_ITERS: u64 = 3_000_000_000;
    let target = target.to_owned();
    let report = report.to_owned();
    let exe = match std::env::current_exe()
        .ok()
        .and_then(|path| std::ffi::CString::new(path.as_os_str().as_bytes()).ok())
    {
        Some(exe) => exe,
        None => std::process::exit(2),
    };
    let state = std::sync::Arc::new(AtomicUsize::new(STARTING));
    let worker_state = state.clone();
    let spawned = std::thread::Builder::new()
        .name("exec-worker".to_string())
        .spawn(move || {
            let mut spins: u64 = 0;
            while worker_state.load(Ordering::Acquire) == STARTING {
                spins += 1;
                if spins >= SPIN_ITERS {
                    std::process::exit(2);
                }
                std::hint::spin_loop();
            }
            if worker_state.load(Ordering::Acquire) == FAILED {
                std::process::exit(2);
            }
            let target = std::ffi::CString::new(target).unwrap_or_else(|_| std::process::exit(2));
            let report = std::ffi::CString::new(report).unwrap_or_else(|_| std::process::exit(2));
            let argv = [
                exe.as_ptr(),
                c"post-exec-map".as_ptr(),
                c"--target".as_ptr(),
                target.as_ptr(),
                c"--report".as_ptr(),
                report.as_ptr(),
                std::ptr::null(),
            ];
            // SAFETY: NUL-terminated argv; returns only on failure.
            unsafe {
                libc::execvp(exe.as_ptr(), argv.as_ptr());
            }
            worker_state.store(FAILED, Ordering::Release);
            // Park: the leader's bounded spin reports the failure.
            loop {
                std::thread::park();
            }
        });
    if spawned.is_err() {
        std::process::exit(2);
    }
    state.store(SPINNING, Ordering::Release);
    // The exec kills this thread. Userspace only: a flag check per
    // 4096 pause iterations, zero syscalls, so the tracer phase at
    // the renumber is provably userspace on every schedule.
    let mut spins: u64 = 0;
    loop {
        spins += 1;
        if spins % 4096 == 0 && state.load(Ordering::Acquire) == FAILED {
            break;
        }
        if spins >= SPIN_ITERS {
            break;
        }
        std::hint::spin_loop();
    }
    cli::err_line("audit subject setup failed at nonleader exec");
    std::process::exit(2);
}

/// S06: exec this binary as `post-exec-map` on the leader.
/// Diverges on success; exit 2 when the self-exe path or the exec
/// itself refuses.
fn leader_exec(target: &str, report: &str) -> ! {
    use std::os::unix::ffi::OsStrExt as _;
    let exe = std::env::current_exe()
        .ok()
        .and_then(|path| std::ffi::CString::new(path.as_os_str().as_bytes()).ok());
    let target = std::ffi::CString::new(target).ok();
    let report = std::ffi::CString::new(report).ok();
    let (Some(exe), Some(target), Some(report)) = (exe, target, report) else {
        cli::err_line("audit subject setup failed at leader exec argv");
        std::process::exit(2);
    };
    let argv = [
        exe.as_ptr(),
        c"post-exec-map".as_ptr(),
        c"--target".as_ptr(),
        target.as_ptr(),
        c"--report".as_ptr(),
        report.as_ptr(),
        std::ptr::null(),
    ];
    // SAFETY: NUL-terminated argv; returns only on failure.
    unsafe {
        libc::execvp(exe.as_ptr(), argv.as_ptr());
    }
    cli::err_line("audit subject setup failed at leader exec");
    std::process::exit(2);
}

fn main() {
    // R03: non-UTF-8 argv refuses with usage, never panics in args().
    let argv = match cli::argv_strings() {
        Some(argv) => argv,
        None => {
            cli::err_line("argv is not valid Unicode");
            usage();
        }
    };
    if argv.len() < 2 {
        usage();
    }
    if argv[1] == "thread-plant" {
        let target = flag_value(&argv, "--target").unwrap_or_else(|| usage());
        let report = flag_value(&argv, "--report").unwrap_or_else(|| usage());
        let code = thread_plant(&target);
        std::fs::write(&report, format!("worker={code}\n")).unwrap_or_else(|_| {
            cli::err_line("audit subject setup failed at report");
            std::process::exit(2);
        });
        std::process::exit(if code == 0 { 0 } else { 2 });
    }
    if argv[1] == "fork-exec-survivor" {
        let signal = flag_value(&argv, "--signal").unwrap_or_else(|| usage());
        let marker = flag_value(&argv, "--marker").unwrap_or_else(|| usage());
        fork_exec_survivor(&signal, &marker);
    }
    if argv[1] == "exec-marker" {
        let file = flag_value(&argv, "--file").unwrap_or_else(|| usage());
        let code = exec_marker(&file);
        std::process::exit(if code == 0 { 0 } else { 2 });
    }
    if argv[1] == "nondumpable-map" {
        let target = flag_value(&argv, "--target").unwrap_or_else(|| usage());
        let report = flag_value(&argv, "--report").unwrap_or_else(|| usage());
        let code = nondumpable_map(&target);
        std::fs::write(&report, format!("mapped={code}\n")).unwrap_or_else(|_| {
            cli::err_line("audit subject setup failed at report");
            std::process::exit(2);
        });
        std::process::exit(if code == 0 { 0 } else { 2 });
    }
    if argv[1] == "trap-ack" {
        let report = flag_value(&argv, "--report").unwrap_or_else(|| usage());
        let code = trap_ack(&report);
        std::process::exit(if code == 0 { 0 } else { 2 });
    }
    if argv[1] == "mremap-anon" {
        let report = flag_value(&argv, "--report").unwrap_or_else(|| usage());
        let code = mremap_anon();
        std::fs::write(&report, format!("mremapped={code}\n")).unwrap_or_else(|_| {
            cli::err_line("audit subject setup failed at report");
            std::process::exit(2);
        });
        std::process::exit(if code == 0 { 0 } else { 2 });
    }
    if argv[1] == "mremap-file" {
        let target = flag_value(&argv, "--target").unwrap_or_else(|| usage());
        let report = flag_value(&argv, "--report").unwrap_or_else(|| usage());
        let code = mremap_file(&target);
        std::fs::write(&report, format!("mremapped={code}\n")).unwrap_or_else(|_| {
            cli::err_line("audit subject setup failed at report");
            std::process::exit(2);
        });
        std::process::exit(if code == 0 { 0 } else { 2 });
    }
    if argv[1] == "nonleader-exec" {
        let target = flag_value(&argv, "--target").unwrap_or_else(|| usage());
        let report = flag_value(&argv, "--report").unwrap_or_else(|| usage());
        nonleader_exec(&target, &report);
    }
    if argv[1] == "leader-exec" {
        let target = flag_value(&argv, "--target").unwrap_or_else(|| usage());
        let report = flag_value(&argv, "--report").unwrap_or_else(|| usage());
        leader_exec(&target, &report);
    }
    if argv[1] == "post-exec-map" {
        let target = flag_value(&argv, "--target").unwrap_or_else(|| usage());
        let report = flag_value(&argv, "--report").unwrap_or_else(|| usage());
        let code = post_exec_map(&target);
        std::fs::write(&report, format!("mapped={code}\n")).unwrap_or_else(|_| {
            cli::err_line("audit subject setup failed at report");
            std::process::exit(2);
        });
        std::process::exit(if code == 0 { 0 } else { 2 });
    }
    if argv[1] != "observe" {
        usage();
    }
    let target = flag_value(&argv, "--target").unwrap_or_else(|| usage());
    let pid_text = flag_value(&argv, "--pid").unwrap_or_else(|| usage());
    let range_text = flag_value(&argv, "--range").unwrap_or_else(|| usage());
    let report = flag_value(&argv, "--report").unwrap_or_else(|| usage());
    let plant = argv.iter().any(|a| a == "--plant-violation");
    let pid: i32 = pid_text.parse().unwrap_or_else(|_| usage());
    let (start_text, end_text) = range_text.split_once('-').unwrap_or_else(|| usage());
    let start = u64::from_str_radix(start_text.trim(), 16).unwrap_or_else(|_| usage());
    let end = u64::from_str_radix(end_text.trim(), 16).unwrap_or_else(|_| usage());

    let control = OperationControl::unlimited();
    let proc = ProcLimits {
        parse: ParseLimits {
            max_bytes: 1 << 20,
            max_entries: 1 << 16,
            max_line_bytes: 1 << 16,
        },
        max_read_calls: 4096,
        max_metadata_bytes: 1 << 20,
    };
    let setup_fail = |stage: &str| -> ! {
        cli::err_line(&format!("audit subject setup failed at {stage}"));
        std::process::exit(2);
    };
    let resolver = ProcFdResolver::open_self().unwrap_or_else(|_| setup_fail("resolver"));
    let held = Arc::new(
        HeldFile::open(
            PathBuf::from(&target).as_path(),
            &resolver,
            SymlinkPolicy::Follow,
        )
        .unwrap_or_else(|_| setup_fail("hold")),
    );
    let epoch = ObserverEpoch::new(proc, &control).unwrap_or_else(|_| setup_fail("epoch"));
    let pid = Pid::new(pid).unwrap_or_else(|| setup_fail("pid"));
    let obs = ProcessObservation::acquire(pid, &epoch, proc, &control)
        .unwrap_or_else(|_| setup_fail("acquire"));
    let range = MapRange::new(start, end).unwrap_or_else(|_| setup_fail("range"));
    let pool = MappingPool::new(MappingPoolLimits {
        max_mappings: 0,
        max_mapped_bytes: 0,
    })
    .unwrap_or_else(|_| setup_fail("pool"));
    let outcome = scopebase_linux::mapping::observe_mapping(
        MappingRequest {
            pool: &pool,
            held: Arc::clone(&held),
            process: &obs,
            range,
            policy: MappingPolicy::NoNewTargetMappings,
            retained: None,
            limits: MappingLimits {
                proc,
                max_mount_refreshes: 1,
                max_open_fds: 1024,
                max_live_mappings: 0,
            },
        },
        &control,
    );
    let verdict = match &outcome {
        Ok(MappingOutcome::ExactRange(_)) => "verdict=ExactRange".to_string(),
        Ok(MappingOutcome::KeyCompatible(_)) => "verdict=KeyCompatible".to_string(),
        Ok(MappingOutcome::Mismatch(e)) => format!("verdict=Mismatch:{:?}", e.kind()),
        Ok(MappingOutcome::Inconclusive(r)) => {
            format!("verdict=Inconclusive:{:?}", r.kind())
        }
        Ok(other) => format!("verdict=Other:{other:?}"),
        Err(f) => format!("verdict=Failure:{:?}", f.error().reason()),
    };
    if plant {
        // The planted transient: one page of the TARGET file mapped
        // and immediately unmapped. The audit must attribute it by
        // (device, inode), not by pathname spelling.
        let path = std::ffi::CString::new(target.as_str()).unwrap_or_else(|_| setup_fail("path"));
        // SAFETY: NUL-terminated admitted path; all results checked.
        unsafe {
            let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
            if fd < 0 {
                setup_fail("plant-open");
            }
            let addr = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            );
            if addr == libc::MAP_FAILED {
                libc::close(fd);
                setup_fail("plant-mmap");
            }
            // Touch one byte so the map is real, then withdraw it.
            let _ = (addr as *const u8).read_volatile();
            if libc::munmap(addr, 4096) != 0 {
                libc::close(fd);
                setup_fail("plant-munmap");
            }
            libc::close(fd);
        }
    }
    std::fs::write(&report, format!("{verdict}\n")).unwrap_or_else(|_| setup_fail("report"));
}
