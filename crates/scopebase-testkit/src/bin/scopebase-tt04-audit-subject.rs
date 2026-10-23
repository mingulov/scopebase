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
         fork-exec-survivor --signal PATH | \
         nondumpable-map --target PATH --report PATH | \
         trap-ack --report PATH",
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

/// R25: fork a signalling child, then exec `true` in the parent.
/// The child (syscalls only after fork) naps 200ms, writes `hi` to
/// the signal file, and exits 0. Diverges: the parent image is
/// replaced, the child `_exit`s; exit 2 on setup failure.
fn fork_exec_survivor(signal: &str) -> ! {
    let path = match std::ffi::CString::new(signal) {
        Ok(path) => path,
        Err(_) => std::process::exit(2),
    };
    // SAFETY: single-threaded here; the child runs syscalls only.
    let forked = unsafe { libc::fork() };
    if forked < 0 {
        cli::err_line("audit subject setup failed at fork");
        std::process::exit(2);
    }
    if forked == 0 {
        // SAFETY: raw syscalls on stack memory only, then _exit.
        unsafe {
            let nap = libc::timespec {
                tv_sec: 0,
                tv_nsec: 200_000_000,
            };
            libc::nanosleep(&nap, std::ptr::null_mut());
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
    // Parent: replace the image at once; the child is mid-nap.
    let argv0 = c"true".as_ptr();
    // SAFETY: NUL-terminated argv; returns only on failure.
    unsafe {
        libc::execvp(c"true".as_ptr(), [argv0, std::ptr::null()].as_ptr());
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
        fork_exec_survivor(&signal);
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
