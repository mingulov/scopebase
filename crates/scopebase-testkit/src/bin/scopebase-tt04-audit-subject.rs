// SPDX-License-Identifier: Apache-2.0
//! TT04 FS10 audit subject: run one production NoNew mapping
//! observation in a traceable child process, optionally planting a
//! transient target-backed mmap violation.
//!
//! Usage: scopebase-tt04-audit-subject observe --target PATH --pid PID
//!   --range START-END [--plant-violation] --report PATH
//!
//! Exit 0 after writing `verdict=...` to the report for every completed
//! observation (any production outcome, including MappingFailure,
//! counts as observed); exit 2 on usage/setup errors. NEW per the
//! frozen FS10 design; the traced phase is the real production
//! `observe_mapping`, never a model.
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
use std::path::PathBuf;
use std::sync::Arc;

fn usage() -> ! {
    eprintln!(
        "usage: scopebase-tt04-audit-subject observe --target PATH --pid PID \
         --range START-END [--plant-violation] --report PATH"
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

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 || argv[1] != "observe" {
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
        eprintln!("audit subject setup failed at {stage}");
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
