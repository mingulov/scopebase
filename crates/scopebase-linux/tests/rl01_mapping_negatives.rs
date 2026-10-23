// SPDX-License-Identifier: Apache-2.0
//! RL01 LX06 negatives: wrong-domain retained proofs and dropped controllers
//! with pending domains. LX06 is accepted, so these run here (not deferred).
//!
//! Real native populations only: the test process maps its own temp files and
//! observes itself through retained LX08 process observations.
#![cfg(feature = "mapping")]
use scopebase_linux::{
    control::OperationControl,
    error::Reason,
    file::{HeldFile, ProcFdResolver, SymlinkPolicy},
    mapping::{
        MapRange, MappingLimits, MappingOutcome, MappingPolicy, MappingPool, MappingPoolLimits,
        MappingRequest,
    },
    process::{ObserverEpoch, Pid, ProcLimits, ProcessObservation},
    procfs::ParseLimits,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn proc_limits() -> ProcLimits {
    ProcLimits {
        parse: ParseLimits {
            max_bytes: 1 << 20,
            max_entries: 1 << 16,
            max_line_bytes: 1 << 16,
        },
        max_read_calls: 4096,
        max_metadata_bytes: 1 << 20,
    }
}

fn mapping_limits() -> MappingLimits {
    MappingLimits {
        proc: proc_limits(),
        max_mount_refreshes: 1,
        max_open_fds: 1024,
        max_live_mappings: 0,
    }
}

fn control() -> OperationControl {
    OperationControl::unlimited()
}

fn epoch() -> ObserverEpoch {
    ObserverEpoch::new(proc_limits(), &control()).expect("epoch on own process")
}

fn me() -> Pid {
    Pid::new(std::process::id() as i32).unwrap()
}

fn no_new_pool() -> MappingPool {
    MappingPool::new(MappingPoolLimits {
        max_mappings: 0,
        max_mapped_bytes: 0,
    })
    .unwrap()
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempFile {
    path: std::path::PathBuf,
}

impl TempFile {
    fn create(size: usize) -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "rl01-lx06-{}-{}-{}.dat",
            std::process::id(),
            id,
            size
        ));
        let mut data = vec![0u8; size];
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = (index.wrapping_mul(31).wrapping_add(id as usize) % 251 + 1) as u8;
        }
        std::fs::write(&path, &data).expect("write temp file");
        Self { path }
    }

    fn hold(&self) -> Arc<HeldFile> {
        let resolver = ProcFdResolver::open_self().unwrap();
        Arc::new(HeldFile::open(&self.path, &resolver, SymlinkPolicy::Follow).unwrap())
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A test-owned private read-only mapping, munmapped on drop.
struct TestMapping {
    addr: *mut std::ffi::c_void,
    len: usize,
}

unsafe impl Send for TestMapping {}
unsafe impl Sync for TestMapping {}

impl TestMapping {
    fn map(file: &std::fs::File, len: usize) -> Self {
        let addr = unsafe {
            rustix::mm::mmap(
                std::ptr::null_mut(),
                len,
                rustix::mm::ProtFlags::READ,
                rustix::mm::MapFlags::PRIVATE,
                file,
                0,
            )
        }
        .expect("test mmap");
        Self { addr, len }
    }

    fn addr(&self) -> u64 {
        self.addr as u64
    }
}

impl Drop for TestMapping {
    fn drop(&mut self) {
        unsafe {
            let _ = rustix::mm::munmap(self.addr, self.len);
        }
    }
}

fn observe(
    pool: &MappingPool,
    held: &Arc<HeldFile>,
    process: &ProcessObservation,
    range: MapRange,
    retained: Option<&scopebase_linux::mapping::MappingProof>,
) -> Result<MappingOutcome, scopebase_linux::mapping::MappingFailure> {
    scopebase_linux::mapping::observe_mapping(
        MappingRequest {
            pool,
            held: Arc::clone(held),
            process,
            range,
            policy: MappingPolicy::NoNewTargetMappings,
            retained,
            limits: mapping_limits(),
        },
        &control(),
    )
}

fn proof_of(outcome: &MappingOutcome) -> scopebase_linux::mapping::MappingProof {
    match outcome {
        MappingOutcome::ExactRange(proof) => proof.proof().clone(),
        MappingOutcome::KeyCompatible(proof) => proof.clone(),
        outcome => panic!("expected a proof, got {outcome:?}"),
    }
}

/// RL01 LX06 negative 1: a retained proof is pool-independent. Pools are
/// explicit accounting domains, not proof authority, so reusing pool A's
/// proof under pool B (same held owner, process, range) must NOT refuse
/// with WrongContext. This locks the contract reading against a future
/// over-tightening that would confuse accounting with authority.
#[test]
fn retained_proof_reuse_ignores_pool_domain() {
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let file = std::fs::File::open(&temp.path).unwrap();
    let mapping = TestMapping::map(&file, rustix::param::page_size());
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps.snapshot().containing(mapping.addr()).unwrap();
    let range = MapRange::new(line.start(), line.end()).unwrap();

    let pool_a = no_new_pool();
    let issued = observe(&pool_a, &held, &process, range, None).expect("live mapping proves");
    let proof = proof_of(&issued);

    // Same held/process/range under the same pool and under an independent
    // pool domain: the pool leg must not change the recheck verdict. On
    // eligible filesystems reuse accepts; elsewhere (this container's /tmp
    // is btrfs) it refuses InvalidInput -- identically under both pools.
    let pool_b = no_new_pool();
    assert_ne!(pool_a.status().domain(), pool_b.status().domain());
    let under_a = observe(&pool_a, &held, &process, range, Some(&proof));
    let under_b = observe(&pool_b, &held, &process, range, Some(&proof));
    match (&under_a, &under_b) {
        (Ok(_), Ok(_)) => {
            assert!(
                proof.filesystem().retained_reuse_eligible(),
                "acceptance requires an eligible filesystem"
            );
        }
        (Err(a), Err(b)) => {
            assert_eq!(
                (a.error().reason(), b.error().reason()),
                (Reason::InvalidInput, Reason::InvalidInput),
                "ineligible reuse refuses identically under both pools"
            );
        }
        (a, b) => panic!("pool domain must not change the verdict: {a:?} vs {b:?}"),
    }

    pool_a.close(&control()).unwrap();
    pool_b.close(&control()).unwrap();
    drop(mapping);
}

/// RL01 LX06 negative 2: a same-pool, wrong-range proof refuses. This
/// isolates the range leg of the wrong-domain recheck from the pool leg
/// locked above: only the range differs, so WrongContext must come from
/// the range comparison.
#[test]
fn same_pool_wrong_range_proof_refuses() {
    // Coverage requires an exact rendered-line match, so the two ranges are
    // two separately mapped one-page temp files (never sub-ranges).
    let page = rustix::param::page_size();
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp_a = TempFile::create(page);
    let temp_b = TempFile::create(page);
    let held = temp_a.hold();
    let file_a = std::fs::File::open(&temp_a.path).unwrap();
    let file_b = std::fs::File::open(&temp_b.path).unwrap();
    let mapping_a = TestMapping::map(&file_a, page);
    let mapping_b = TestMapping::map(&file_b, page);
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line_a = maps.snapshot().containing(mapping_a.addr()).unwrap();
    let line_b = maps.snapshot().containing(mapping_b.addr()).unwrap();
    let first = MapRange::new(line_a.start(), line_a.end()).unwrap();
    let second = MapRange::new(line_b.start(), line_b.end()).unwrap();
    assert_ne!((first.start(), first.end()), (second.start(), second.end()));

    let pool = no_new_pool();
    let issued = observe(&pool, &held, &process, first, None).expect("live mapping proves");
    let proof = proof_of(&issued);

    // Only the range differs: the range leg refuses pre-effect with
    // WrongContext, ahead of the filesystem-eligibility leg.
    let failure = observe(&pool, &held, &process, second, Some(&proof))
        .expect_err("wrong-range proof must refuse");
    assert_eq!(failure.error().reason(), Reason::WrongContext);
    assert!(failure.unresolved().is_none());

    pool.close(&control()).unwrap();
    drop(mapping_a);
    drop(mapping_b);
}

/// RL01 LX06 negative 3: dropping one pool clone while a survivor lives
/// keeps the shared domain fully usable. Terminal unresolved retention only
/// applies when the LAST public handle disappears; a retained clone is the
/// supported recovery route.
#[test]
fn dropped_pool_clone_keeps_domain_usable() {
    let pool = no_new_pool();
    let survivor = pool.clone();
    assert_eq!(pool.status().domain(), survivor.status().domain());
    drop(pool);

    // The survivor still observes the shared domain and closes it cleanly.
    let status = survivor.status();
    assert_eq!(
        (
            status.active_mappings(),
            status.unresolved_mappings(),
            status.reserved_mappings()
        ),
        (0, 0, 0)
    );
    let closed = survivor.close(&control()).expect("survivor closes cleanly");
    assert_eq!(closed.domain(), status.domain());
}
