// SPDX-License-Identifier: Apache-2.0
//! LX06 mapping relations, explicit calibration and retained custody.
//!
//! Real native populations only: the test process maps its own temp files and
//! observes itself through retained LX08 process observations. The map_files
//! oracle is independently acquired through std paths, never through the
//! library under test. Environments that deny map_files stat (this container
//! returns EPERM even for self) must yield KeyCompatible/Inconclusive/Mismatch
//! and never ExactRange; environments that grant it must yield ExactRange for
//! a retained mapped range. TT04-cell populations (Btrfs distinct-object key
//! collision, overlay copy-up, foreign mount namespaces, fork/exec/exit
//! fixtures, privileged restriction cells) are out of scope and recorded in
//! the lane commit, not faked here.
#![cfg(feature = "mapping")]
use scopebase_linux::{
    control::OperationControl,
    error::{LimitKind, Reason, Stage},
    file::{HeldFile, ProcFdResolver, SymlinkPolicy},
    mapping::{
        InconclusiveKind, InconclusiveReason, MapRange, MappingFailure, MappingLimits,
        MappingOutcome, MappingPolicy, MappingPool, MappingPoolLimits, MappingRequest,
        MismatchEvidence, MismatchKind, ProofMethod,
    },
    process::{ObserverEpoch, Pid, ProcLimits, ProcessObservation},
    procfs::ParseLimits,
};
use std::os::fd::AsFd;
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

fn mapping_limits(policy_live: usize) -> MappingLimits {
    MappingLimits {
        proc: proc_limits(),
        max_mount_refreshes: 1,
        max_open_fds: 1024,
        max_live_mappings: policy_live,
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

fn pool_for(policy: &MappingPolicy) -> MappingPool {
    match policy {
        MappingPolicy::NoNewTargetMappings => MappingPool::new(MappingPoolLimits {
            max_mappings: 0,
            max_mapped_bytes: 0,
        })
        .unwrap(),
        MappingPolicy::AllowPrivateCalibration { max_mapped_bytes } => {
            MappingPool::new(MappingPoolLimits {
                max_mappings: 1,
                max_mapped_bytes: *max_mapped_bytes,
            })
            .unwrap()
        }
    }
}

fn page_size() -> usize {
    rustix::param::page_size()
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Owned temp file with `size` bytes; removed on drop. fsync-free test data.
struct TempFile {
    path: std::path::PathBuf,
}

impl TempFile {
    fn create(size: usize) -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("lx06-{}-{}-{}.dat", std::process::id(), id, size));
        let mut data = vec![0u8; size];
        // Distinct nonzero content per file so same-size files still differ.
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

// The mapping is never dereferenced by the test; it exists so /proc renders it.
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

/// Count own maps lines whose file inode equals `inode`, read through a fresh
/// retained observation (not through the mapping under test).
fn maps_lines_with_inode(process: &ProcessObservation, inode: u64) -> usize {
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    maps.snapshot()
        .entries()
        .filter(|entry| entry.file_key().inode() == inode)
        .count()
}

/// Independent map_files oracle: open the VMA's own file through a std path,
/// outside the library, and read identity from the held descriptor (F14).
/// Returns the open file plus the (dev, ino) the kernel reports; callers
/// keep the file alive through their comparison.
fn oracle_map_files_identity(
    pid: u32,
    start: u64,
    end: u64,
) -> std::io::Result<(std::fs::File, (u64, u64))> {
    use std::os::unix::fs::MetadataExt;
    let file = std::fs::File::open(format!("/proc/{pid}/map_files/{start:x}-{end:x}"))?;
    let metadata = file.metadata()?;
    Ok((file, (metadata.dev(), metadata.ino())))
}

fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

#[test]
fn mapping_types_are_send_sync() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<MapRange>();
    send_sync::<MappingPolicy>();
    send_sync::<MappingPool>();
    send_sync::<scopebase_linux::mapping::MappingPoolStatus>();
    send_sync::<scopebase_linux::mapping::MappingDrainReport>();
    send_sync::<scopebase_linux::mapping::MappingPoolClosed>();
    send_sync::<scopebase_linux::mapping::MappingPoolCloseFailure>();
    send_sync::<MappingLimits>();
    send_sync::<MappingOutcome>();
    send_sync::<scopebase_linux::mapping::MappingProof>();
    send_sync::<scopebase_linux::mapping::MapRangeProof>();
    send_sync::<MismatchEvidence>();
    send_sync::<MismatchKind>();
    send_sync::<InconclusiveReason>();
    send_sync::<InconclusiveKind>();
    send_sync::<MappingFailure>();
    send_sync::<scopebase_linux::mapping::MappingCustody>();
    send_sync::<ProofMethod>();
    send_sync::<scopebase_linux::mapping::FsClass>();
}

#[test]
fn map_range_validates_page_offset_and_length() {
    let page = page_size() as u64;
    assert!(MapRange::new(0, 0).is_err(), "empty range refuses");
    assert!(MapRange::new(page, page).is_err(), "empty range refuses");
    assert!(
        MapRange::new(2 * page, page).is_err(),
        "inverted range refuses"
    );
    assert!(MapRange::new(1, page).is_err(), "misaligned start refuses");
    assert!(
        MapRange::new(page, page + 1).is_err(),
        "unrounded length refuses"
    );
    let range = MapRange::new(page, 3 * page).unwrap();
    assert_eq!(
        (range.start(), range.end(), range.len()),
        (page, 3 * page, 2 * page)
    );
    let err = MapRange::new(0, 1).unwrap_err();
    assert_eq!(err.stage(), Stage::ConfigureMapping);
    assert_eq!(err.reason(), Reason::InvalidInput);
}

#[test]
fn pool_new_validates_domain_budgets() {
    // (0, 0) is the valid no-new domain.
    let pool = MappingPool::new(MappingPoolLimits {
        max_mappings: 0,
        max_mapped_bytes: 0,
    })
    .unwrap();
    let status = pool.status();
    assert_eq!(
        (
            status.active_mappings(),
            status.active_bytes(),
            status.unresolved_mappings(),
            status.unresolved_bytes(),
            status.reserved_mappings(),
            status.reserved_bytes(),
        ),
        (0, 0, 0, 0, 0, 0)
    );
    // Partially zero budgets are incoherent and refuse.
    let err = MappingPool::new(MappingPoolLimits {
        max_mappings: 0,
        max_mapped_bytes: page_size(),
    })
    .unwrap_err();
    assert_eq!(err.reason(), Reason::InvalidInput);
    let err = MappingPool::new(MappingPoolLimits {
        max_mappings: 1,
        max_mapped_bytes: 0,
    })
    .unwrap_err();
    assert_eq!(err.reason(), Reason::InvalidInput);
}

#[test]
fn no_new_mapping_creates_no_mapping_of_held_file() {
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let inode = held.stat().unwrap().key().inode();
    assert_eq!(maps_lines_with_inode(&process, inode), 0);
    let before = maps_lines_with_inode(&process, inode);

    let pool = pool_for(&MappingPolicy::NoNewTargetMappings);
    // A page-aligned unmapped gap: the outcome must be Mismatch, never a proof.
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let mut gap = None;
    let mut previous_end = 0u64;
    for entry in maps.snapshot().entries() {
        if entry.start() > previous_end
            && entry.start() - previous_end >= page_size() as u64
            && previous_end % page_size() as u64 == 0
            && previous_end > 0
        {
            gap = Some(MapRange::new(previous_end, previous_end + page_size() as u64).unwrap());
            break;
        }
        previous_end = previous_end.max(entry.end());
    }
    let range = gap.expect("address-space gap for the unmapped probe");
    let outcome = observe_mapping(
        &pool,
        &held,
        &process,
        range,
        MappingPolicy::NoNewTargetMappings,
        None,
    )
    .expect("unmapped range is a Mismatch outcome, not an error");
    match outcome {
        MappingOutcome::Mismatch(evidence) => {
            assert_eq!(evidence.kind(), MismatchKind::RangeUnmapped);
            assert!(!evidence.stage_charges().is_empty());
        }
        outcome => panic!("unexpected outcome: {outcome:?}"),
    }
    assert_eq!(maps_lines_with_inode(&process, inode), before);
    assert_eq!(maps_lines_with_inode(&process, inode), 0);
    // The no-new domain holds no charge after a refused range.
    let status = pool.status();
    assert_eq!(status.active_mappings(), 0);
    assert_eq!(status.unresolved_mappings(), 0);
    pool.close(&control()).unwrap();
}

fn observe_mapping(
    pool: &MappingPool,
    held: &Arc<HeldFile>,
    process: &ProcessObservation,
    range: MapRange,
    policy: MappingPolicy,
    retained: Option<&scopebase_linux::mapping::MappingProof>,
) -> Result<MappingOutcome, MappingFailure> {
    let live = match policy {
        MappingPolicy::NoNewTargetMappings => 0,
        MappingPolicy::AllowPrivateCalibration { .. } => 1,
    };
    scopebase_linux::mapping::observe_mapping(
        MappingRequest {
            pool,
            held: Arc::clone(held),
            process,
            range,
            policy,
            retained,
            limits: mapping_limits(live),
        },
        &control(),
    )
}

/// Observe a genuinely mapped temp-file range. The oracle decides the required
/// verdict: where the environment grants map_files stat, only ExactRange is
/// acceptable; where it denies it (EPERM here), only KeyCompatible with a
/// matching kernel-rendered key is acceptable. ExactRange without the oracle
/// descriptor is never acceptable.
#[test]
fn mapped_range_verdict_agrees_with_map_files_oracle() {
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let file = std::fs::File::open(&temp.path).unwrap();
    let mapping = TestMapping::map(&file, page_size());
    let addr = mapping.addr();

    // Resolve the exact rendered line for the range request.
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps
        .snapshot()
        .containing(addr)
        .expect("test mapping is rendered");
    assert!(line.start() <= addr && addr + page_size() as u64 <= line.end());
    let range = MapRange::new(line.start(), line.end()).unwrap();
    let oracle = oracle_map_files_identity(std::process::id(), line.start(), line.end());
    let held_key = held.stat().unwrap().key();

    for (policy, key_method) in [
        (
            MappingPolicy::NoNewTargetMappings,
            ProofMethod::MountResolved,
        ),
        (
            MappingPolicy::AllowPrivateCalibration {
                max_mapped_bytes: page_size(),
            },
            ProofMethod::Calibrated,
        ),
    ] {
        let pool = pool_for(&policy);
        let outcome = observe_mapping(&pool, &held, &process, range, policy, None)
            .expect("mapped range observes");
        match (&oracle, &outcome) {
            (Ok((file, (dev, ino))), MappingOutcome::ExactRange(proof)) => {
                // F14: the oracle descriptor is alive through this
                // comparison (it is dropped only after the match).
                use std::os::unix::fs::MetadataExt;
                let live = file.metadata().unwrap();
                assert_eq!((live.dev(), live.ino()), (*dev, *ino));
                assert_eq!((*dev, *ino), (held_key.device_raw(), held_key.inode()));
                assert_eq!(proof.range(), range);
                assert_eq!(
                    proof.map_files_identity(),
                    (held_key.device_raw(), held_key.inode())
                );
            }
            (Err(_), MappingOutcome::KeyCompatible(proof)) => {
                // The key relation holds: the kernel-rendered maps key names
                // this held object, but exact association is unproven. NoNew
                // resolves through the mount table; calibration mode renders
                // the key from its own explicit mapping.
                assert_eq!(proof.range(), range);
                assert_eq!(proof.maps_key(), line.file_key());
                assert_eq!(proof.stat().key(), held_key);
                assert_eq!(proof.method(), key_method);
                assert!(!proof.stage_charges().is_empty());
            }
            (oracle, outcome) => panic!(
                "verdict {outcome:?} disagrees with oracle {}",
                match oracle {
                    Ok((_, (dev, ino))) => format!("Ok({dev},{ino})"),
                    Err(error) => format!("Err({error})"),
                }
            ),
        }
        // Every path retires cleanly: no occupied pool charge remains.
        let status = pool.status();
        assert_eq!(status.active_mappings(), 0);
        assert_eq!(status.active_bytes(), 0);
        assert_eq!(status.unresolved_mappings(), 0);
        assert_eq!(status.reserved_mappings(), 0);
        pool.close(&control()).unwrap();
    }
    // Only the test's own mapping references the temp inode; the library's
    // calibration mapping (if any ran) is retired, not leaked.
    assert_eq!(
        maps_lines_with_inode(&process, held.stat().unwrap().key().inode()),
        1
    );
    drop(mapping);
    drop(file);
}

#[test]
fn map_files_observation_holds_its_object_descriptor() {
    // F14: where the environment grants map_files, the observation carries
    // the open mapped object: the descriptor is alive, its fstat equals the
    // reported identity and the oracle, and charges record both the
    // transient directory and the held object acquisition. Where the
    // environment denies map_files, library and oracle deny together.
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let file = std::fs::File::open(&temp.path).unwrap();
    let mapping = TestMapping::map(&file, page_size());
    let addr = mapping.addr();
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps
        .snapshot()
        .containing(addr)
        .expect("test mapping is rendered");
    match process.read_map_files_identity(line.start(), line.end(), proc_limits(), &control()) {
        Ok(obs) => {
            let (_ofile, (dev, ino)) =
                oracle_map_files_identity(std::process::id(), line.start(), line.end())
                    .expect("oracle grants where the library grants");
            let identity = obs.identity();
            assert_eq!((identity.device(), identity.inode()), (dev, ino));
            // The held descriptor is open and names the same object: a
            // shadow open through /proc/self/fd stats the same identity.
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::MetadataExt;
            let shadow = std::fs::File::open(format!(
                "/proc/self/fd/{}",
                obs.object().as_raw_fd()
            ))
            .expect("held object descriptor is open");
            let live = shadow.metadata().expect("shadow stats");
            assert_eq!((live.dev(), live.ino()), (dev, ino));
            assert!(obs.charges().fd_acquisitions() >= 2);
            let _ = &held;
        }
        Err(error) => {
            assert_eq!(error.reason(), Reason::Denied);
            assert!(
                oracle_map_files_identity(std::process::id(), line.start(), line.end()).is_err(),
                "oracle must deny where the library denies"
            );
        }
    }
    drop(mapping);
    drop(file);
}

#[test]
fn wrong_file_range_is_key_mismatch() {
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp_a = TempFile::create(8192);
    let temp_b = TempFile::create(8192);
    let held_a = temp_a.hold();
    let file_b = std::fs::File::open(&temp_b.path).unwrap();
    let mapping_b = TestMapping::map(&file_b, page_size());
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps.snapshot().containing(mapping_b.addr()).unwrap();
    let range = MapRange::new(line.start(), line.end()).unwrap();

    // Held object A against B's rendered range: the keys differ, so the
    // relation is Mismatch under both policies, never a proof.
    for policy in [
        MappingPolicy::NoNewTargetMappings,
        MappingPolicy::AllowPrivateCalibration {
            max_mapped_bytes: page_size(),
        },
    ] {
        let pool = pool_for(&policy);
        let outcome = observe_mapping(&pool, &held_a, &process, range, policy, None)
            .expect("wrong-file range is a Mismatch outcome");
        match outcome {
            MappingOutcome::Mismatch(evidence) => {
                assert_eq!(evidence.kind(), MismatchKind::KeyMismatch);
                assert!(!evidence.stage_charges().is_empty());
            }
            outcome => panic!("unexpected outcome: {outcome:?}"),
        }
        pool.close(&control()).unwrap();
    }
    // NoNew mode mapped nothing of A.
    assert_eq!(
        maps_lines_with_inode(&process, held_a.stat().unwrap().key().inode()),
        0
    );
    drop(mapping_b);
}

#[test]
fn stale_proof_after_metadata_change_refuses() {
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let file = std::fs::File::open(&temp.path).unwrap();
    let mapping = TestMapping::map(&file, page_size());
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps.snapshot().containing(mapping.addr()).unwrap();
    let range = MapRange::new(line.start(), line.end()).unwrap();

    // Issue a proof over the live mapping (ExactRange where map_files is
    // granted, KeyCompatible where it is denied).
    let pool = pool_for(&MappingPolicy::NoNewTargetMappings);
    let issued = observe_mapping(
        &pool,
        &held,
        &process,
        range,
        MappingPolicy::NoNewTargetMappings,
        None,
    )
    .expect("live mapping proves");
    let proof = match &issued {
        MappingOutcome::ExactRange(proof) => proof.proof().clone(),
        MappingOutcome::KeyCompatible(proof) => proof.clone(),
        outcome => panic!("expected a proof, got {outcome:?}"),
    };
    // Mutate the held object: length and times change under the retained key.
    std::fs::write(&temp.path, vec![7u8; 4096]).expect("rewrite temp file");

    let pool2 = pool_for(&MappingPolicy::NoNewTargetMappings);
    let failure = observe_mapping(
        &pool2,
        &held,
        &process,
        range,
        MappingPolicy::NoNewTargetMappings,
        Some(&proof),
    )
    .expect_err("changed metadata must refuse retained reuse");
    assert_eq!(failure.error().reason(), Reason::ChangedSource);
    assert!(failure.unresolved().is_none());
    pool.close(&control()).unwrap();
    pool2.close(&control()).unwrap();
    drop(mapping);
}

#[test]
fn foreign_view_proof_refuses() {
    let epoch = epoch();
    let first = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let file = std::fs::File::open(&temp.path).unwrap();
    let mapping = TestMapping::map(&file, page_size());
    let maps = first.read_maps(proc_limits(), &control()).unwrap();
    let line = maps.snapshot().containing(mapping.addr()).unwrap();
    let range = MapRange::new(line.start(), line.end()).unwrap();
    let pool = pool_for(&MappingPolicy::NoNewTargetMappings);
    let issued = observe_mapping(
        &pool,
        &held,
        &first,
        range,
        MappingPolicy::NoNewTargetMappings,
        None,
    )
    .expect("live mapping proves");
    let proof = match &issued {
        MappingOutcome::ExactRange(proof) => proof.proof().clone(),
        MappingOutcome::KeyCompatible(proof) => proof.clone(),
        outcome => panic!("expected a proof, got {outcome:?}"),
    };

    // A fresh observation is a fresh view: the old proof is foreign to it.
    let second = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    assert_ne!(first.mount_view(), second.mount_view());
    let pool2 = pool_for(&MappingPolicy::NoNewTargetMappings);
    let failure = observe_mapping(
        &pool2,
        &held,
        &second,
        range,
        MappingPolicy::NoNewTargetMappings,
        Some(&proof),
    )
    .expect_err("foreign-view proof must refuse");
    assert_eq!(failure.error().reason(), Reason::WrongContext);
    pool.close(&control()).unwrap();
    pool2.close(&control()).unwrap();
    drop(mapping);
}

#[test]
fn different_owner_object_refuses_reuse() {
    // Owner continuity is object identity, not path equality: a second
    // HeldFile over the same path is a different owner and must refuse.
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let file = std::fs::File::open(&temp.path).unwrap();
    let mapping = TestMapping::map(&file, page_size());
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps.snapshot().containing(mapping.addr()).unwrap();
    let range = MapRange::new(line.start(), line.end()).unwrap();
    let pool = pool_for(&MappingPolicy::NoNewTargetMappings);
    let issued = observe_mapping(
        &pool,
        &held,
        &process,
        range,
        MappingPolicy::NoNewTargetMappings,
        None,
    )
    .expect("live mapping proves");
    let proof = match &issued {
        MappingOutcome::ExactRange(proof) => proof.proof().clone(),
        MappingOutcome::KeyCompatible(proof) => proof.clone(),
        outcome => panic!("expected a proof, got {outcome:?}"),
    };
    let other = temp.hold();
    assert!(!Arc::ptr_eq(&held, &other));
    assert_eq!(held.stat().unwrap().key(), other.stat().unwrap().key());
    let pool2 = pool_for(&MappingPolicy::NoNewTargetMappings);
    let failure = observe_mapping(
        &pool2,
        &other,
        &process,
        range,
        MappingPolicy::NoNewTargetMappings,
        Some(&proof),
    )
    .expect_err("different owner object must refuse");
    assert_eq!(failure.error().reason(), Reason::WrongContext);
    pool.close(&control()).unwrap();
    pool2.close(&control()).unwrap();
    drop(mapping);
}

#[test]
fn retained_proof_reuse_follows_filesystem_eligibility() {
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let file = std::fs::File::open(&temp.path).unwrap();
    let mapping = TestMapping::map(&file, page_size());
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps.snapshot().containing(mapping.addr()).unwrap();
    let range = MapRange::new(line.start(), line.end()).unwrap();
    let pool = pool_for(&MappingPolicy::NoNewTargetMappings);
    let issued = observe_mapping(
        &pool,
        &held,
        &process,
        range,
        MappingPolicy::NoNewTargetMappings,
        None,
    )
    .expect("live mapping proves");
    let proof = match &issued {
        MappingOutcome::ExactRange(proof) => proof.proof().clone(),
        MappingOutcome::KeyCompatible(proof) => proof.clone(),
        outcome => panic!("expected a proof, got {outcome:?}"),
    };

    // Unchanged object, same observation: reuse is accepted exactly on the
    // ext4 allowlist and refused elsewhere (this container's /tmp is btrfs).
    // fstatfs failure never counts as ordinary: Unknown refuses like Other.
    let pool2 = pool_for(&MappingPolicy::NoNewTargetMappings);
    let again = observe_mapping(
        &pool2,
        &held,
        &process,
        range,
        MappingPolicy::NoNewTargetMappings,
        Some(&proof),
    );
    if proof.filesystem().retained_reuse_eligible() {
        let outcome = again.expect("eligible reuse accepts");
        match outcome {
            MappingOutcome::KeyCompatible(next) => {
                assert_eq!(next.maps_key(), proof.maps_key());
            }
            MappingOutcome::ExactRange(_) => {}
            outcome => panic!("reuse must keep a proof, got {outcome:?}"),
        }
    } else {
        let failure = again.expect_err("ineligible filesystem must refuse reuse");
        assert_eq!(failure.error().reason(), Reason::InvalidInput);
    }
    pool.close(&control()).unwrap();
    pool2.close(&control()).unwrap();
    drop(mapping);
}

#[test]
fn uncalibrated_live_mapping_request_refuses() {
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let pool = pool_for(&MappingPolicy::NoNewTargetMappings);
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps
        .snapshot()
        .containing(maps.snapshot().entries().next().unwrap().start());
    let line = line.unwrap();
    let range = MapRange::new(line.start(), line.end()).unwrap();
    // NoNew policy with a nonzero live-mapping ceiling asks for calibration
    // effects without calibration authority: typed refusal, no observation.
    let failure = scopebase_linux::mapping::observe_mapping(
        MappingRequest {
            pool: &pool,
            held,
            process: &process,
            range,
            policy: MappingPolicy::NoNewTargetMappings,
            retained: None,
            limits: mapping_limits(1),
        },
        &control(),
    )
    .expect_err("uncalibrated live mapping must refuse");
    assert_eq!(failure.error().stage(), Stage::ConfigureMapping);
    assert_eq!(failure.error().reason(), Reason::InvalidInput);
    assert!(failure.unresolved().is_none());
    pool.close(&control()).unwrap();
}

#[test]
fn empty_file_is_inconclusive_without_mapping() {
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(0);
    let held = temp.hold();
    let inode = held.stat().unwrap().key().inode();
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps.snapshot().entries().next().unwrap();
    let range = MapRange::new(line.start(), line.end()).unwrap();
    let pool = pool_for(&MappingPolicy::AllowPrivateCalibration {
        max_mapped_bytes: page_size(),
    });
    let outcome = observe_mapping(
        &pool,
        &held,
        &process,
        range,
        MappingPolicy::AllowPrivateCalibration {
            max_mapped_bytes: page_size(),
        },
        None,
    )
    .expect("empty file is Inconclusive, not an error");
    match outcome {
        MappingOutcome::Inconclusive(reason) => {
            assert_eq!(reason.kind(), InconclusiveKind::EmptyFile);
            assert!(reason.stage_charges().is_empty());
        }
        outcome => panic!("unexpected outcome: {outcome:?}"),
    }
    assert_eq!(maps_lines_with_inode(&process, inode), 0);
    let status = pool.status();
    assert_eq!(status.active_mappings(), 0);
    assert_eq!(status.unresolved_mappings(), 0);
    pool.close(&control()).unwrap();
}

#[test]
fn sub_page_cap_is_inconclusive_without_mapping() {
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let inode = held.stat().unwrap().key().inode();
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps
        .snapshot()
        .containing(maps.snapshot().entries().next().unwrap().start());
    let line = line.unwrap();
    let range = MapRange::new(line.start(), line.end()).unwrap();
    // A cap below one page-granularity mapping cannot calibrate: Inconclusive
    // with no mapping attempt.
    let pool = MappingPool::new(MappingPoolLimits {
        max_mappings: 1,
        max_mapped_bytes: page_size(),
    })
    .unwrap();
    let outcome = scopebase_linux::mapping::observe_mapping(
        MappingRequest {
            pool: &pool,
            held: Arc::clone(&held),
            process: &process,
            range,
            policy: MappingPolicy::AllowPrivateCalibration {
                max_mapped_bytes: 1,
            },
            retained: None,
            limits: mapping_limits(1),
        },
        &control(),
    )
    .expect("sub-page cap observes");
    // The cap binds the calibration step only: where map_files is denied the
    // key path reaches calibration and the sub-page cap is Inconclusive
    // without mapping; where map_files is granted the contradictory
    // association decides KeyMismatch without ever calibrating.
    match (
        oracle_map_files_identity(std::process::id(), line.start(), line.end()).is_err(),
        outcome,
    ) {
        (true, MappingOutcome::Inconclusive(reason)) => {
            assert_eq!(reason.kind(), InconclusiveKind::CapBelowPage);
            assert!(!reason.stage_charges().is_empty());
        }
        (false, MappingOutcome::Mismatch(evidence)) => {
            assert_eq!(evidence.kind(), MismatchKind::KeyMismatch);
        }
        (denied, outcome) => panic!("denied={denied} unexpected outcome: {outcome:?}"),
    }
    assert_eq!(maps_lines_with_inode(&process, inode), 0);
    pool.close(&control()).unwrap();
}

#[test]
fn zero_fd_ceiling_refuses_before_effects() {
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let pool = pool_for(&MappingPolicy::NoNewTargetMappings);
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps.snapshot().entries().next().unwrap();
    let range = MapRange::new(line.start(), line.end()).unwrap();
    let failure = scopebase_linux::mapping::observe_mapping(
        MappingRequest {
            pool: &pool,
            held,
            process: &process,
            range,
            policy: MappingPolicy::NoNewTargetMappings,
            retained: None,
            limits: MappingLimits {
                proc: proc_limits(),
                max_mount_refreshes: 1,
                max_open_fds: 0,
                max_live_mappings: 0,
            },
        },
        &control(),
    )
    .expect_err("zero FD ceiling must refuse");
    assert_eq!(
        failure.error().reason(),
        Reason::LimitExceeded(LimitKind::OpenFds)
    );
    // F13: the refusal happens before effects, so no acquisition may be
    // recorded anywhere on the failure (neither stage charges nor the
    // error's own charges). Transient open-then-reject would show up here.
    let staged: u64 = failure
        .stage_charges()
        .iter()
        .map(|charges| charges.fd_acquisitions())
        .sum();
    assert_eq!(staged, 0, "zero-FD refusal must acquire nothing");
    assert_eq!(
        failure.error().charges().fd_acquisitions(),
        0,
        "refusal error must carry no acquisitions"
    );
    pool.close(&control()).unwrap();
}

// R11: a positive-but-insufficient FD budget (4 < birth's worst case 5)
// refuses at the birth preflight with zero acquisitions recorded. The
// old fully-spent-only preflight ran the sub-operation and
// over-acquired transiently before rejecting.
#[test]
fn insufficient_fd_ceiling_refuses_at_birth_preflight() {
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let pool = pool_for(&MappingPolicy::NoNewTargetMappings);
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps.snapshot().entries().next().unwrap();
    let range = MapRange::new(line.start(), line.end()).unwrap();
    let failure = scopebase_linux::mapping::observe_mapping(
        MappingRequest {
            pool: &pool,
            held,
            process: &process,
            range,
            policy: MappingPolicy::NoNewTargetMappings,
            retained: None,
            limits: MappingLimits {
                proc: proc_limits(),
                max_mount_refreshes: 1,
                max_open_fds: 4,
                max_live_mappings: 0,
            },
        },
        &control(),
    )
    .expect_err("4-FD ceiling cannot admit birth's 5");
    assert_eq!(
        failure.error().reason(),
        Reason::LimitExceeded(LimitKind::OpenFds)
    );
    let staged: u64 = failure
        .stage_charges()
        .iter()
        .map(|charges| charges.fd_acquisitions())
        .sum();
    assert_eq!(staged, 0, "preflight refusal must acquire nothing");
    assert_eq!(
        failure.error().charges().fd_acquisitions(),
        0,
        "refusal error must carry no acquisitions"
    );
    pool.close(&control()).unwrap();
}

#[test]
fn pool_close_blocks_stale_clones() {
    let pool = MappingPool::new(MappingPoolLimits {
        max_mappings: 1,
        max_mapped_bytes: page_size(),
    })
    .unwrap();
    let stale = pool.clone();
    assert_eq!(pool.status().domain(), stale.status().domain());
    let closed = pool.close(&control()).expect("empty domain closes");
    assert_eq!(closed.domain(), stale.status().domain());

    // The stale clone cannot start new work after the successful close.
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps.snapshot().entries().next().unwrap();
    let range = MapRange::new(line.start(), line.end()).unwrap();
    let failure = observe_mapping(
        &stale,
        &held,
        &process,
        range,
        MappingPolicy::NoNewTargetMappings,
        None,
    )
    .expect_err("stale clone must refuse after close");
    assert_eq!(failure.error().reason(), Reason::WrongContext);
}

#[test]
fn independent_pool_is_separate_accounting_domain() {
    let first = MappingPool::new(MappingPoolLimits {
        max_mappings: 1,
        max_mapped_bytes: page_size(),
    })
    .unwrap();
    let second = MappingPool::new(MappingPoolLimits {
        max_mappings: 1,
        max_mapped_bytes: page_size(),
    })
    .unwrap();
    assert_ne!(first.status().domain(), second.status().domain());
    first.close(&control()).unwrap();
    // Closing one domain leaves the other fully usable.
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps.snapshot().entries().next().unwrap();
    let range = MapRange::new(line.start(), line.end()).unwrap();
    let outcome = observe_mapping(
        &second,
        &held,
        &process,
        range,
        MappingPolicy::NoNewTargetMappings,
        None,
    )
    .expect("independent domain still admits");
    assert!(matches!(
        outcome,
        MappingOutcome::Mismatch(_)
            | MappingOutcome::Inconclusive(_)
            | MappingOutcome::KeyCompatible(_)
    ));
    second.close(&control()).unwrap();
}

#[test]
fn cancelled_close_returns_open_pool() {
    use scopebase_linux::control::{CancelToken, OperationControl};
    let pool = MappingPool::new(MappingPoolLimits {
        max_mappings: 1,
        max_mapped_bytes: page_size(),
    })
    .unwrap();
    let cancel = CancelToken::new();
    let cancelled = OperationControl::new(None, cancel.clone());
    cancel.cancel();
    let failure = pool.close(&cancelled).expect_err("cancelled close fails");
    assert_eq!(failure.error().reason(), Reason::Cancelled);
    // The domain is still Open: the returned pool admits new work.
    let pool = failure.into_pool();
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps.snapshot().entries().next().unwrap();
    let range = MapRange::new(line.start(), line.end()).unwrap();
    observe_mapping(
        &pool,
        &held,
        &process,
        range,
        MappingPolicy::NoNewTargetMappings,
        None,
    )
    .expect("recovered pool admits");
    pool.close(&control()).unwrap();
}

#[test]
fn calibration_leaves_no_fds_or_mappings_behind() {
    // Native custody oracle: repeated calibration observations hold no FDs and
    // leave no mapping of the held file behind.
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let inode = held.stat().unwrap().key().inode();
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps.snapshot().entries().next().unwrap();
    let range = MapRange::new(line.start(), line.end()).unwrap();
    let pool = MappingPool::new(MappingPoolLimits {
        max_mappings: 1,
        max_mapped_bytes: page_size(),
    })
    .unwrap();
    let mut stable = 0u32;
    for _ in 0..20 {
        let before = fd_count();
        let outcome = observe_mapping(
            &pool,
            &held,
            &process,
            range,
            MappingPolicy::AllowPrivateCalibration {
                max_mapped_bytes: page_size(),
            },
            None,
        )
        .expect("calibration observes");
        let _ = outcome;
        assert_eq!(maps_lines_with_inode(&process, inode), 0);
        if fd_count() == before {
            stable += 1;
            if stable >= 3 {
                break;
            }
        }
    }
    assert!(stable >= 3, "calibration holds no FDs");
    // Strong-count custody: only the test's Arc and the pool-free proof (if
    // any) reference the held file; no stranded custody owns it.
    assert_eq!(pool.status().unresolved_mappings(), 0);
    pool.close(&control()).unwrap();
    assert_eq!(maps_lines_with_inode(&process, inode), 0);
}

#[test]
fn mount_resolved_key_matches_rendered_maps_key() {
    // The fdinfo/mountinfo resolution names the same kernel-rendered device
    // that maps itself renders (on this btrfs /tmp, 0:35, not st_dev 0:37).
    // The library's KeyCompatible proof must carry exactly that key.
    let epoch = epoch();
    let process = ProcessObservation::acquire(me(), &epoch, proc_limits(), &control()).unwrap();
    let temp = TempFile::create(8192);
    let held = temp.hold();
    let file = std::fs::File::open(&temp.path).unwrap();
    let mapping = TestMapping::map(&file, page_size());
    let maps = process.read_maps(proc_limits(), &control()).unwrap();
    let line = maps.snapshot().containing(mapping.addr()).unwrap();
    let range = MapRange::new(line.start(), line.end()).unwrap();

    let mnt_id = fdinfo_mnt_id(held.as_fd());
    let mountinfo = process.read_mountinfo(proc_limits(), &control()).unwrap();
    let row = mountinfo
        .snapshot()
        .entry_by_number(mnt_id)
        .expect("held mount resolves in the target table");
    assert_eq!(row.device().major(), line.file_key().device_major());
    assert_eq!(row.device().minor(), line.file_key().device_minor());

    // The NoNew proof path uses exactly this resolution: where map_files is
    // denied, the issued key must equal the independently resolved one.
    let pool = pool_for(&MappingPolicy::NoNewTargetMappings);
    let outcome = observe_mapping(
        &pool,
        &held,
        &process,
        range,
        MappingPolicy::NoNewTargetMappings,
        None,
    )
    .expect("mapped range observes");
    if oracle_map_files_identity(std::process::id(), line.start(), line.end()).is_err() {
        match outcome {
            MappingOutcome::KeyCompatible(proof) => {
                assert_eq!(proof.maps_key(), line.file_key());
                assert_eq!(proof.method(), ProofMethod::MountResolved);
            }
            outcome => panic!("denied map_files must give KeyCompatible, got {outcome:?}"),
        }
    }
    pool.close(&control()).unwrap();
    drop(mapping);
}

/// Minimal independent fdinfo oracle: parse this fd's mnt_id from /proc/self.
fn fdinfo_mnt_id(fd: std::os::fd::BorrowedFd<'_>) -> u64 {
    use std::os::fd::AsRawFd;
    let text = std::fs::read(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).unwrap();
    let text = String::from_utf8(text).unwrap();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("mnt_id:") {
            return value.trim().parse().unwrap();
        }
    }
    panic!("no mnt_id in fdinfo");
}

#[test]
fn drain_report_counts_idle_domain() {
    let pool = MappingPool::new(MappingPoolLimits {
        max_mappings: 1,
        max_mapped_bytes: page_size(),
    })
    .unwrap();
    let report = pool.retry_unresolved(&control());
    assert_eq!(
        (report.attempted(), report.retired(), report.unresolved()),
        (0, 0, 0)
    );
    assert!(report.errors().is_empty());
    pool.close(&control()).unwrap();
}
