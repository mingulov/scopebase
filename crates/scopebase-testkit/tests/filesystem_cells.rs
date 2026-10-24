// SPDX-License-Identifier: Apache-2.0
//! TT04 real filesystem cells and mapping-policy audit over LX06 relations.
//!
//! Plan authority: docs/superpowers/plans/2026-10-17-scopebase-testing.md
//! TT04 section; recipes FS01-FS10 from
//! docs/superpowers/specs/2026-10-17-scopebase-testing-design.md. Every cell
//! drives the real production APIs (`scopebase_linux::mapping`/
//! `process`) against live fixtures; independent oracles use only std
//! reads of /proc, never the library under test. Cells that cannot run
//! here print `TT04-SKIP <cell>: <exact missing capability>` and pass
//! vacuously never: a fixture that does not produce its trigger FAILS
//! as unexercised.
//!
//! Privileged fixtures (FS01/FS04-FS08 overlays, loop ext4, namespace
//! sleepers, churn driver) come from `tools/qualification/provision_fs.py
//! create --privileged` via the `TT04_MANIFEST` path; unprivileged cells
//! self-provision under a temp dir. The manifest is admission-checked
//! against live state (stat+sha, mount table, proc starttimes) before
//! any cell trusts it: text alone grants no authority.
//!
//! Donor lineage: the maps oracle extends P
//! tests/e20_live_collision.rs @2c2713e6:97-119 (`maps_inode`: collect
//! inodes per mapped path suffix from /proc/PID/maps) to full
//! dev:ino:range entries; target fixtures use the ported OwnedTarget
//! (P src/discovery/test_subject.rs @2c2713e6). D03 scoped grant
//! (2026-10-23) covers GPL-source to Apache-2.0 destination inside
//! this workspace; donor files/terms untouched.
#![cfg(feature = "linux-fixtures")]
use scopebase_linux::{
    control::OperationControl,
    error::Reason,
    file::{HeldFile, ProcFdResolver, ReadLimits, SymlinkPolicy},
    mapping::{
        InconclusiveKind, MapRange, MappingLimits, MappingOutcome, MappingPolicy, MappingPool,
        MappingPoolLimits, MappingRequest, MismatchKind,
    },
    process::{ObserverEpoch, Pid, ProcLimits, ProcessObservation},
    procfs::{parse_mountinfo, ParseLimits},
};
use scopebase_testkit::fixture::linux::{
    audit::{self, AuditConfig},
    target::OwnedTarget,
};
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Small shared helpers: limits, pools, temp files, independent oracles.
// ---------------------------------------------------------------------------

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

fn read_limits() -> ReadLimits {
    ReadLimits {
        max_bytes: 1 << 20,
        max_read_calls: 4096,
        max_buffer_capacity: 1 << 20,
    }
}

fn control() -> OperationControl {
    OperationControl::unlimited()
}

fn epoch() -> ObserverEpoch {
    ObserverEpoch::new(proc_limits(), &control()).expect("epoch on own process")
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

fn hold(path: &Path) -> Arc<HeldFile> {
    let resolver = ProcFdResolver::open_self().unwrap();
    Arc::new(HeldFile::open(path, &resolver, SymlinkPolicy::Follow).unwrap())
}

#[allow(clippy::result_large_err)]
fn hold_with(
    path: &Path,
    policy: SymlinkPolicy,
) -> Result<Arc<HeldFile>, scopebase_linux::error::LinuxError> {
    let resolver = ProcFdResolver::open_self().unwrap();
    HeldFile::open(path, &resolver, policy).map(Arc::new)
}

fn read_held(held: &HeldFile) -> Vec<u8> {
    held.read_all(read_limits(), &control())
        .expect("bounded retained read")
        .bytes()
        .to_vec()
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// R32: process-start nonce so a rerun under a recycled PID never
/// collides with crash residue (which would otherwise panic below).
static START_NONCE: std::sync::OnceLock<u128> = std::sync::OnceLock::new();

fn start_nonce() -> u128 {
    *START_NONCE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    })
}

fn temp_dir(tag: &str) -> PathBuf {
    let id = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "tt04-{}-{}-{}-{:x}",
        std::process::id(),
        id,
        tag,
        start_nonce()
    ));
    claim_temp_dir(&dir);
    dir
}

/// R32: exclusively create a private temp dir. A pre-existing
/// candidate (preplanted symlink, stale residue) is refused
/// loudly: silently reusing it would let a planted link redirect
/// privileged fixture writes outside the temp tree.
fn claim_temp_dir(dir: &Path) {
    match std::fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) => panic!(
            "refused: temp candidate {} already exists ({e}); remove stale tt04-* dirs or a preplant",
            dir.display()
        ),
    }
}

fn pattern_bytes(seed: usize, size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| (i.wrapping_mul(31).wrapping_add(seed) % 251 + 1) as u8)
        .collect()
}

fn skip(cell: &str, reason: &str) {
    println!("TT04-SKIP {cell}: {reason}");
}

fn pass(cell: &str, evidence: &str) {
    println!("TT04-PASS {cell}: {evidence}");
}

/// R32: a preplanted symlink at the claimed path is refused, never
/// followed: the outside canary survives and nothing is written
/// through the link. The old `create_dir_all` helper would have
/// descended into the plant.
#[test]
fn temp_claim_refuses_preplanted_symlink() {
    let plant = std::env::temp_dir().join(format!(
        "tt04-{}-canary-plant-{:x}",
        std::process::id(),
        start_nonce()
    ));
    let _ = std::fs::remove_file(&plant);
    let _ = std::fs::remove_dir_all(&plant);
    let outside = temp_dir("canary-outside");
    let canary = outside.join("canary.txt");
    std::fs::write(&canary, b"canary").unwrap();
    std::os::unix::fs::symlink(&outside, &plant).unwrap();
    let outcome = std::panic::catch_unwind(|| claim_temp_dir(&plant));
    assert!(
        outcome.is_err(),
        "preplanted symlink was claimed instead of refused"
    );
    assert_eq!(
        std::fs::read(&canary).unwrap(),
        b"canary",
        "claim wrote through the planted link"
    );
    std::fs::remove_file(&plant).unwrap();
}

/// One parsed /proc/PID/maps row from the independent std oracle.
#[derive(Debug, Clone)]
struct MapsEntry {
    start: u64,
    end: u64,
    dev_major: u64,
    dev_minor: u64,
    ino: u64,
    path: Option<String>,
}

fn parse_hex_u64(text: &str) -> Option<u64> {
    u64::from_str_radix(text, 16).ok()
}

/// Independent maps oracle (std only): every mapping row of one process.
fn maps_entries(pid: u32) -> Vec<MapsEntry> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .unwrap_or_else(|e| panic!("oracle maps read for owned pid {pid}: {e}"));
    let mut out = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(range), Some(_perms), Some(_offset), Some(dev), Some(ino)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let (Some(addr), Some(dev_pair)) = (range.split_once('-'), dev.split_once(':')) else {
            continue;
        };
        let (Some(start), Some(end)) = (parse_hex_u64(addr.0), parse_hex_u64(addr.1)) else {
            continue;
        };
        let Ok(ino) = ino.parse::<u64>() else {
            continue;
        };
        let (Ok(major), Ok(minor)) = (
            u64::from_str_radix(dev_pair.0, 16),
            u64::from_str_radix(dev_pair.1, 16),
        ) else {
            continue;
        };
        // The pathname is the whole remainder: markers like
        // " (deleted)" are separate whitespace fields.
        let rest: Vec<&str> = fields.collect();
        out.push(MapsEntry {
            start,
            end,
            dev_major: major,
            dev_minor: minor,
            ino,
            path: if rest.is_empty() {
                None
            } else {
                Some(rest.join(" "))
            },
        });
    }
    out
}

/// Independent oracle: the maps key of `path` as mapped by `pid`.
fn maps_key_for(pid: u32, path: &Path) -> Option<(u64, u64, u64, u64, u64)> {
    let want = path.to_string_lossy().into_owned();
    maps_entries(pid)
        .into_iter()
        .find(|e| e.path.as_deref() == Some(want.as_str()))
        .map(|e| (e.start, e.end, e.dev_major, e.dev_minor, e.ino))
}

fn stat_key(path: &Path) -> (u64, u64, u64) {
    let st = std::fs::metadata(path).expect("oracle stat");
    (st.dev() as u64, st.ino(), st.size())
}

fn nspid_of(pid: u32) -> Vec<u32> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap_or_else(|e| panic!("oracle status for {pid}: {e}"));
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("NSpid:") {
            return rest
                .split_whitespace()
                .map(|n| n.parse::<u32>().expect("NSpid numeric"))
                .collect();
        }
    }
    panic!("no NSpid for {pid}");
}

fn starttime_of(pid: u32) -> u64 {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .unwrap_or_else(|e| panic!("oracle stat for {pid}: {e}"));
    let after = text.rsplit(')').next().expect("last-paren stat");
    after
        .split_whitespace()
        .nth(19)
        .expect("field 22")
        .parse::<u64>()
        .expect("starttime numeric")
}

fn parse_range(text: &str) -> (u64, u64) {
    let (a, b) = text.split_once('-').expect("start-end range");
    let start = u64::from_str_radix(a.trim(), 16).expect("hex start");
    let end = u64::from_str_radix(b.trim(), 16).expect("hex end");
    assert!(start < end && start % 4096 == 0, "page-aligned range");
    (start, end)
}

fn report_value(report: &Path, key: &str) -> String {
    let text = std::fs::read_to_string(report).expect("sleeper report");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}=")) {
            return rest.trim().to_string();
        }
    }
    panic!("report {report:?} lacks {key}");
}

fn short_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())[..16].to_string()
}

/// Run-unique fixture tag: provisioned layers persist across suite
/// runs, so per-run names must never collide with a previous run's
/// upper copies.
fn unique_tag() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}", std::process::id())
}

fn assert_bytes_eq(actual: &[u8], expected: &[u8], what: &str) {
    assert_eq!(actual.len(), expected.len(), "{what}: length diverged");
    assert_eq!(
        short_hash(actual),
        short_hash(expected),
        "{what}: content diverged (actual sha256:{} expected sha256:{})",
        short_hash(actual),
        short_hash(expected)
    );
}

// ---------------------------------------------------------------------------
// Manifest admission: live state re-verified, text alone grants nothing.
// ---------------------------------------------------------------------------

struct Manifest {
    value: serde_json::Value,
    run_root: PathBuf,
}

impl Manifest {
    fn cell(&self, name: &str) -> (String, String) {
        let cell = self.value["cells"][name]
            .as_object()
            .unwrap_or_else(|| panic!("TT04-ADMIT-REFUSED: manifest lacks cell {name}"));
        let status = cell["status"].as_str().unwrap_or("?").to_string();
        let note = cell
            .get("reason")
            .or_else(|| cell.get("detail"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        (status, note)
    }

    fn file(&self, role: &str) -> PathBuf {
        let files = self.value["files"].as_array().expect("files array");
        for entry in files {
            if entry["role"].as_str() == Some(role) {
                return PathBuf::from(entry["path"].as_str().expect("file path"));
            }
        }
        panic!("TT04-ADMIT-REFUSED: manifest lacks file role {role}");
    }

    fn mount_target(&self, role: &str) -> PathBuf {
        let mounts = self.value["mounts"].as_array().expect("mounts array");
        for entry in mounts {
            if entry["role"].as_str() == Some(role) {
                return PathBuf::from(entry["target"].as_str().expect("target"));
            }
        }
        panic!("TT04-ADMIT-REFUSED: manifest lacks mount role {role}");
    }

    fn proc_pid(&self, role: &str) -> u32 {
        let procs = self.value["procs"].as_array().expect("procs array");
        for entry in procs {
            if entry["role"].as_str() == Some(role) {
                return entry["pid"].as_u64().expect("pid") as u32;
            }
        }
        panic!("TT04-ADMIT-REFUSED: manifest lacks proc role {role}");
    }

    fn evidence_path(&self, keys: &[&str]) -> PathBuf {
        let mut node = &self.value["evidence"];
        for key in keys {
            node = &node[key];
        }
        PathBuf::from(
            node.as_str()
                .unwrap_or_else(|| panic!("TT04-ADMIT-REFUSED: manifest lacks evidence {keys:?}")),
        )
    }
}

fn run_root_allowed(root: &str) -> bool {
    if root.is_empty() || root.len() > 4095 || root.contains('\0') {
        return false;
    }
    let path = Path::new(root);
    if path.components().any(|c| c.as_os_str() == "..") || !path.is_absolute() {
        return false;
    }
    for base in ["/tmp", "/var/tmp", "/dev/shm"] {
        if root == base || root.starts_with(&format!("{base}/")) {
            return true;
        }
    }
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        if !tmpdir.is_empty() && (root == tmpdir || root.starts_with(&format!("{tmpdir}/"))) {
            return true;
        }
    }
    false
}

/// Load and admit the provisioner manifest, or return None when the
/// `TT04_MANIFEST` environment is absent (privileged cells SKIP).
/// A present-but-rotten manifest FAILS the cell, never skips it.
fn admit_manifest() -> Option<Manifest> {
    let path = std::env::var("TT04_MANIFEST").ok()?;
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("TT04-ADMIT-REFUSED: manifest unreadable: {e}"));
    let value: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("TT04-ADMIT-REFUSED: manifest unparseable: {e}"));
    assert_eq!(
        value["schema"].as_str(),
        Some("tt04-fs-manifest-v1"),
        "TT04-ADMIT-REFUSED: schema mismatch"
    );
    let run_root = value["run_root"].as_str().expect("run_root").to_string();
    assert!(
        run_root_allowed(&run_root),
        "TT04-ADMIT-REFUSED: foreign run-root {run_root}"
    );
    let root = PathBuf::from(&run_root);
    // Files: live stat identity plus bounded sha256 over live bytes.
    for entry in value["files"].as_array().expect("files") {
        let role = entry["role"].as_str().unwrap_or("?");
        let file = entry["path"]
            .as_str()
            .unwrap_or_else(|| panic!("TT04-ADMIT-REFUSED: file {role} lacks path"));
        assert!(
            Path::new(file).starts_with(&root),
            "TT04-ADMIT-REFUSED: file {role} escapes run-root"
        );
        let bytes =
            std::fs::read(file).unwrap_or_else(|e| panic!("TT04-ADMIT-REFUSED: file {role}: {e}"));
        assert!(
            bytes.len() <= (1 << 20),
            "TT04-ADMIT-REFUSED: {role} too big"
        );
        let meta = std::fs::metadata(file).expect("live metadata");
        assert_eq!(
            meta.dev() as u64,
            entry["dev"].as_u64().expect("dev"),
            "TT04-ADMIT-REFUSED: {role} dev changed"
        );
        assert_eq!(
            meta.ino(),
            entry["ino"].as_u64().expect("ino"),
            "TT04-ADMIT-REFUSED: {role} ino changed"
        );
        assert_eq!(
            meta.size(),
            entry["size"].as_u64().expect("size"),
            "TT04-ADMIT-REFUSED: {role} size changed"
        );
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        assert_eq!(
            hex::encode(hasher.finalize()),
            entry["sha256"].as_str().expect("sha"),
            "TT04-ADMIT-REFUSED: {role} content changed"
        );
    }
    // Mounts: live mount table through the strict parser, then identity.
    let table_bytes = std::fs::read("/proc/self/mountinfo")
        .unwrap_or_else(|e| panic!("TT04-ADMIT-REFUSED: mountinfo: {e}"));
    let snapshot = parse_mountinfo(
        &table_bytes,
        ParseLimits {
            max_bytes: 1 << 20,
            max_entries: 1 << 16,
            max_line_bytes: 1 << 16,
        },
    )
    .unwrap_or_else(|e| panic!("TT04-ADMIT-REFUSED: mountinfo parse: {e:?}"));
    for entry in value["mounts"].as_array().expect("mounts") {
        let role = entry["role"].as_str().unwrap_or("?");
        let target = entry["target"]
            .as_str()
            .unwrap_or_else(|| panic!("TT04-ADMIT-REFUSED: mount {role} lacks target"));
        assert!(
            Path::new(target).starts_with(&root),
            "TT04-ADMIT-REFUSED: mount {role} escapes run-root"
        );
        let row = snapshot
            .entries()
            .find(|e| e.mount_point().decoded() == target.as_bytes())
            .unwrap_or_else(|| panic!("TT04-ADMIT-REFUSED: mount {role} not present"));
        assert_eq!(
            row.id().number(),
            entry["mnt_id"].as_u64().expect("mnt_id"),
            "TT04-ADMIT-REFUSED: {role} mnt_id changed"
        );
        assert_eq!(
            row.filesystem_type().decoded(),
            entry["fstype"].as_str().expect("fstype").as_bytes(),
            "TT04-ADMIT-REFUSED: {role} fstype changed"
        );
        assert_eq!(
            row.source().decoded(),
            entry["source"].as_str().expect("source").as_bytes(),
            "TT04-ADMIT-REFUSED: {role} source changed"
        );
        let live_super = row.super_options().decoded();
        for want in entry["expect_super"].as_array().expect("expect_super") {
            let want = want.as_str().expect("super substring");
            assert!(
                live_super.windows(want.len()).any(|w| w == want.as_bytes()),
                "TT04-ADMIT-REFUSED: {role} lost super option {want}"
            );
        }
    }
    // Procs: pid liveness plus starttime identity (no PID reuse).
    for entry in value["procs"].as_array().expect("procs") {
        let role = entry["role"].as_str().unwrap_or("?");
        let pid = entry["pid"].as_u64().expect("pid") as u32;
        let live = starttime_of(pid);
        assert_eq!(
            live,
            entry["starttime"].as_u64().expect("starttime"),
            "TT04-ADMIT-REFUSED: proc {role} identity changed"
        );
    }
    Some(Manifest {
        value,
        run_root: root,
    })
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    }
}

/// True when the manifest cell provisioned; otherwise prints the exact
/// recorded SKIP reason and returns false.
fn provisioned(manifest: &Manifest, cell: &str) -> bool {
    let (status, note) = manifest.cell(cell);
    if status == "provisioned" {
        return true;
    }
    skip(cell, &format!("cell {status}: {note}"));
    false
}

#[allow(clippy::result_large_err)]
fn observe(
    pool: &MappingPool,
    held: &Arc<HeldFile>,
    process: &ProcessObservation,
    range: MapRange,
    policy: MappingPolicy,
    control: &OperationControl,
) -> Result<MappingOutcome, scopebase_linux::mapping::MappingFailure> {
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
            retained: None,
            limits: mapping_limits(live),
        },
        control,
    )
}

/// Btrfs collision triple: manifest fixtures when admitted, otherwise
/// self-provisioned subvolumes under an owned temp dir. Returns None
/// with an exact SKIP reason when btrfs refuses.
fn btrfs_triple(manifest: Option<&Manifest>) -> Option<(PathBuf, PathBuf, PathBuf)> {
    if let Some(m) = manifest {
        if provisioned(m, "FS02") {
            return Some((
                m.file("btrfs-svA-f"),
                m.file("btrfs-svB-f"),
                m.file("btrfs-snapA-f"),
            ));
        }
        return None;
    }
    let base = temp_dir("btrfs");
    let run = |argv: &[&str]| {
        std::process::Command::new(argv[0])
            .args(&argv[1..])
            .output()
    };
    for sv in ["svA", "svB"] {
        match run(&[
            "btrfs",
            "subvolume",
            "create",
            base.join(sv).to_str().unwrap(),
        ]) {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                skip(
                    "FS02",
                    &format!(
                        "btrfs subvolume create refused: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ),
                );
                return None;
            }
            Err(e) => {
                skip("FS02", &format!("missing btrfs(8) tool: {e}"));
                return None;
            }
        }
    }
    std::fs::write(base.join("svA/f"), pattern_bytes(11, 8192)).unwrap();
    std::fs::write(base.join("svB/f"), pattern_bytes(12, 8192)).unwrap();
    match run(&[
        "btrfs",
        "subvolume",
        "snapshot",
        base.join("svA").to_str().unwrap(),
        base.join("snapA").to_str().unwrap(),
    ]) {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            skip(
                "FS03",
                &format!(
                    "btrfs snapshot refused: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            );
            return None;
        }
        Err(e) => {
            skip("FS03", &format!("missing btrfs(8) tool: {e}"));
            return None;
        }
    }
    Some((base.join("svA/f"), base.join("svB/f"), base.join("snapA/f")))
}

// ---------------------------------------------------------------------------
// Required cells: split/collision, copy-up, wrong-view, transient mmap.
// ---------------------------------------------------------------------------

/// FS02/FS03: the btrfs stat-vs-maps split and the distinct-object
/// raw-key collision are REQUIRED triggers. The oracle must observe an
/// actual equal-maps-key/distinct-stat pair first; the mapping audit
/// then proves raw-key equality yields at most KeyCompatible and never
/// ExactRange for either colliding object.
#[test]
fn split_and_collision_are_required() {
    let manifest = admit_manifest();
    let Some((a, b, snap)) = btrfs_triple(manifest.as_ref()) else {
        return;
    };
    // Trigger proof via the independent oracle: mmap all three in this
    // process and read our own maps rows back.
    let me = std::process::id();
    let mut keep = Vec::new();
    for path in [&a, &b, &snap] {
        let file = std::fs::File::open(path).expect("oracle open");
        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                std::os::unix::io::AsRawFd::as_raw_fd(&file),
                0,
            )
        };
        assert_ne!(map, libc::MAP_FAILED, "oracle mmap");
        keep.push((file, map));
    }
    let key_a = maps_key_for(me, &a).expect("oracle maps row for svA/f");
    let key_b = maps_key_for(me, &b).expect("oracle maps row for svB/f");
    let key_snap = maps_key_for(me, &snap).expect("oracle maps row for snapA/f");
    for (file, map) in keep {
        unsafe { libc::munmap(map, 4096) };
        drop(file);
    }
    let stat_a = stat_key(&a);
    let stat_snap = stat_key(&snap);
    // Distinct stat objects (split part one)...
    assert_ne!(
        (stat_a.0, stat_a.1),
        (stat_snap.0, stat_snap.1),
        "fixture unexercised: svA/f and snapA/f share a stat key"
    );
    // ...with actually colliding raw maps keys (FS03 trigger).
    assert_eq!(
        (key_a.2, key_a.3, key_a.4),
        (key_snap.2, key_snap.3, key_snap.4),
        "fixture unexercised: svA/f and snapA/f maps keys do not collide"
    );
    // Stat-vs-maps split (FS02 trigger): neither stat dev renders in maps.
    assert_ne!(
        stat_a.0,
        (key_a.2 << 8) | key_a.3,
        "fixture unexercised: no stat-vs-maps dev split"
    );
    let b_collides = (key_b.2, key_b.3, key_b.4) == (key_a.2, key_a.3, key_a.4);
    // Mapping-policy audit over the live collision pair.
    let held_a = hold(&a);
    let held_snap = hold(&snap);
    let foreign = temp_dir("foreign");
    let foreign_file = foreign.join("other.bin");
    std::fs::write(&foreign_file, pattern_bytes(99, 8192)).unwrap();
    let held_foreign = hold(&foreign_file);
    let target = OwnedTarget::mapping(&snap).expect("mapping target");
    let (rstart, rend) = target.range().expect("mapping target has range");
    let range = MapRange::new(rstart, rend).unwrap();
    let ctl = control();
    let epoch = epoch();
    let pid = Pid::new(target.pid() as i32).unwrap();
    let obs = ProcessObservation::acquire(pid, &epoch, proc_limits(), &ctl)
        .expect("acquire mapping target");
    let policy = MappingPolicy::NoNewTargetMappings;
    let pool = pool_for(&policy);
    for (name, held) in [("svA", &held_a), ("snapA", &held_snap)] {
        match observe(&pool, held, &obs, range, policy, &ctl) {
            Ok(MappingOutcome::KeyCompatible(_)) => {}
            other => panic!("colliding held {name} must yield KeyCompatible, saw {other:?}"),
        }
    }
    match observe(&pool, &held_foreign, &obs, range, policy, &ctl) {
        Ok(MappingOutcome::Mismatch(e)) if e.kind() == MismatchKind::KeyMismatch => {}
        other => panic!("foreign held object must mismatch, saw {other:?}"),
    }
    assert_eq!(pool.status().active_mappings(), 0);
    assert_eq!(pool.status().unresolved_mappings(), 0);
    pass(
        "FS02/FS03",
        &format!(
            "split dev stat={} maps={}:{}; collision ino={} (svB{}); \
         both colliding helds KeyCompatible, foreign KeyMismatch",
            stat_a.0,
            key_a.2,
            key_a.3,
            key_a.4,
            if b_collides {
                " collides too"
            } else {
                " distinct"
            }
        ),
    );
}

/// FS06: copy-up must actually trigger before any mapping-reuse verdict
/// is evaluated. The old held FD keeps old bytes, the merged path shows
/// new bytes under the SAME stat key, and a retained pre-copy-up proof
/// is refused for the new acquisition, never inherited.
#[test]
fn copy_up_trigger_must_happen() {
    let Some(m) = admit_manifest() else {
        skip(
            "FS06",
            "missing TT04_MANIFEST \
            (run provision_fs.py create --privileged)",
        );
        return;
    };
    if !provisioned(&m, "FS06") {
        return;
    }
    let merged = m.evidence_path(&["ov-xino-off_layout", "merged"]);
    let upper = m.evidence_path(&["ov-xino-off_layout", "upper"]);
    let lower = m.evidence_path(&["ov-xino-off_layout", "lower"]);
    // Per-run victim file so reruns never observe a stale copy-up
    // left in the upper layer by an earlier run. Sized for mapping
    // targets (>= 4096 bytes).
    let victim = format!("victim-{}.txt", unique_tag());
    let mut victim_old = b"lower-victim-original\n".to_vec();
    victim_old.extend_from_slice(&pattern_bytes(81, 8192 - victim_old.len()));
    let mut victim_new = b"upper-victim-rewritten-bytes\n".to_vec();
    victim_new.extend_from_slice(&pattern_bytes(82, 8192 - victim_new.len()));
    std::fs::write(lower.join(&victim), &victim_old).unwrap();
    let merged_victim = merged.join(&victim);
    assert!(merged_victim.exists(), "victim visible through merged view");
    let key_before = stat_key(&merged_victim);
    let held_old = hold(&merged_victim);
    let target = OwnedTarget::mapping(&merged_victim).expect("mapping target");
    let (tstart, tend) = target.range().expect("mapping target has range");
    let range = MapRange::new(tstart, tend).unwrap();
    let ctl = control();
    let epoch = epoch();
    let pid = Pid::new(target.pid() as i32).unwrap();
    let obs = ProcessObservation::acquire(pid, &epoch, proc_limits(), &ctl)
        .expect("acquire mapping target");
    let policy = MappingPolicy::NoNewTargetMappings;
    let pool = pool_for(&policy);
    let proof_old = match observe(&pool, &held_old, &obs, range, policy, &ctl) {
        Ok(MappingOutcome::KeyCompatible(proof)) => proof,
        other => panic!("pre-copy-up observe must be KeyCompatible, saw {other:?}"),
    };
    // Pre-fault the private mapping now: untouched pages would fault
    // through post-copy-up state and prove nothing about retention.
    assert_bytes_eq(
        &target.sample().expect("pre-trigger sample"),
        &victim_old[..4096],
        "pre-trigger target sample",
    );
    // Trigger: data write through the merged view.
    std::fs::write(&merged_victim, &victim_new).unwrap();
    let upper_victim = upper.join(&victim);
    assert!(
        upper_victim.exists(),
        "fixture unexercised: copy-up produced no upper file"
    );
    assert_eq!(
        std::fs::read(lower.join(&victim)).unwrap(),
        victim_old,
        "fixture unexercised: lower layer mutated"
    );
    assert_eq!(
        std::fs::read(&merged_victim).unwrap(),
        victim_new,
        "fixture unexercised: merged view lacks new bytes"
    );
    let key_after = stat_key(&merged_victim);
    // Kernel-transparent following: an overlay read FD opened
    // pre-copy-up serves the NEW upper bytes afterwards (verified
    // against raw pread as well as HeldFile reads). Staleness
    // protection therefore lives in proof rechecks, not fd reads.
    assert_bytes_eq(
        &read_held(&held_old),
        &victim_new,
        "overlay FD must transparently follow copy-up",
    );
    // The pre-faulted private pages, COW-copied from the lower
    // object, keep old bytes: data staleness and metadata staleness
    // diverge here.
    assert_bytes_eq(
        &target.sample().expect("target sample"),
        &victim_old[..4096],
        "retained target mapping",
    );
    // The new acquisition must not inherit the old proof, and the
    // same old descriptor must not reuse it either: (dev, ino, size)
    // are IDENTICAL across this copy-up, so only the metadata leg
    // (mtime/ctime) plus descriptor identity refuse it.
    assert_eq!(
        (key_before.0, key_before.1, key_before.2),
        (key_after.0, key_after.1, key_after.2),
        "this copy-up must preserve the raw stat key"
    );
    let held_new = hold(&merged_victim);
    let err = scopebase_linux::mapping::observe_mapping(
        MappingRequest {
            pool: &pool,
            held: Arc::clone(&held_new),
            process: &obs,
            range,
            policy,
            retained: Some(&proof_old),
            limits: mapping_limits(0),
        },
        &ctl,
    )
    .expect_err("retained pre-copy-up proof must be refused for the new object");
    assert!(
        matches!(
            err.error().reason(),
            Reason::ChangedSource | Reason::WrongContext
        ),
        "refusal must name ChangedSource/WrongContext, saw {:?}",
        err.error().reason()
    );
    let same_fd_err = scopebase_linux::mapping::observe_mapping(
        MappingRequest {
            pool: &pool,
            held: Arc::clone(&held_old),
            process: &obs,
            range,
            policy,
            retained: Some(&proof_old),
            limits: mapping_limits(0),
        },
        &ctl,
    )
    .expect_err("same-FD reuse of the pre-copy-up proof must be refused");
    assert_eq!(
        same_fd_err.error().reason(),
        Reason::ChangedSource,
        "same-FD reuse must name ChangedSource, saw {:?}",
        same_fd_err.error().reason()
    );
    // A fresh observation re-establishes the key relation on new metadata.
    match observe(&pool, &held_new, &obs, range, policy, &ctl) {
        Ok(MappingOutcome::KeyCompatible(proof)) => {
            assert_eq!(proof.stat().len(), key_after.2);
        }
        other => panic!("post-copy-up observe must be KeyCompatible, saw {other:?}"),
    }
    pass(
        "FS06",
        &format!(
            "upper artifact present, lower intact; stat key {key_before:?} -> \
         {key_after:?}; old proof refused with {:?}; fresh KeyCompatible",
            err.error().reason()
        ),
    );
}

/// FS08 wrong-view negative: the foreign-mount sleeper maps the same
/// pathname the observer holds, but its private overmount resolves that
/// path to a DIFFERENT object. The observer's held object must MISMATCH
/// the target range; the actually-mapped object must match. Keys, not
/// paths, decide.
#[test]
fn wrong_mount_view_rejected() {
    let Some(m) = admit_manifest() else {
        skip(
            "FS08-view",
            "missing TT04_MANIFEST \
            (run provision_fs.py create --privileged)",
        );
        return;
    };
    if !provisioned(&m, "FS08") {
        return;
    }
    let pid = m.proc_pid("mnt-sleeper");
    let report = m.evidence_path(&["ns_reports", "mnt"]);
    let range_text = report_value(&report, "range");
    assert_ne!(
        range_text, "none",
        "fixture unexercised: sleeper mapped nothing"
    );
    let (start, end) = parse_range(&range_text);
    // Fixture proof: the target's maps row names the observer-visible
    // pathname but the FOREIGN object's key.
    let view_file = m.run_root.join("ns/view/data.txt");
    let alt_file = m.run_root.join("ns/alt/data.txt");
    let oracle_row = maps_key_for(pid, &view_file)
        .unwrap_or_else(|| panic!("fixture unexercised: no maps row for {view_file:?} in {pid}"));
    let stat_view = stat_key(&view_file);
    let stat_alt = stat_key(&alt_file);
    assert_ne!(
        (stat_view.0, stat_view.1),
        (stat_alt.0, stat_alt.1),
        "fixture unexercised: view and alt are the same object"
    );
    // The target-view pathname resolves to the FOREIGN object: the maps
    // row carries the alt inode, never the observer-view inode.
    assert_eq!(
        oracle_row.4, stat_alt.1,
        "fixture unexercised: target maps row lacks the alt inode"
    );
    assert_ne!(
        oracle_row.4, stat_view.1,
        "fixture unexercised: target maps row shows the observer inode"
    );
    assert_eq!(
        (oracle_row.0, oracle_row.1),
        (start, end),
        "fixture unexercised: maps row disagrees with sleeper report"
    );
    // Production: cross-view association is refused in both directions.
    // The held mount id has no row in the foreign table (copies are
    // renumbered), so even the actually-mapped object cannot be proven
    // across views: fail closed, never guess.
    let ctl = control();
    let epoch = epoch();
    let pid = Pid::new(pid as i32).unwrap();
    let obs = ProcessObservation::acquire(pid, &epoch, proc_limits(), &ctl)
        .expect("acquire foreign-view target");
    let policy = MappingPolicy::NoNewTargetMappings;
    let pool = pool_for(&policy);
    let range = MapRange::new(start, end).unwrap();
    for (name, path) in [("observer-view", &view_file), ("alt", &alt_file)] {
        let held = hold(path);
        match observe(&pool, &held, &obs, range, policy, &ctl) {
            Ok(MappingOutcome::Inconclusive(reason))
                if reason.kind() == InconclusiveKind::MountUnresolved => {}
            other => panic!("cross-view held {name} must be MountUnresolved, saw {other:?}"),
        }
    }
    // Aligned control: with agreeing views the same alt object matches.
    let local = OwnedTarget::mapping(&alt_file).expect("local alt target");
    let (lstart, lend) = local.range().expect("mapping target has range");
    let lpid = Pid::new(local.pid() as i32).unwrap();
    let lobs = ProcessObservation::acquire(lpid, &epoch, proc_limits(), &ctl)
        .expect("acquire local target");
    let held_alt = hold(&alt_file);
    match observe(
        &pool,
        &held_alt,
        &lobs,
        MapRange::new(lstart, lend).unwrap(),
        policy,
        &ctl,
    ) {
        Ok(MappingOutcome::KeyCompatible(_)) => {}
        other => panic!("same-view alt observe must match, saw {other:?}"),
    }
    pass(
        "FS08-view",
        &format!(
            "row ino={} (alt={}, view={}); both cross-view legs \
         MountUnresolved; same-view control KeyCompatible",
            oracle_row.4, stat_alt.1, stat_view.1
        ),
    );
}

fn audit_subject_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_scopebase-tt04-audit-subject"))
}

/// F18: an FS10 observation only counts when the production phase
/// genuinely observed the mapping. The subject exits 0 and writes a
/// `verdict=...` report for every completed observation INCLUDING
/// failures, so a bare `starts_with("verdict=")` check passes
/// vacuously on `verdict=Failure` (and the planted leg would flag
/// its plant even when the observation itself failed, since the
/// plant runs independently). Only the two positive outcomes gate.
fn positive_verdict(report: &str) -> bool {
    matches!(
        report.trim(),
        "verdict=ExactRange" | "verdict=KeyCompatible"
    )
}

/// FS10: the independent syscall audit detects even a transient
/// target-backed mmap during the production no-new-mapping phase. The
/// planted violation MUST be flagged (sensitivity); the clean NoNew
/// phase MUST show zero target-backed maps while still showing
/// allocator mmaps (instrument liveness, not a deaf tracer).
#[test]
fn transient_target_mmap_detected() {
    let yama = match audit::preflight() {
        Ok(note) => note,
        Err(e) => {
            skip("FS10", &format!("ptrace preflight refused: {e}"));
            return;
        }
    };
    let dir = temp_dir("audit");
    let target_file = dir.join("audit-target.bin");
    std::fs::write(&target_file, pattern_bytes(51, 8192)).unwrap();
    let target = OwnedTarget::mapping(&target_file).expect("audit target");
    let (start, end) = target.range().expect("mapping target has range");
    let range_text = format!("{start:x}-{end:x}");
    let st = std::fs::metadata(&target_file).unwrap();
    let config = AuditConfig {
        target_dev: st.dev() as u64,
        target_ino: st.ino(),
        max_entries: 4096,
        timeout: Duration::from_secs(60),
    };
    let subject = audit_subject_bin();
    // Sensitivity leg: the subject plants one transient target mmap.
    let plant_report = dir.join("plant.report");
    let planted = audit::audit_subject(
        &subject,
        &[
            "observe".to_string(),
            "--target".to_string(),
            target_file.to_string_lossy().into_owned(),
            "--pid".to_string(),
            target.pid().to_string(),
            "--range".to_string(),
            range_text.clone(),
            "--plant-violation".to_string(),
            "--report".to_string(),
            plant_report.to_string_lossy().into_owned(),
        ],
        &config,
    )
    .expect("planted audit run");
    assert_eq!(planted.exit_code, Some(0), "planted subject must exit 0");
    assert!(
        plant_report.exists(),
        "fixture unexercised: planted subject wrote no verdict report"
    );
    // F18: the sensitivity leg only counts on a genuine observation;
    // the plant runs even when the observation failed.
    let planted_verdict = std::fs::read_to_string(&plant_report)
        .expect("fixture unexercised: planted subject wrote no report");
    assert!(
        positive_verdict(&planted_verdict),
        "fixture unexercised: planted observation was not positive: {}",
        planted_verdict.trim()
    );
    let planted_hit = planted
        .target_backed_mmaps()
        .into_iter()
        .find(|e| e.succeeded() && e.len >= 4096);
    let Some(hit) = planted_hit else {
        panic!("audit missed the planted transient target mmap");
    };
    let covered = planted
        .munmaps()
        .into_iter()
        .any(|u| u.addr <= hit.result_addr() && hit.result_addr() < u.addr + u.len);
    assert!(covered, "planted transient lacks its munmap close");
    // R29: the genuine plant verifies (enter sample and maps row
    // agree); R28: nothing in the planted ledger is unattributed.
    assert!(!hit.unattributed, "planted target map failed verification");
    assert!(
        planted.unattributed_mmaps().is_empty(),
        "planted ledger has unattributed maps: {:?}",
        planted.unattributed_mmaps()
    );
    // Clean leg: the real NoNew production phase maps no target bytes.
    let clean_report = dir.join("clean.report");
    let clean = audit::audit_subject(
        &subject,
        &[
            "observe".to_string(),
            "--target".to_string(),
            target_file.to_string_lossy().into_owned(),
            "--pid".to_string(),
            target.pid().to_string(),
            "--range".to_string(),
            range_text,
            "--report".to_string(),
            clean_report.to_string_lossy().into_owned(),
        ],
        &config,
    )
    .expect("clean audit run");
    assert_eq!(clean.exit_code, Some(0), "clean subject must exit 0");
    let verdict = std::fs::read_to_string(&clean_report)
        .expect("fixture unexercised: clean subject wrote no report");
    // F18: the clean leg only counts on a genuine positive
    // observation, never on a Failure/Inconclusive/Mismatch that
    // trivially maps no target bytes.
    assert!(
        positive_verdict(&verdict),
        "fixture unexercised: clean observation was not positive: {}",
        verdict.trim()
    );
    assert!(
        clean.target_backed_mmaps().is_empty(),
        "NoNew phase mapped target bytes: {:?}",
        clean.target_backed_mmaps()
    );
    // R28: clean means fully attributed, not merely target-free.
    assert!(
        clean.unattributed_mmaps().is_empty(),
        "NoNew phase has unattributed maps: {:?}",
        clean.unattributed_mmaps()
    );
    assert!(
        clean.anonymous_mmaps() >= 1,
        "fixture unexercised: tracer saw no allocator mmaps (deaf?)"
    );
    assert!(!clean.truncated, "clean ledger truncated");
    pass(
        "FS10",
        &format!(
            "yama {yama}; planted mmap@{:#x} flagged+munmap-closed; clean \
         phase: {} anon mmaps, 0 target-backed, {}",
            hit.result_addr(),
            clean.anonymous_mmaps(),
            verdict.trim()
        ),
    );
}

/// F15: the audit follows worker threads. The subject maps the target
/// only from a spawned worker (its main thread never touches it); the
/// tracer must attribute that map. The old main-only tracer saw an
/// empty target ledger here.
#[test]
fn audit_follows_worker_thread_maps() {
    let yama = match audit::preflight() {
        Ok(note) => note,
        Err(e) => {
            skip("FS10", &format!("ptrace preflight refused: {e}"));
            return;
        }
    };
    let dir = temp_dir("audit-thread");
    let target_file = dir.join("thread-target.bin");
    std::fs::write(&target_file, pattern_bytes(77, 8192)).unwrap();
    let st = std::fs::metadata(&target_file).unwrap();
    let config = AuditConfig {
        target_dev: st.dev() as u64,
        target_ino: st.ino(),
        max_entries: 4096,
        timeout: Duration::from_secs(60),
    };
    let worker_report = dir.join("thread.report");
    let traced = audit::audit_subject(
        &audit_subject_bin(),
        &[
            "thread-plant".to_string(),
            "--target".to_string(),
            target_file.to_string_lossy().into_owned(),
            "--report".to_string(),
            worker_report.to_string_lossy().into_owned(),
        ],
        &config,
    )
    .expect("thread audit run");
    assert_eq!(traced.exit_code, Some(0), "thread subject must exit 0");
    assert_eq!(
        std::fs::read_to_string(&worker_report)
            .expect("worker wrote its report")
            .trim(),
        "worker=0",
        "fixture unexercised: worker plant failed"
    );
    assert!(
        traced.threads_seen >= 2,
        "tracer saw {} threads, want main + worker",
        traced.threads_seen
    );
    let hit = traced
        .target_backed_mmaps()
        .into_iter()
        .find(|e| e.succeeded() && e.len >= 4096);
    let Some(hit) = hit else {
        panic!("audit missed the worker-thread target mmap");
    };
    let covered = traced
        .munmaps()
        .into_iter()
        .any(|u| u.addr <= hit.result_addr() && hit.result_addr() < u.addr + u.len);
    assert!(covered, "worker transient lacks its munmap close");
    // R29: the worker plant verifies like any genuine map.
    assert!(!hit.unattributed, "worker target map failed verification");
    assert!(
        traced.unattributed_mmaps().is_empty(),
        "worker ledger has unattributed maps: {:?}",
        traced.unattributed_mmaps()
    );
    pass(
        "FS10",
        &format!(
            "yama {yama}; worker mmap@{:#x} flagged+munmap-closed; threads_seen={}",
            hit.result_addr(),
            traced.threads_seen
        ),
    );
}

/// R25/S47: the tracer compares TracerPid against its own TID, not
/// the process ID. The audit runs on a worker thread (TID != PID)
/// over a subject whose fork child rendezvouses across the parent's
/// exec: the child waits for the marker only the post-exec image
/// writes (which proves the tracer processed the exec), then stops
/// itself and writes the signal once resumed. The child must be
/// followed to its exit, so the signal is present when the audit
/// returns. The old PID-compare prune dropped the live child and
/// never resumed it, so the signal never landed. No nap schedules
/// this: the marker causal chain plus the mtime order below force
/// and verify the interleaving on any scheduler.
#[test]
fn audit_from_worker_thread_follows_exec_survivor() {
    let yama = match audit::preflight() {
        Ok(note) => note,
        Err(e) => {
            skip("FS10", &format!("ptrace preflight refused: {e}"));
            return;
        }
    };
    let dir = temp_dir("audit-survivor");
    let signal = dir.join("survivor.signal");
    let marker = dir.join("survivor.marker");
    let st = std::fs::metadata(&dir).unwrap();
    let config = AuditConfig {
        target_dev: st.dev() as u64,
        target_ino: st.ino(),
        max_entries: 4096,
        timeout: Duration::from_secs(60),
    };
    let subject = audit_subject_bin();
    let signal_arg = signal.to_string_lossy().into_owned();
    let marker_arg = marker.to_string_lossy().into_owned();
    // The audit itself runs on a worker thread: the tracer TID
    // differs from the process ID, which is exactly the case the
    // old PID-compare prune got wrong.
    let traced = std::thread::Builder::new()
        .name("r25-auditor".to_string())
        .spawn(move || {
            audit::audit_subject(
                &subject,
                &[
                    "fork-exec-survivor".to_string(),
                    "--signal".to_string(),
                    signal_arg,
                    "--marker".to_string(),
                    marker_arg,
                ],
                &config,
            )
        })
        .expect("auditor thread spawns")
        .join()
        .expect("auditor thread joins")
        .expect("survivor audit run");
    assert_eq!(traced.exit_code, Some(0), "exec target must exit 0");
    assert!(
        traced.threads_seen >= 2,
        "tracer saw {} threads, want main + survivor",
        traced.threads_seen
    );
    assert_eq!(
        std::fs::read_to_string(&signal)
            .expect("survivor wrote its signal")
            .trim(),
        "hi",
        "audit returned before the exec-surviving child exited"
    );
    // S47: the schedule, verified explicitly. The marker proves the
    // tracer processed the exec (no post-exec byte runs before the
    // resume); the mtime order proves the child wrote only after.
    let marker_time = std::fs::metadata(&marker)
        .expect("post-exec marker exists")
        .modified()
        .expect("marker mtime");
    let signal_time = std::fs::metadata(&signal)
        .expect("signal exists")
        .modified()
        .expect("signal mtime");
    assert!(
        signal_time >= marker_time,
        "survivor must write after the processed exec"
    );
    pass(
        "FS10",
        &format!(
            "yama {yama}; worker-thread audit followed the fork survivor across exec; threads_seen={}",
            traced.threads_seen
        ),
    );
}

/// R28: a successful mapping the tracer cannot attribute is an
/// incomplete audit, never a clean report. The subject clears its
/// own dumpability (fd and maps identity reads deny even to the
/// same-uid tracer — probed EACCES), then maps one target page
/// transiently and reports `mapped=0`, proving the map really
/// happened. The audit must refuse with `unattributable`; the old
/// tracer returned Ok with an empty target ledger.
#[test]
fn audit_refuses_unattributable_nondumpable_map() {
    let yama = match audit::preflight() {
        Ok(note) => note,
        Err(e) => {
            skip("FS10", &format!("ptrace preflight refused: {e}"));
            return;
        }
    };
    let dir = temp_dir("audit-nondump");
    let target_file = dir.join("nondump-target.bin");
    std::fs::write(&target_file, pattern_bytes(91, 8192)).unwrap();
    let st = std::fs::metadata(&target_file).unwrap();
    let config = AuditConfig {
        target_dev: st.dev() as u64,
        target_ino: st.ino(),
        max_entries: 4096,
        timeout: Duration::from_secs(60),
    };
    let map_report = dir.join("nondump.report");
    let error = audit::audit_subject(
        &audit_subject_bin(),
        &[
            "nondumpable-map".to_string(),
            "--target".to_string(),
            target_file.to_string_lossy().into_owned(),
            "--report".to_string(),
            map_report.to_string_lossy().into_owned(),
        ],
        &config,
    )
    .expect_err("non-dumpable target map must be audit-incomplete");
    assert!(
        error.to_string().contains("unattributable"),
        "unexpected refusal: {error}"
    );
    assert_eq!(
        std::fs::read_to_string(&map_report)
            .expect("subject wrote its report")
            .trim(),
        "mapped=0",
        "fixture unexercised: subject never mapped"
    );
    pass(
        "FS10",
        &format!("yama {yama}; non-dumpable target map refused as incomplete"),
    );
}

/// R30: the tracer forwards genuine SIGTRAP delivery instead of
/// swallowing it. The subject's handler acknowledges to the
/// report; the audit must return Ok with exit 0 AND a `trapped`
/// report. The old tracer resumed event-zero traps without
/// delivery, so the handler never ran and the report stayed empty.
#[test]
fn audit_forwards_genuine_sigtrap() {
    let yama = match audit::preflight() {
        Ok(note) => note,
        Err(e) => {
            skip("FS10", &format!("ptrace preflight refused: {e}"));
            return;
        }
    };
    let dir = temp_dir("audit-trap");
    let report = dir.join("trap.report");
    let st = std::fs::metadata(&dir).unwrap();
    let config = AuditConfig {
        target_dev: st.dev() as u64,
        target_ino: st.ino(),
        max_entries: 4096,
        timeout: Duration::from_secs(60),
    };
    let traced = audit::audit_subject(
        &audit_subject_bin(),
        &[
            "trap-ack".to_string(),
            "--report".to_string(),
            report.to_string_lossy().into_owned(),
        ],
        &config,
    )
    .expect("trap audit run");
    assert_eq!(traced.exit_code, Some(0), "trap subject must exit 0");
    assert_eq!(
        std::fs::read_to_string(&report)
            .expect("subject created its report")
            .trim(),
        "trapped",
        "SIGTRAP handler never ran: genuine trap swallowed"
    );
    assert!(
        traced.unattributed_mmaps().is_empty(),
        "trap subject has unattributed maps: {:?}",
        traced.unattributed_mmaps()
    );
    pass(
        "FS10",
        &format!("yama {yama}; genuine SIGTRAP forwarded, handler acked"),
    );
}

/// S30: an anonymous mremap is ordinary allocator activity: the
/// audit classifies it anonymous, never unattributed. Before the fix
/// every anonymous remap was unattributed (no pathname) and a
/// successful mmap→mremap refused the audit.
#[test]
fn audit_mremap_anon_stays_attributed() {
    match audit::preflight() {
        Ok(_) => {}
        Err(e) => {
            skip("FS10", &format!("ptrace preflight refused: {e}"));
            return;
        }
    };
    let dir = temp_dir("audit-mremap-anon");
    let target_file = dir.join("mremap-target.bin");
    std::fs::write(&target_file, pattern_bytes(91, 8192)).unwrap();
    let st = std::fs::metadata(&target_file).unwrap();
    let config = AuditConfig {
        target_dev: st.dev() as u64,
        target_ino: st.ino(),
        max_entries: 4096,
        timeout: Duration::from_secs(60),
    };
    let report = dir.join("mremap.report");
    let traced = audit::audit_subject(
        &audit_subject_bin(),
        &[
            "mremap-anon".to_string(),
            "--report".to_string(),
            report.to_string_lossy().into_owned(),
        ],
        &config,
    )
    .expect("mremap-anon audit run");
    assert_eq!(traced.exit_code, Some(0), "subject must exit 0");
    assert_eq!(
        std::fs::read_to_string(&report)
            .expect("subject wrote its report")
            .trim(),
        "mremapped=0",
        "fixture unexercised: anonymous mremap failed"
    );
    let ours = traced.mmaps.iter().find(|e| {
        e.nr == libc::SYS_mremap && e.succeeded() && e.len == 4096 && e.new_len == 8192
    });
    let Some(ours) = ours else {
        panic!("audit missed the 4K->8K anonymous mremap");
    };
    assert!(
        ours.anonymous,
        "remap of anonymous memory must stay anonymous"
    );
    assert!(
        !ours.unattributed,
        "anonymous remap must not be unattributed"
    );
    assert!(
        traced
            .mmaps
            .iter()
            .filter(|e| e.nr == libc::SYS_mremap && e.succeeded())
            .all(|e| !e.unattributed),
        "a successful mremap was left unattributed"
    );
}

/// S30 control: a file-backed mremap keeps its target identity
/// across the remap. This passed before the fix too: it pins that
/// the anonymous/missing distinction did not disturb file remaps.
#[test]
fn audit_mremap_file_preserves_identity() {
    match audit::preflight() {
        Ok(_) => {}
        Err(e) => {
            skip("FS10", &format!("ptrace preflight refused: {e}"));
            return;
        }
    };
    let dir = temp_dir("audit-mremap-file");
    let target_file = dir.join("mremap-target.bin");
    std::fs::write(&target_file, pattern_bytes(93, 8192)).unwrap();
    let st = std::fs::metadata(&target_file).unwrap();
    let config = AuditConfig {
        target_dev: st.dev() as u64,
        target_ino: st.ino(),
        max_entries: 4096,
        timeout: Duration::from_secs(60),
    };
    let report = dir.join("mremap.report");
    let traced = audit::audit_subject(
        &audit_subject_bin(),
        &[
            "mremap-file".to_string(),
            "--target".to_string(),
            target_file.to_string_lossy().into_owned(),
            "--report".to_string(),
            report.to_string_lossy().into_owned(),
        ],
        &config,
    )
    .expect("mremap-file audit run");
    assert_eq!(traced.exit_code, Some(0), "subject must exit 0");
    assert_eq!(
        std::fs::read_to_string(&report)
            .expect("subject wrote its report")
            .trim(),
        "mremapped=0",
        "fixture unexercised: file mremap failed"
    );
    let ours = traced.mmaps.iter().find(|e| {
        e.nr == libc::SYS_mremap && e.succeeded() && e.len == 4096 && e.new_len == 8192
    });
    let Some(ours) = ours else {
        panic!("audit missed the 4K->8K file mremap");
    };
    assert!(!ours.anonymous, "file remap must not be anonymous");
    assert_eq!(
        ours.dev,
        Some(config.target_dev),
        "remap lost the target device"
    );
    assert_eq!(
        ours.ino,
        Some(config.target_ino),
        "remap lost the target inode"
    );
    assert!(!ours.unattributed, "file remap must verify");
}

/// S06: a worker that execs is renumbered to the leader before the
/// EXEC event; the tracer must reset the syscall phase there. The
/// post-exec target map really happens (the report proves it), so a
/// phase-keeping tracer records it with a following entry's -ENOSYS
/// instead of its success.
#[test]
fn audit_nonleader_exec_keeps_phase() {
    match audit::preflight() {
        Ok(_) => {}
        Err(e) => {
            skip("FS10", &format!("ptrace preflight refused: {e}"));
            return;
        }
    };
    let dir = temp_dir("audit-nonleader-exec");
    let target_file = dir.join("exec-target.bin");
    std::fs::write(&target_file, pattern_bytes(95, 8192)).unwrap();
    let st = std::fs::metadata(&target_file).unwrap();
    let config = AuditConfig {
        target_dev: st.dev() as u64,
        target_ino: st.ino(),
        max_entries: 4096,
        timeout: Duration::from_secs(60),
    };
    let report = dir.join("exec.report");
    let traced = audit::audit_subject(
        &audit_subject_bin(),
        &[
            "nonleader-exec".to_string(),
            "--target".to_string(),
            target_file.to_string_lossy().into_owned(),
            "--report".to_string(),
            report.to_string_lossy().into_owned(),
        ],
        &config,
    )
    .expect("nonleader-exec audit run");
    assert_eq!(traced.exit_code, Some(0), "post-exec subject must exit 0");
    assert_eq!(
        std::fs::read_to_string(&report)
            .expect("subject wrote its report")
            .trim(),
        "mapped=0",
        "fixture unexercised: post-exec map failed"
    );
    assert!(
        traced.threads_seen >= 2,
        "tracer saw {} threads, want main + exec worker",
        traced.threads_seen
    );
    let hit = traced
        .target_backed_mmaps()
        .into_iter()
        .find(|e| e.succeeded() && e.len >= 4096);
    let Some(hit) = hit else {
        panic!("post-exec target map recorded as failure (inverted phase)");
    };
    assert!(
        !hit.unattributed,
        "post-exec target map failed verification"
    );
}

/// S06: the same post-exec map after a plain leader exec (no
/// renumber, threads_seen stays 1). The phase reset plus
/// self-synchronization must hold here too: the execve exit stop
/// still follows the event and must consume without flipping.
#[test]
fn audit_leader_exec_keeps_phase() {
    match audit::preflight() {
        Ok(_) => {}
        Err(e) => {
            skip("FS10", &format!("ptrace preflight refused: {e}"));
            return;
        }
    };
    let dir = temp_dir("audit-leader-exec");
    let target_file = dir.join("exec-target.bin");
    std::fs::write(&target_file, pattern_bytes(95, 8192)).unwrap();
    let st = std::fs::metadata(&target_file).unwrap();
    let config = AuditConfig {
        target_dev: st.dev() as u64,
        target_ino: st.ino(),
        max_entries: 4096,
        timeout: Duration::from_secs(60),
    };
    let report = dir.join("exec.report");
    let traced = audit::audit_subject(
        &audit_subject_bin(),
        &[
            "leader-exec".to_string(),
            "--target".to_string(),
            target_file.to_string_lossy().into_owned(),
            "--report".to_string(),
            report.to_string_lossy().into_owned(),
        ],
        &config,
    )
    .expect("leader-exec audit run");
    assert_eq!(traced.exit_code, Some(0), "post-exec subject must exit 0");
    assert_eq!(
        std::fs::read_to_string(&report)
            .expect("subject wrote its report")
            .trim(),
        "mapped=0",
        "fixture unexercised: post-exec map failed"
    );
    assert_eq!(
        traced.threads_seen, 1,
        "leader exec must not invent threads (saw {})",
        traced.threads_seen
    );
    let hit = traced
        .target_backed_mmaps()
        .into_iter()
        .find(|e| e.succeeded() && e.len >= 4096);
    let Some(hit) = hit else {
        panic!("post-exec target map recorded as failure (inverted phase)");
    };
    assert!(
        !hit.unattributed,
        "post-exec target map failed verification"
    );
}

fn audit_denial_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_scopebase-tt04-audit-denial"))
}

/// Run the denial driver; returns its stdout, skipping the test on
/// environmental refusal (no ptrace / no seccomp install).
fn denial_verdict(mode: &str, dir: &Path, subject: &[String]) -> String {
    let target_file = dir.join("denial-target.bin");
    if !target_file.exists() {
        std::fs::write(&target_file, pattern_bytes(97, 8192)).unwrap();
    }
    let output = std::process::Command::new(audit_denial_bin())
        .arg(mode)
        .arg("--target")
        .arg(&target_file)
        .arg("--timeout")
        .arg("10")
        .arg("--")
        .arg(audit_subject_bin())
        .args(subject)
        .output()
        .expect("denial driver runs");
    // S55: the documented exit-3 setup response must be recognized
    // BEFORE asserting success: on a host that permits ptrace but
    // denies the filter install, success-first ordering panics
    // instead of skipping.
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.code() == Some(3) {
        // S55-round4: the validated setup response returns BEFORE the
        // success assertion — `skip` only prints, so falling through
        // panics on the environmental refusal instead of skipping.
        if let Some(setup) = stdout.strip_prefix("setup=") {
            skip("FS10", &format!("denial driver environmental: {setup}"));
            return stdout;
        }
    }
    assert!(
        output.status.success(),
        "denial driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

/// S55-round4: forced environmental-refusal control. The driver's
/// `setup-probe` mode always exits 3 with a `setup=` body; the
/// harness must return it (callers skip on the prefix) instead of
/// panicking at the success assertion. Pre-fix this panicked.
#[test]
fn denial_setup_probe_returns_before_success_assertion() {
    let dir = temp_dir("audit-deny-setup-probe");
    let verdict = denial_verdict("setup-probe", &dir, &[]);
    assert!(
        verdict.starts_with("setup=forced-probe"),
        "forced setup refusal must return its body, got: {verdict}"
    );
    pass("FS10", "forced exit-3 returns before the success assertion");
}

/// S05: a caller seccomp filter denying only PTRACE_GETREGS still
/// permits TRACEME, SETOPTIONS and SYSCALL. The audit must report
/// an incomplete audit, never an exit-zero run with empty ledgers.
#[test]
fn audit_getregs_denial_is_incomplete_not_clean() {
    match audit::preflight() {
        Ok(_) => {}
        Err(e) => {
            skip("FS10", &format!("ptrace preflight refused: {e}"));
            return;
        }
    };
    let dir = temp_dir("audit-deny-getregs");
    let report = dir.join("denied.report");
    let verdict = denial_verdict(
        "getregs",
        &dir,
        &[
            "mremap-anon".to_string(),
            "--report".to_string(),
            report.to_string_lossy().into_owned(),
        ],
    );
    if verdict.starts_with("setup=") {
        return;
    }
    assert!(
        verdict.starts_with("verdict=err") && verdict.contains("PTRACE_GETREGS"),
        "GETREGS denial must fail loud, got: {verdict}"
    );
}

/// S05-round3: GETREGS denied AFTER a mmap-family entry is recorded
/// must fail at the matching EXIT sample — never as a fabricated
/// `result=-1` mapping, and never misreported as an entry failure.
/// The `exit:` marker distinguishes this path: restoring only the
/// former exit fallback yields `enter:` (the next entry sample fails
/// first) and fails this test. Absence of `unresolved tracees` proves
/// the error-path drain retired every tracee it held.
#[test]
fn audit_getregs_exit_denial_is_incomplete_not_clean() {
    match audit::preflight() {
        Ok(_) => {}
        Err(e) => {
            skip("FS10", &format!("ptrace preflight refused: {e}"));
            return;
        }
    };
    let dir = temp_dir("audit-deny-getregs-exit");
    let report = dir.join("denied.report");
    let verdict = denial_verdict(
        "getregs-exit",
        &dir,
        &[
            "mremap-anon".to_string(),
            "--report".to_string(),
            report.to_string_lossy().into_owned(),
        ],
    );
    if verdict.starts_with("setup=") {
        return;
    }
    assert!(
        verdict.starts_with("verdict=err") && verdict.contains("PTRACE_GETREGS exit:"),
        "exit-sample GETREGS denial must fail loud at the exit, got: {verdict}"
    );
    assert!(
        !verdict.contains("unresolved tracees"),
        "exit-path drain must retire every tracee, got: {verdict}"
    );
}

/// S54: with stdout refused (/dev/full), the denial driver exits 4
/// with a stderr note instead of panicking in `println!`. Every
/// driver response path (setup and verdict) funnels through the
/// fallible emitter, so any valid invocation reaches it.
#[test]
fn audit_denial_dead_stdout_exits_without_panic() {
    use std::process::Stdio;
    if !std::path::Path::new("/dev/full").exists() {
        skip("FS10", "no /dev/full on this host");
        return;
    }
    let dir = temp_dir("audit-deny-full");
    let target_file = dir.join("denial-target.bin");
    std::fs::write(&target_file, pattern_bytes(97, 8192)).unwrap();
    let report = dir.join("denied.report");
    let full = std::fs::File::create("/dev/full").unwrap();
    let output = std::process::Command::new(audit_denial_bin())
        .arg("getregs")
        .arg("--target")
        .arg(&target_file)
        .arg("--timeout")
        .arg("10")
        .arg("--")
        .arg(audit_subject_bin())
        .arg("mremap-anon")
        .arg("--report")
        .arg(&report)
        .stdout(Stdio::from(full))
        .output()
        .expect("denial driver runs");
    assert_eq!(
        output.status.code(),
        Some(4),
        "dead stdout must exit 4, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("panicked"),
        "driver panicked on dead stdout"
    );
}

/// Run the denial driver in a preflight-denial mode with a bounded
/// wait: a hung probe (the S52 regression) is killed and fails the
/// test instead of hanging the suite.
fn preflight_denial_output(mode: &str) -> std::process::Output {
    use std::time::{Duration, Instant};
    let mut child = std::process::Command::new(audit_denial_bin())
        .arg(mode)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("denial driver spawns");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match child.try_wait().expect("try_wait runs") {
            Some(_) => break child.wait_with_output().expect("output collected"),
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("denial driver hung in {mode} mode (S52 regression)");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

/// S52: with PTRACE_CONT denied, the preflight must refuse naming
/// the failed resume — not strand its child stopped and block in
/// the next waitpid forever. The old code ignored the CONT result
/// and hung; the bounded wait above kills that hang and fails.
#[test]
fn preflight_denied_cont_refuses_without_hang() {
    let output = preflight_denial_output("preflight-cont");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.code() == Some(3) {
        assert!(
            stdout.starts_with("setup="),
            "exit 3 must carry its setup reason, got: {stdout}"
        );
        return;
    }
    assert!(
        output.status.success(),
        "driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.starts_with("verdict=err") && stdout.contains("resume"),
        "CONT denial must fail loud naming resume, got: {stdout}"
    );
}

/// S52: with the wait syscall denied, the preflight must fail naming
/// the wait failure and its unproven reap — never report a clean
/// refusal over a child it could not observe, and never hang.
#[test]
fn preflight_denied_wait_fails_with_custody_note() {
    let output = preflight_denial_output("preflight-wait");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.code() == Some(3) {
        assert!(
            stdout.starts_with("setup="),
            "exit 3 must carry its setup reason, got: {stdout}"
        );
        return;
    }
    assert!(
        output.status.success(),
        "driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.starts_with("verdict=err")
            && stdout.contains("wait")
            && stdout.contains("not proven reaped"),
        "wait denial must fail loud with custody note, got: {stdout}"
    );
}

/// S52-round4: with CONT and both kill routes denied, the preflight
/// must refuse naming the failed resume AND its unresolved custody —
/// the EPERM existence probe means present-but-unobservable, never
/// gone. The old code returned "retired" on any probe failure and
/// omitted the custody note. The victim is identified independently
/// (a live ptrace-stopped child of the driver, observed mid-run —
/// after the tracer exits it resumes and self-exits, so no post-hoc
/// orphan scan can see it); the custody note is the fix assertion.
#[test]
fn preflight_cont_and_signal_denial_reports_unreaped_child() {
    use std::time::{Duration, Instant};
    let mut child = std::process::Command::new(audit_denial_bin())
        .arg("preflight-contkill")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("denial driver spawns");
    let driver_pid = child.id();
    // The victim stops within milliseconds and stays stopped for the
    // driver's whole 5s retirement window: poll for a ptrace-stopped
    // (state t) child of OUR driver pid. PPid attribution makes
    // parallel tests' victims impossible to misattribute.
    let mut victim: Option<(u32, u64)> = None;
    let deadline = Instant::now() + Duration::from_secs(8);
    while victim.is_none() && Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        victim = ptrace_stopped_child(driver_pid);
        if victim.is_none() {
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match child.try_wait().expect("try_wait runs") {
            Some(_) => break,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("denial driver hung in preflight-contkill mode");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
    let output = child.wait_with_output().expect("output collected");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.code() == Some(3) {
        assert!(
            stdout.starts_with("setup="),
            "exit 3 must carry its setup reason, got: {stdout}"
        );
        return;
    }
    assert!(
        output.status.success(),
        "driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.starts_with("verdict=err")
            && stdout.contains("resume")
            && stdout.contains("not proven reaped"),
        "CONT+signal denial must fail loud with custody note, got: {stdout}"
    );
    let (victim_pid, victim_start) = victim.expect(
        "a live ptrace-stopped driver child must be observed mid-run (vacuous otherwise)",
    );
    // The victim resumes and self-exits once the tracer is gone: it
    // must vanish promptly (no pollution), verified by starttime so
    // a recycled number is never misread — let alone signaled.
    let gone_deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match proc_starttime(victim_pid) {
            None => break,
            Some(start) if start != victim_start => break,
            Some(_) => {
                if Instant::now() >= gone_deadline {
                    // Unexpected linger: identity-verified kill only.
                    unsafe { libc::kill(victim_pid as i32, libc::SIGKILL) };
                    panic!("victim {victim_pid} lingered after its tracer exited");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
    pass("FS10", "CONT+signal denial reports its unreaped child");
}

/// S52/S68-round5: run a preflight-denial driver mode that must
/// leave a stopped victim for its whole retirement window. The
/// victim is observed independently mid-run (state `t`, child of
/// the driver pid — PPid attribution makes parallel tests'
/// victims impossible to misattribute); after the driver exits it
/// resumes and self-exits, so post-run vanish (starttime
/// verified, so a recycled number is never misread) proves no
/// pollution. The `expect` words must all appear in the verdict.
fn preflight_stopped_victim_denial(mode: &str, expect: &[&str]) {
    use std::time::{Duration, Instant};
    let mut child = std::process::Command::new(audit_denial_bin())
        .arg(mode)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("denial driver spawns");
    let driver_pid = child.id();
    let mut victim: Option<(u32, u64)> = None;
    let deadline = Instant::now() + Duration::from_secs(8);
    while victim.is_none() && Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        victim = ptrace_stopped_child(driver_pid);
        if victim.is_none() {
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match child.try_wait().expect("try_wait runs") {
            Some(_) => break,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("denial driver hung in {mode} mode");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
    let output = child.wait_with_output().expect("output collected");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.code() == Some(3) {
        assert!(
            stdout.starts_with("setup="),
            "exit 3 must carry its setup reason, got: {stdout}"
        );
        return;
    }
    assert!(
        output.status.success(),
        "driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for word in expect {
        assert!(
            stdout.contains(word),
            "mode {mode} must fail loud with {word:?}, got: {stdout}"
        );
    }
    let (victim_pid, victim_start) = victim.expect(
        "a live ptrace-stopped driver child must be observed mid-run (vacuous otherwise)",
    );
    let gone_deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match proc_starttime(victim_pid) {
            None => break,
            Some(start) if start != victim_start => break,
            Some(_) => {
                if Instant::now() >= gone_deadline {
                    // Unexpected linger: identity-verified kill only.
                    unsafe { libc::kill(victim_pid as i32, libc::SIGKILL) };
                    panic!("victim {victim_pid} lingered after its tracer exited");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

/// S52-round5: with BLOCKING waits denied but WNOHANG allowed,
/// retirement consumes the queued TRACEME stop — and must NOT
/// report retired on it. Both kill routes are denied too, so the
/// stop survives signaling and the verdict must carry the
/// unresolved-custody note for the independently observed
/// still-stopped child. Old code returned true on the stop with
/// no note.
#[test]
fn preflight_waitstop_reports_unretired_stop() {
    preflight_stopped_victim_denial(
        "preflight-waitstop",
        &["verdict=err", "preflight wait", "not proven reaped"],
    );
    pass(
        "FS10",
        "flags-selective wait denial reports its stopped child",
    );
}

/// S68-round5: with pidfd authority denied (CONT denied to force a
/// retirement), signaling must report Uncertain and reap WITHOUT
/// signaling — never a numeric SIGKILL — so the stopped survivor
/// reports unresolved custody. The kill(2) syscall stays allowed:
/// old code used it and returned retired with no note.
#[test]
fn preflight_nopidfd_reaps_without_signaling() {
    preflight_stopped_victim_denial(
        "preflight-nopidfd",
        &["verdict=err", "resume", "not proven reaped"],
    );
    pass("FS10", "pidfd-less retirement never signals, reports custody");
}

/// Scan /proc for a ptrace-stopped (state `t`) child of `ppid`.
/// Returns the pid and its starttime (recycling discriminator).
fn ptrace_stopped_child(ppid: u32) -> Option<(u32, u64)> {
    let tasks = std::fs::read_dir("/proc").ok()?;
    for entry in tasks.flatten() {
        let pid: u32 = match entry.file_name().to_str().and_then(|n| n.parse().ok()) {
            Some(pid) => pid,
            None => continue,
        };
        let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            Err(_) => continue,
        };
        let after = match stat.rsplit_once(") ") {
            Some((_, after)) => after,
            None => continue,
        };
        let mut fields = after.split_whitespace();
        let (Some(state), Some(parent), Some(starttime)) = (
            fields.next(),
            fields.next().and_then(|p| p.parse::<u32>().ok()),
            fields.nth(17).and_then(|s| s.parse::<u64>().ok()),
        ) else {
            continue;
        };
        if state == "t" && parent == ppid {
            return Some((pid, starttime));
        }
    }
    None
}

/// The /proc starttime of `pid`, or None when the process is gone.
fn proc_starttime(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(") ")?.1;
    let mut fields = after.split_whitespace();
    fields.next()?;
    fields.next()?;
    fields.nth(17)?.parse().ok()
}

/// S68-round5: with `SIGCHLD=SIG_IGN` (auto-reap), the probe
/// refuses BEFORE forking — an exited child would vanish before
/// any pidfd could pin it, so post-fork authority is unprovable.
/// No child exists to signal: any kill attempt trips the RET_KILL
/// tripwire and dies with SIGSYS. Driver survival plus the
/// loud auto-reap refusal is the assertion; nothing forked needs
/// no custody note.
#[test]
fn preflight_autoreap_never_signals_unreserved_pid() {
    let output = preflight_denial_output("preflight-autoreap");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.code() == Some(3) {
        assert!(
            stdout.starts_with("setup="),
            "exit 3 must carry its setup reason, got: {stdout}"
        );
        return;
    }
    assert!(
        output.status.success(),
        "driver must survive (SIGSYS = something signaled); stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.starts_with("verdict=err")
            && stdout.contains("SIGCHLD auto-reap (SIG_IGN or SA_NOCLDWAIT)"),
        "auto-reap must fail loud naming the disposition, got: {stdout}"
    );
    assert!(
        !stdout.contains("not proven reaped"),
        "nothing forked needs no custody note, got: {stdout}"
    );
    pass("FS10", "auto-reap refuses pre-fork without signaling");
}

/// S68-round6: same refusal under `SA_NOCLDWAIT` without `SIG_IGN`
/// — the auto-reap configuration the round-5 predicate missed. The
/// kill tripwire and the loud refusal are asserted exactly as for
/// the `SIG_IGN` mode above.
#[test]
fn preflight_autoreap_nocldwait_never_signals() {
    let output = preflight_denial_output("preflight-autoreap-nocldwait");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.code() == Some(3) {
        assert!(
            stdout.starts_with("setup="),
            "exit 3 must carry its setup reason, got: {stdout}"
        );
        return;
    }
    assert!(
        output.status.success(),
        "driver must survive (SIGSYS = something signaled); stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.starts_with("verdict=err")
            && stdout.contains("SIGCHLD auto-reap (SIG_IGN or SA_NOCLDWAIT)"),
        "nocldwait auto-reap must fail loud, got: {stdout}"
    );
    assert!(
        !stdout.contains("not proven reaped"),
        "nothing forked needs no custody note, got: {stdout}"
    );
    pass(
        "FS10",
        "nocldwait auto-reap refuses pre-fork without signaling",
    );
}

/// S32: with the wait syscall itself denied (EPERM, never ECHILD),
/// every observation wait fails loud but proves nothing dead: the
/// audit must fail with the unreaped tracees still named in
/// unresolved custody, never a clean-looking drain. The old drain
/// treated every non-interruption wait error as disappearance and
/// reported no survivors. (~12s: the bounded drain grace still
/// caps the unobservable retire.)
#[test]
fn audit_waitpid_denial_retains_unresolved_custody() {
    match audit::preflight() {
        Ok(_) => {}
        Err(e) => {
            skip("FS10", &format!("ptrace preflight refused: {e}"));
            return;
        }
    };
    let dir = temp_dir("audit-deny-waitpid");
    let report = dir.join("denied.report");
    let verdict = denial_verdict(
        "waitpid",
        &dir,
        &[
            "mremap-anon".to_string(),
            "--report".to_string(),
            report.to_string_lossy().into_owned(),
        ],
    );
    if verdict.starts_with("setup=") {
        return;
    }
    for expect in ["verdict=err", "audit wait", "unresolved tracees:"] {
        assert!(
            verdict.contains(expect),
            "waitpid denial must fail loud with custody retained, missing {expect:?} in: {verdict}"
        );
    }
}

/// S31: with PTRACE_GETEVENTMSG denied, a clone birth is an explicit
/// custody failure, and the unknown newborn is retired by the sweep
/// (named in the error, nothing unreaped) instead of stranding
/// stopped and invisible.
#[test]
fn audit_eventmsg_denial_retires_unknown_child() {
    match audit::preflight() {
        Ok(_) => {}
        Err(e) => {
            skip("FS10", &format!("ptrace preflight refused: {e}"));
            return;
        }
    };
    let dir = temp_dir("audit-deny-eventmsg");
    let target_file = dir.join("denial-target.bin");
    std::fs::write(&target_file, pattern_bytes(97, 8192)).unwrap();
    let worker_report = dir.join("denied.report");
    let verdict = denial_verdict(
        "eventmsg",
        &dir,
        &[
            "thread-plant".to_string(),
            "--target".to_string(),
            target_file.to_string_lossy().into_owned(),
            "--report".to_string(),
            worker_report.to_string_lossy().into_owned(),
        ],
    );
    if verdict.starts_with("setup=") {
        return;
    }
    for expect in ["verdict=err", "PTRACE_GETEVENTMSG", "unreaped: []"] {
        assert!(
            verdict.contains(expect),
            "denied birth must fail loud and retire the unknown, missing {expect:?} in: {verdict}"
        );
    }
    // The fork-child variant: a separate-process unknown retires the
    // same way. The child is retired before the marker it polls for
    // can exist, so no signal file appears.
    let signal = dir.join("denied.signal");
    let verdict = denial_verdict(
        "eventmsg",
        &dir,
        &[
            "fork-exec-survivor".to_string(),
            "--signal".to_string(),
            signal.to_string_lossy().into_owned(),
            "--marker".to_string(),
            dir.join("denied.marker").to_string_lossy().into_owned(),
        ],
    );
    if verdict.starts_with("setup=") {
        return;
    }
    for expect in ["verdict=err", "PTRACE_GETEVENTMSG", "unreaped: []"] {
        assert!(
            verdict.contains(expect),
            "denied fork birth must fail loud and retire the unknown, missing {expect:?} in: {verdict}"
        );
    }
    assert!(
        !signal.exists(),
        "retired fork child must never run its signal leg"
    );
}

/// F16: the audit deadline bounds a hung subject. `sleep 300` never
/// returns from its syscall; the tracer must kill it at the deadline
/// instead of blocking in waitpid for the full sleep. The old
/// blocking wait took the whole 300 seconds (then wrongly Ok).
#[test]
fn audit_deadline_kills_hung_subject() {
    let yama = match audit::preflight() {
        Ok(note) => note,
        Err(e) => {
            skip("FS10", &format!("ptrace preflight refused: {e}"));
            return;
        }
    };
    let config = AuditConfig {
        target_dev: 0,
        target_ino: 0,
        max_entries: 4096,
        timeout: Duration::from_secs(3),
    };
    let start = Instant::now();
    let err = match audit::audit_subject(Path::new("sleep"), &["300".to_string()], &config) {
        Ok(_) => panic!("sleep 300 must not complete inside a 3s audit"),
        Err(err) => err,
    };
    let elapsed = start.elapsed();
    let detail = err.to_string();
    if detail.contains("spawn refused") {
        skip("FS10", "no sleep binary for the hang control");
        return;
    }
    assert!(
        detail.contains("timed out"),
        "hung subject must time out, got: {detail}"
    );
    assert!(
        elapsed < Duration::from_secs(60),
        "deadline did not bound the hang: {elapsed:?}"
    );
    pass(
        "FS10",
        &format!("yama {yama}; sleep 300 killed after {elapsed:?}"),
    );
}

/// F18 control: a non-positive observation exits 0 with a
/// `verdict=...` report (the trap the old `starts_with` gate fell
/// into), and the strict gate rejects it. Runs the subject directly
/// — no ptrace, so this control never skips.
#[test]
fn clean_gate_rejects_nonpositive_verdicts() {
    let dir = temp_dir("audit-gate");
    let target_file = dir.join("gate-target.bin");
    std::fs::write(&target_file, pattern_bytes(31, 8192)).unwrap();
    let target = OwnedTarget::mapping(&target_file).expect("gate target");
    let gate_report = dir.join("gate.report");
    // The null page is never mapped: the observation cannot be positive.
    let status = std::process::Command::new(audit_subject_bin())
        .args([
            "observe",
            "--target",
            &target_file.to_string_lossy(),
            "--pid",
            &target.pid().to_string(),
            "--range",
            "1000-2000",
            "--report",
            &gate_report.to_string_lossy(),
        ])
        .status()
        .expect("subject runs");
    assert_eq!(
        status.code(),
        Some(0),
        "subject exits 0 even when not positive"
    );
    let verdict = std::fs::read_to_string(&gate_report).expect("subject wrote its report");
    assert!(
        verdict.starts_with("verdict="),
        "control unexercised: no verdict to gate, got {verdict:?}"
    );
    assert!(
        !positive_verdict(&verdict),
        "control failed: unmapped range observed positive: {}",
        verdict.trim()
    );
    for accepted in ["verdict=ExactRange\n", "verdict=KeyCompatible\n"] {
        assert!(positive_verdict(accepted), "gate must accept {accepted:?}");
    }
    for rejected in [
        "verdict=Failure:MappingDown\n",
        "verdict=Mismatch:Key\n",
        "verdict=Inconclusive:Unresolved\n",
        "verdict=Other:X\n",
        "garbage\n",
        "",
    ] {
        assert!(!positive_verdict(rejected), "gate must reject {rejected:?}");
    }
    pass(
        "FS10",
        &format!("gate rejects {}; accepts positives", verdict.trim()),
    );
}

/// FS01 ext4 control: hardlink alias identity, rename/delete path
/// staleness without key confusion, and actually mapped ranges.
#[test]
fn ext4_control() {
    let Some(m) = admit_manifest() else {
        skip(
            "FS01",
            "missing TT04_MANIFEST \
            (run provision_fs.py create --privileged)",
        );
        return;
    };
    if !provisioned(&m, "FS01") {
        return;
    }
    let mnt = m.mount_target("ext4-fs01");
    let a = mnt.join("a.bin");
    let alias = mnt.join("alias.bin");
    let (a_dev, a_ino, _) = stat_key(&a);
    let (alias_dev, alias_ino, _) = stat_key(&alias);
    assert_eq!(
        (a_dev, a_ino),
        (alias_dev, alias_ino),
        "fixture unexercised: alias is not the same object"
    );
    let ctl = control();
    let epoch = epoch();
    let policy = MappingPolicy::NoNewTargetMappings;
    let pool = pool_for(&policy);
    // Alias identity: both names observe the same mapped object.
    let target = OwnedTarget::mapping(&a).expect("ext4 target");
    let (start, end) = target.range().expect("mapping target has range");
    let range = MapRange::new(start, end).unwrap();
    let pid = Pid::new(target.pid() as i32).unwrap();
    let obs =
        ProcessObservation::acquire(pid, &epoch, proc_limits(), &ctl).expect("acquire ext4 target");
    for (name, path) in [("a", &a), ("alias", &alias)] {
        let held = hold(path);
        match observe(&pool, &held, &obs, range, policy, &ctl) {
            Ok(MappingOutcome::KeyCompatible(_)) => {}
            other => panic!("ext4 {name} must be KeyCompatible, saw {other:?}"),
        }
    }
    // Rename leg on a per-run file (manifest fixtures are never
    // mutated: every cell admits the same manifest concurrently).
    // The maps row FOLLOWS the rename to the new name while the
    // object (and its key relation) survives.
    let tag = unique_tag();
    let rname = mnt.join(format!("rb-{tag}.bin"));
    std::fs::write(&rname, pattern_bytes(62, 8192)).unwrap();
    let rino = stat_key(&rname).1;
    let target_b = OwnedTarget::mapping(&rname).expect("rename target");
    let (bstart, bend) = target_b.range().expect("mapping target has range");
    let renamed = mnt.join(format!("rb-{tag}-new.bin"));
    std::fs::rename(&rname, &renamed).expect("rename");
    let rows = maps_entries(target_b.pid());
    let followed = rows
        .iter()
        .find(|e| e.start == bstart && e.end == bend)
        .expect("fixture unexercised: renamed row vanished");
    assert!(
        followed
            .path
            .as_deref()
            .is_some_and(|p| p.ends_with("-new.bin")),
        "fixture unexercised: maps row did not follow the rename, saw {:?}",
        followed.path
    );
    assert_eq!(followed.ino, rino, "rename must preserve the object");
    let held_renamed = hold(&renamed);
    let bpid = Pid::new(target_b.pid() as i32).unwrap();
    let bobs = ProcessObservation::acquire(bpid, &epoch, proc_limits(), &ctl)
        .expect("acquire renamed target");
    match observe(
        &pool,
        &held_renamed,
        &bobs,
        MapRange::new(bstart, bend).unwrap(),
        policy,
        &ctl,
    ) {
        Ok(MappingOutcome::KeyCompatible(_)) => {}
        other => panic!("renamed object must stay KeyCompatible, saw {other:?}"),
    }
    // Delete: the mapping outlives its last name (" (deleted)").
    let victim = mnt.join(format!("doomed-{tag}.bin"));
    let doomed_bytes = pattern_bytes(61, 8192);
    std::fs::write(&victim, &doomed_bytes).unwrap();
    let held_pre = hold(&victim);
    let target_d = OwnedTarget::mapping(&victim).expect("doomed target");
    let (dstart, dend) = target_d.range().expect("mapping target has range");
    std::fs::remove_file(&victim).expect("delete");
    let drows = maps_entries(target_d.pid());
    let gone = drows
        .iter()
        .find(|e| e.start == dstart && e.end == dend)
        .expect("fixture unexercised: deleted row vanished");
    assert!(
        gone.path
            .as_deref()
            .is_some_and(|p| p.contains("(deleted)")),
        "fixture unexercised: no (deleted) marker, saw {:?}",
        gone.path
    );
    // The deleted name no longer opens, but the pre-delete held FD
    // still reads the live object.
    match hold_with(&victim, SymlinkPolicy::Follow) {
        Err(_) => {}
        Ok(_) => panic!("deleted name must not re-open"),
    }
    assert_bytes_eq(&read_held(&held_pre), &doomed_bytes, "pre-delete held FD");
    pass(
        "FS01",
        &format!(
            "alias ino={a_ino} both KeyCompatible; rename follows to new \
         name + keys; delete markers row (deleted), name refused, \
         FD live"
        ),
    );
}

/// FS04 overlay xino=off: aligned merged/lower inode identity with a
/// split device domain, plus the mapping relation on merged files.
#[test]
fn overlay_xino_off_aligned() {
    let Some(m) = admit_manifest() else {
        skip(
            "FS04",
            "missing TT04_MANIFEST \
            (run provision_fs.py create --privileged)",
        );
        return;
    };
    if !provisioned(&m, "FS04") {
        return;
    }
    let layout = "ov-xino-off_layout";
    let merged_dir = m.evidence_path(&[layout, "merged"]);
    let lower_dir = m.evidence_path(&[layout, "lower"]);
    // Per-run lower file (manifest fixtures are never mutated).
    let name = format!("big-{}.bin", unique_tag());
    std::fs::write(lower_dir.join(&name), pattern_bytes(83, 8192)).unwrap();
    let merged = merged_dir.join(&name);
    let lower = lower_dir.join(&name);
    let (mdev, mino, _) = stat_key(&merged);
    let (ldev, lino, _) = stat_key(&lower);
    assert_eq!(mino, lino, "xino=off must pass the lower inode through");
    assert_ne!(mdev, ldev, "overlay stat dev must differ from layer dev");
    let ctl = control();
    let epoch = epoch();
    let policy = MappingPolicy::NoNewTargetMappings;
    let pool = pool_for(&policy);
    let target = OwnedTarget::mapping(&merged).expect("overlay target");
    let (start, end) = target.range().expect("mapping target has range");
    let pid = Pid::new(target.pid() as i32).unwrap();
    let obs = ProcessObservation::acquire(pid, &epoch, proc_limits(), &ctl)
        .expect("acquire overlay target");
    let held = hold(&merged);
    match observe(
        &pool,
        &held,
        &obs,
        MapRange::new(start, end).unwrap(),
        policy,
        &ctl,
    ) {
        Ok(MappingOutcome::KeyCompatible(_)) => {}
        other => panic!("overlay merged observe must match, saw {other:?}"),
    }
    // Negative: an unmapped upper file names no range here.
    let upper_only = merged_dir.join("upper-only.txt");
    let held_upper = hold(&upper_only);
    match observe(
        &pool,
        &held_upper,
        &obs,
        MapRange::new(start, end).unwrap(),
        policy,
        &ctl,
    ) {
        Ok(MappingOutcome::Mismatch(e)) if e.kind() == MismatchKind::KeyMismatch => {}
        other => panic!("unmapped upper file must mismatch, saw {other:?}"),
    }
    pass(
        "FS04",
        &format!(
            "aligned ino={mino} dev overlay={mdev} layer={ldev}; merged \
         KeyCompatible, upper-only KeyMismatch"
        ),
    );
}

/// FS05 overlay xino=on across filesystems: composed merged inodes.
#[test]
fn overlay_xino_on_split() {
    let Some(m) = admit_manifest() else {
        skip(
            "FS05",
            "missing TT04_MANIFEST \
            (run provision_fs.py create --privileged)",
        );
        return;
    };
    if !provisioned(&m, "FS05") {
        return;
    }
    let layout = "ov-xino-on_layout";
    let merged_dir = m.evidence_path(&[layout, "merged"]);
    let lower_dir = m.evidence_path(&[layout, "lower"]);
    let name = format!("big-{}.bin", unique_tag());
    std::fs::write(lower_dir.join(&name), pattern_bytes(84, 8192)).unwrap();
    let merged = merged_dir.join(&name);
    let lower = lower_dir.join(&name);
    let (mdev, mino, _) = stat_key(&merged);
    let (ldev, lino, _) = stat_key(&lower);
    assert_ne!(
        mino, lino,
        "fixture unexercised: xino=on did not compose (same-fs ignore?)"
    );
    assert_ne!(mdev, ldev, "overlay dev must differ from tmpfs lower dev");
    let ctl = control();
    let epoch = epoch();
    let policy = MappingPolicy::NoNewTargetMappings;
    let pool = pool_for(&policy);
    let target = OwnedTarget::mapping(&merged).expect("xino target");
    let (start, end) = target.range().expect("mapping target has range");
    let pid = Pid::new(target.pid() as i32).unwrap();
    let obs =
        ProcessObservation::acquire(pid, &epoch, proc_limits(), &ctl).expect("acquire xino target");
    let held = hold(&merged);
    match observe(
        &pool,
        &held,
        &obs,
        MapRange::new(start, end).unwrap(),
        policy,
        &ctl,
    ) {
        Ok(MappingOutcome::KeyCompatible(_)) => {}
        other => panic!("xino merged observe must match, saw {other:?}"),
    }
    pass(
        "FS05",
        &format!(
            "composed ino={mino} != lower {lino} (tmpfs lower dev={ldev}); \
         KeyCompatible"
        ),
    );
}

/// FS07 overlay metacopy=on profile: a metadata-only change copies up
/// just metadata (zero-block upper stub, lower data intact), and a
/// later data write completes to a full upper copy.
#[test]
fn metacopy_transition() {
    let Some(m) = admit_manifest() else {
        skip(
            "FS07",
            "missing TT04_MANIFEST \
            (run provision_fs.py create --privileged)",
        );
        return;
    };
    if !provisioned(&m, "FS07") {
        return;
    }
    let layout = "ov-metacopy_layout";
    let merged_dir = m.evidence_path(&[layout, "merged"]);
    let upper_dir = m.evidence_path(&[layout, "upper"]);
    let lower_dir = m.evidence_path(&[layout, "lower"]);
    let name = format!("mc-{}.txt", unique_tag());
    let mut payload = b"metacopy-payload-bytes\n".to_vec();
    payload.extend_from_slice(&pattern_bytes(85, 8192 - payload.len()));
    std::fs::write(lower_dir.join(&name), &payload).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        lower_dir.join(&name),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    // Metadata-only change through the merged view.
    std::fs::set_permissions(
        merged_dir.join(&name),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let upper_meta = std::fs::metadata(upper_dir.join(&name))
        .expect("fixture unexercised: metacopy produced no upper file");
    assert_eq!(
        upper_meta.blocks(),
        0,
        "fixture unexercised: upper copy holds data blocks (not metacopy)"
    );
    assert_eq!(
        std::fs::metadata(lower_dir.join(&name))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644,
        "fixture unexercised: lower mode mutated"
    );
    assert_eq!(
        std::fs::metadata(merged_dir.join(&name))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "merged view lacks the new mode"
    );
    assert_eq!(
        std::fs::read(merged_dir.join(&name)).unwrap(),
        payload,
        "merged data must still come from the lower layer"
    );
    // Data write completes the copy-up to full upper data.
    let mut full = b"metacopy-full-rewrite\n".to_vec();
    full.extend_from_slice(&pattern_bytes(86, 8192 - full.len()));
    std::fs::write(merged_dir.join(&name), &full).unwrap();
    let full_meta = std::fs::metadata(upper_dir.join(&name)).unwrap();
    assert!(full_meta.blocks() > 0, "data write must materialize blocks");
    assert_eq!(
        std::fs::read(lower_dir.join(&name)).unwrap(),
        payload,
        "lower data must stay intact after full copy-up"
    );
    // The mapping relation tracks the transitioned object.
    let ctl = control();
    let epoch = epoch();
    let policy = MappingPolicy::NoNewTargetMappings;
    let pool = pool_for(&policy);
    let target = OwnedTarget::mapping(&merged_dir.join(&name)).expect("metacopy target");
    let (start, end) = target.range().expect("mapping target has range");
    let pid = Pid::new(target.pid() as i32).unwrap();
    let obs = ProcessObservation::acquire(pid, &epoch, proc_limits(), &ctl)
        .expect("acquire metacopy target");
    let held = hold(&merged_dir.join(&name));
    match observe(
        &pool,
        &held,
        &obs,
        MapRange::new(start, end).unwrap(),
        policy,
        &ctl,
    ) {
        Ok(MappingOutcome::KeyCompatible(_)) => {}
        other => panic!("metacopy observe must match, saw {other:?}"),
    }
    pass(
        "FS07",
        &format!(
            "chmod -> 0-block stub (mode 600/644 split); data write -> \
         {} blocks; lower intact; KeyCompatible",
            full_meta.blocks()
        ),
    );
}

/// FS09 real denials: a mode-000 owned file refuses the held reopen
/// (no root bypass here), pid 1 refuses proc acquisition, and the
/// map_files route reports Denied so ExactRange stays unreachable.
#[test]
fn restricted_denial_is_real() {
    if unsafe { libc::geteuid() } == 0 {
        skip("FS09", "euid 0 bypasses DAC: denial untestable as root");
        return;
    }
    let dir = temp_dir("denied");
    let locked = dir.join("locked.bin");
    std::fs::write(&locked, pattern_bytes(71, 4096)).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let err = hold_with(&locked, SymlinkPolicy::Follow).expect_err("mode-000 open must be refused");
    let stage = format!("{:?}", err.stage());
    assert!(
        stage.contains("ReopenHeld"),
        "mode-000 must fail at the held reopen, saw stage {stage}"
    );
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
    // Pid 1: foreign authority, genuinely denied to this observer.
    let ctl = control();
    let epoch = epoch();
    let one = Pid::new(1).unwrap();
    match ProcessObservation::acquire(one, &epoch, proc_limits(), &ctl) {
        Err(e) => assert_eq!(
            e.reason(),
            Reason::Denied,
            "pid-1 acquire must be Denied, saw {:?}",
            e.reason()
        ),
        Ok(_) => panic!("pid-1 acquire must not succeed unprivileged"),
    }
    // map_files of an owned live child reports Denied here (hardened
    // kernels refuse even self): the key path, never ExactRange.
    let probe = dir.join("probe.bin");
    std::fs::write(&probe, pattern_bytes(72, 4096)).unwrap();
    let target = OwnedTarget::mapping(&probe).expect("denial target");
    let (start, end) = target.range().expect("mapping target has range");
    let pid = Pid::new(target.pid() as i32).unwrap();
    let obs = ProcessObservation::acquire(pid, &epoch, proc_limits(), &ctl)
        .expect("acquire denial target");
    match obs.read_map_files_identity(start, end, proc_limits(), &ctl) {
        Err(e) => assert_eq!(
            e.reason(),
            Reason::Denied,
            "map_files must be Denied, saw {:?}",
            e.reason()
        ),
        Ok(_) => panic!("map_files granted here: FS09 denial vacuous"),
    }
    pass(
        "FS09",
        &format!(
            "mode-000 refused at {stage}; pid-1 acquire Denied; map_files \
         Denied on owned child"
        ),
    );
}

/// LX06 deferral: fork/exec/exit target fixtures. An exited target
/// yields TargetExited; an exec transition preserves birth while its
/// old ranges stop resolving (Mismatch, never stale success).
#[test]
fn fork_exec_exit_verdicts() {
    let dir = temp_dir("lifecycle");
    let file = dir.join("life.bin");
    std::fs::write(&file, pattern_bytes(72, 8192)).unwrap();
    let ctl = control();
    let epoch = epoch();
    let policy = MappingPolicy::NoNewTargetMappings;
    let pool = pool_for(&policy);
    // Exit leg: acquire live, reap, then observe.
    let target = OwnedTarget::mapping(&file).expect("exit target");
    let (start, end) = target.range().expect("mapping target has range");
    let range = MapRange::new(start, end).unwrap();
    let pid = Pid::new(target.pid() as i32).unwrap();
    let obs =
        ProcessObservation::acquire(pid, &epoch, proc_limits(), &ctl).expect("acquire exit target");
    let held = hold(&file);
    let target_pid = target.pid();
    drop(target);
    // Reap barrier: the child must be gone, not merely signalled.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let gone = std::fs::read_to_string(format!("/proc/{target_pid}/stat")).is_err();
        if gone || Instant::now() >= deadline {
            assert!(gone, "fixture unexercised: target survives kill");
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    match observe(&pool, &held, &obs, range, policy, &ctl) {
        Ok(MappingOutcome::Inconclusive(reason))
            if reason.kind() == InconclusiveKind::TargetExited => {}
        other => panic!("exited target must be TargetExited, saw {other:?}"),
    }
    // Exec leg: sh acknowledges, then execs sleep on command.
    let mut exec_target = OwnedTarget::exec_transition().expect("exec target");
    let epid = Pid::new(exec_target.pid() as i32).unwrap();
    let eobs = ProcessObservation::acquire(epid, &epoch, proc_limits(), &ctl)
        .expect("acquire exec target");
    let pre_rows = maps_entries(exec_target.pid());
    assert!(
        !pre_rows.is_empty(),
        "fixture unexercised: no pre-exec rows"
    );
    let victim = pre_rows
        .iter()
        .find(|e| e.path.as_ref().is_some_and(|p| p.starts_with('/')) && e.end - e.start >= 4096)
        .expect("fixture unexercised: no file-backed pre-exec range");
    // The observer matches whole maps rows, so the victim range is
    // the full row, not a prefix of it.
    let vrange = MapRange::new(victim.start, victim.end).unwrap();
    // F19: hold the ACTUAL backing file of the victim range. The old
    // leg held the unrelated exit-leg life.bin, so its post-exec
    // Mismatch was preordained (wrong file mismatches with or
    // without an exec) and proved nothing about exec invalidation.
    let victim_file = hold(Path::new(victim.path.as_ref().expect("victim has a path")));
    // Pre-exec positive: the held backing file genuinely resolves at
    // the victim range before the exec.
    match observe(&pool, &victim_file, &eobs, vrange, policy, &ctl) {
        Ok(MappingOutcome::ExactRange(_)) | Ok(MappingOutcome::KeyCompatible(_)) => {}
        other => panic!("pre-exec victim range must resolve positive, saw {other:?}"),
    }
    exec_target.trigger_exec();
    let exe = exec_target
        .wait_exe("sleep", Duration::from_secs(10))
        .expect("exe barrier poll");
    assert!(exe.ends_with("sleep"), "exec barrier never showed sleep");
    // Birth survives exec; the old range no longer resolves.
    let birth = eobs.verify_birth(&ctl).expect("verify birth");
    assert_eq!(
        birth.status(),
        scopebase_linux::process::BirthStatus::AliveSameBirth,
        "exec must preserve birth"
    );
    match observe(&pool, &victim_file, &eobs, vrange, policy, &ctl) {
        Ok(MappingOutcome::Mismatch(_)) => {}
        other => panic!("post-exec stale range must mismatch, saw {other:?}"),
    }
    pass(
        "FS-lifecycle",
        "exit -> TargetExited; exec preserves birth, \
        stale range Mismatch",
    );
}

/// LX06 deferral: same-owner concurrent reads converge on one verdict
/// with no FD exhaustion and no stranded pool custody.
#[test]
fn concurrent_same_owner_reads() {
    let dir = temp_dir("concurrent");
    let file = dir.join("shared.bin");
    std::fs::write(&file, pattern_bytes(73, 8192)).unwrap();
    let target = OwnedTarget::mapping(&file).expect("shared target");
    let (start, end) = target.range().expect("mapping target has range");
    let range = MapRange::new(start, end).unwrap();
    let pid = target.pid();
    let held = hold(&file);
    let epoch = epoch();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let held = Arc::clone(&held);
        let epoch = epoch.clone();
        handles.push(std::thread::spawn(move || {
            let ctl = control();
            let policy = MappingPolicy::NoNewTargetMappings;
            let pool = pool_for(&policy);
            for _ in 0..25 {
                let opid = Pid::new(pid as i32).unwrap();
                let obs = ProcessObservation::acquire(opid, &epoch, proc_limits(), &ctl)
                    .expect("concurrent acquire");
                match observe(&pool, &held, &obs, range, policy, &ctl) {
                    Ok(MappingOutcome::KeyCompatible(_)) => {}
                    other => panic!("concurrent observe diverged: {other:?}"),
                }
            }
            assert_eq!(pool.status().unresolved_mappings(), 0);
        }));
    }
    for handle in handles {
        handle.join().expect("worker panicked");
    }
    pass("FS-concurrent", "8x25 observes converged on KeyCompatible");
}

/// LX08 deferral: foreign/nested PID namespaces. The NSpid
/// sequences are observed live; the pure-pidns boundary (shared
/// mounts) stays transparent to key resolution, while the
/// --mount-proc sleepers document that --mount-proc implies a fresh
/// mount namespace (their mapping verdicts refuse by mount domain).
#[test]
fn nspid_sequence_across_pidns() {
    let Some(m) = admit_manifest() else {
        skip(
            "FS-nspid",
            "missing TT04_MANIFEST \
            (run provision_fs.py create --privileged)",
        );
        return;
    };
    if !provisioned(&m, "FS08") {
        return;
    }
    let mapped = m.run_root.join("ns/mapped.bin");
    let ctl = control();
    let epoch = epoch();
    let policy = MappingPolicy::NoNewTargetMappings;
    let pool = pool_for(&policy);
    let held = hold(&mapped);
    // Pure pidns leg: shared mounts, foreign pidns -> keys resolve.
    let pure = m.proc_pid("pure-pidns-sleeper");
    let pure_levels = nspid_of(pure);
    assert_eq!(
        pure_levels.len(),
        2,
        "fixture unexercised: pure pidns NSpid depth {} != 2",
        pure_levels.len()
    );
    let pure_report = m.evidence_path(&["ns_reports", "pure"]);
    let (pstart, pend) = parse_range(&report_value(&pure_report, "range"));
    let pure_pid = Pid::new(pure as i32).unwrap();
    let pure_obs = ProcessObservation::acquire(pure_pid, &epoch, proc_limits(), &ctl)
        .expect("acquire pure pidns target");
    match observe(
        &pool,
        &held,
        &pure_obs,
        MapRange::new(pstart, pend).unwrap(),
        policy,
        &ctl,
    ) {
        Ok(MappingOutcome::KeyCompatible(_)) => {}
        other => panic!("pure cross-pidns observe must match, saw {other:?}"),
    }
    // --mount-proc leg: NSpid observed, mapping refused by mount domain.
    let pid = m.proc_pid("pidns-sleeper");
    let levels = nspid_of(pid);
    assert_eq!(
        levels.len(),
        2,
        "fixture unexercised: pidns NSpid depth {} != 2",
        levels.len()
    );
    let report = m.evidence_path(&["ns_reports", "pid"]);
    let (start, end) = parse_range(&report_value(&report, "range"));
    let opid = Pid::new(pid as i32).unwrap();
    let obs = ProcessObservation::acquire(opid, &epoch, proc_limits(), &ctl)
        .expect("acquire pidns target");
    match observe(
        &pool,
        &held,
        &obs,
        MapRange::new(start, end).unwrap(),
        policy,
        &ctl,
    ) {
        Ok(MappingOutcome::Inconclusive(reason))
            if reason.kind() == InconclusiveKind::MountUnresolved => {}
        other => panic!("--mount-proc observe must be MountUnresolved, saw {other:?}"),
    }
    let mut detail = format!(
        "pure NSpid {pure_levels:?} KeyCompatible; --mount-proc NSpid \
         {levels:?} MountUnresolved"
    );
    if m.value["evidence"]["nested_pidns"].as_str() == Some("provisioned") {
        let nested = m.proc_pid("nested-pidns-sleeper");
        let deep = nspid_of(nested);
        assert_eq!(
            deep.len(),
            3,
            "fixture unexercised: nested NSpid depth {} != 3",
            deep.len()
        );
        detail += &format!("; nested depth 3 {deep:?}");
    } else {
        detail += "; nested pidns skipped (unsupported here)";
    }
    pass("FS-nspid", &detail);
}

/// LX08 deferral: symlink-escape fixtures pin the actual HeldFile
/// semantics. Follow resolves to the outside object (identity is the
/// resolved object, no confusion); RejectFinal and loops refuse.
#[test]
fn symlink_escape_pinned() {
    let dir = temp_dir("escape");
    let outside = dir.join("outside.txt");
    std::fs::write(&outside, b"outside-secret\n").unwrap();
    let inner = dir.join("inner");
    std::fs::create_dir(&inner).unwrap();
    std::os::unix::fs::symlink("../outside.txt", inner.join("evil")).unwrap();
    std::os::unix::fs::symlink("loop-b", inner.join("loop-a")).unwrap();
    std::os::unix::fs::symlink("loop-a", inner.join("loop-b")).unwrap();
    let held = hold_with(&inner.join("evil"), SymlinkPolicy::Follow)
        .expect("Follow resolves the escape link");
    assert_eq!(read_held(&held), b"outside-secret\n");
    let outside_stat = stat_key(&outside);
    let via_link = stat_key(&inner.join("evil"));
    assert_eq!(outside_stat, via_link, "link must resolve to outside");
    match hold_with(&inner.join("evil"), SymlinkPolicy::RejectFinal) {
        Err(e) => {
            assert_ne!(e.reason(), Reason::Inconclusive);
        }
        Ok(_) => panic!("RejectFinal must refuse the final symlink"),
    }
    match hold_with(&inner.join("loop-a"), SymlinkPolicy::Follow) {
        Err(_) => {}
        Ok(_) => panic!("symlink loop must refuse"),
    }
    pass(
        "FS-escape",
        "Follow resolves to outside identity; RejectFinal \
        and loops refuse",
    );
}

/// LX08 deferral: the foreign mount view is read AS the target's view.
/// Production mountinfo on the sleeper contains the overmount bind row
/// that the observer's own table lacks.
#[test]
fn overmount_reads_target_view() {
    let Some(m) = admit_manifest() else {
        skip(
            "FS-overmount",
            "missing TT04_MANIFEST \
            (run provision_fs.py create --privileged)",
        );
        return;
    };
    if !provisioned(&m, "FS08") {
        return;
    }
    let pid = m.proc_pid("mnt-sleeper");
    let ctl = control();
    let epoch = epoch();
    let opid = Pid::new(pid as i32).unwrap();
    let obs = ProcessObservation::acquire(opid, &epoch, proc_limits(), &ctl)
        .expect("acquire foreign-view target");
    let view = obs
        .read_mountinfo(proc_limits(), &ctl)
        .expect("production target mountinfo");
    let bind_present = view.snapshot().entries().any(|e| {
        e.mount_point().decoded().ends_with(b"ns/view") && e.root().decoded().ends_with(b"ns/alt")
    });
    assert!(
        bind_present,
        "fixture unexercised: production target view lacks the bind row"
    );
    // The observer's own table has no such row: the views differ.
    let me = Pid::new(std::process::id() as i32).unwrap();
    let mine = ProcessObservation::acquire(me, &epoch, proc_limits(), &ctl).expect("acquire self");
    let mine_view = mine
        .read_mountinfo(proc_limits(), &ctl)
        .expect("production self mountinfo");
    let self_has_bind = mine_view
        .snapshot()
        .entries()
        .any(|e| e.mount_point().decoded().ends_with(b"ns/view"));
    assert!(!self_has_bind, "observer view must not show the bind");
    pass(
        "FS-overmount",
        "production target view shows alt->view bind; \
        observer view does not",
    );
}

/// LX08 deferral: replaced-root target. Readiness was the replaced
/// root link; the chroot holds no mounts so the target's mount table
/// is EMPTY and production refuses the key proof by mount domain
/// instead of guessing. Birth and maps legs still work.
#[test]
fn replaced_root_target() {
    let Some(m) = admit_manifest() else {
        skip(
            "FS-chroot",
            "missing TT04_MANIFEST \
            (run provision_fs.py create --privileged)",
        );
        return;
    };
    if !provisioned(&m, "FS08") {
        return;
    }
    let chroot = &m.value["evidence"]["chroot"];
    let Some(chroot_dir) = chroot["root"].as_str() else {
        skip(
            "FS-chroot",
            &format!("chroot {}", chroot.as_str().unwrap_or("unsupported here")),
        );
        return;
    };
    let pid = m.proc_pid("chroot-sleeper");
    let live_root = std::fs::read_link(format!("/proc/{pid}/root"))
        .expect("fixture unexercised: root link unreadable");
    assert_eq!(
        live_root.to_string_lossy(),
        chroot_dir,
        "fixture unexercised: root link left the chroot"
    );
    let table = std::fs::read_to_string(format!("/proc/{pid}/mountinfo"))
        .expect("fixture unexercised: target mountinfo unreadable");
    assert!(
        table.trim().is_empty(),
        "fixture unexercised: chrooted mount table not empty"
    );
    let busybox = PathBuf::from(chroot_dir).join("bin/busybox");
    let row = maps_entries(pid)
        .into_iter()
        .find(|e| {
            e.path.as_deref() == Some(busybox.to_string_lossy().as_ref()) && e.end - e.start >= 4096
        })
        .expect("fixture unexercised: no busybox maps row");
    let ctl = control();
    let epoch = epoch();
    let opid = Pid::new(pid as i32).unwrap();
    let obs = ProcessObservation::acquire(opid, &epoch, proc_limits(), &ctl)
        .expect("acquire chrooted target");
    assert_eq!(
        obs.verify_birth(&ctl).expect("birth").status(),
        scopebase_linux::process::BirthStatus::AliveSameBirth
    );
    let held = hold(&busybox);
    match observe(
        &pool_for(&MappingPolicy::NoNewTargetMappings),
        &held,
        &obs,
        MapRange::new(row.start, row.start + 4096).unwrap(),
        MappingPolicy::NoNewTargetMappings,
        &ctl,
    ) {
        Ok(MappingOutcome::Inconclusive(reason))
            if reason.kind() == InconclusiveKind::MountUnresolved => {}
        other => panic!("chrooted observe must be MountUnresolved, saw {other:?}"),
    }
    pass(
        "FS-chroot",
        &format!(
            "root link at {chroot_dir}; empty mount table -> \
         MountUnresolved; birth alive"
        ),
    );
}

/// FS08 churn leg: a synchronized bind/unmount cycle while retained
/// views stay distinct. The held FD keeps pre-churn bytes, the live
/// path shows churn bytes, and the foreign sleeper's view never sees
/// observer-namespace churn.
#[test]
fn mount_churn_keeps_retained_views() {
    let Some(m) = admit_manifest() else {
        skip(
            "FS08-churn",
            "missing TT04_MANIFEST \
            (run provision_fs.py create --privileged)",
        );
        return;
    };
    if !provisioned(&m, "FS08") {
        return;
    }
    let fifo = m.evidence_path(&["churn", "fifo"]);
    let ack = m.evidence_path(&["churn", "ack"]);
    let point = m.evidence_path(&["churn", "point"]);
    let ledger = m.evidence_path(&["churn", "ledger"]);
    let drive = |cmd: &str| {
        std::fs::write(&ack, []).unwrap();
        {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            let path = CString::new(fifo.as_os_str().as_bytes()).expect("fifo cstr");
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
            assert!(fd >= 0, "churn fifo has no reader (driver dead?)");
            let bytes = format!("{cmd}\n");
            let wrote = unsafe { libc::write(fd, bytes.as_ptr() as *const _, bytes.len()) };
            unsafe { libc::close(fd) };
            assert_eq!(wrote as usize, bytes.len());
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let text = std::fs::read_to_string(&ack).unwrap_or_default();
            if text.starts_with(&format!("{cmd} rc=")) {
                assert!(text.contains("rc=0"), "churn driver refused {cmd}: {text}");
                return;
            }
            assert!(Instant::now() < deadline, "churn driver never acked {cmd}");
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    assert_eq!(
        std::fs::read(&point).unwrap(),
        b"churn-payload-a\n",
        "fixture unexercised: churn point lacks payload A"
    );
    let held = hold(&point);
    drive("bind-b");
    assert_eq!(
        std::fs::read(&point).unwrap(),
        b"churn-payload-b\n",
        "fixture unexercised: churn bind did not land"
    );
    assert_eq!(
        read_held(&held),
        b"churn-payload-a\n",
        "retained FD must keep pre-churn bytes"
    );
    // Fresh mountinfo shows the churn bind in OUR view only.
    let ctl = control();
    let epoch = epoch();
    let me = Pid::new(std::process::id() as i32).unwrap();
    let mine = ProcessObservation::acquire(me, &epoch, proc_limits(), &ctl).expect("acquire self");
    let mine_view = mine
        .read_mountinfo(proc_limits(), &ctl)
        .expect("self mountinfo");
    let point_name = point.file_name().unwrap().to_string_lossy().into_owned();
    let shows_churn = mine_view
        .snapshot()
        .entries()
        .any(|e| e.mount_point().decoded().ends_with(point_name.as_bytes()));
    assert!(
        shows_churn,
        "fixture unexercised: self view lacks churn bind"
    );
    let sleeper = Pid::new(m.proc_pid("mnt-sleeper") as i32).unwrap();
    let sobs = ProcessObservation::acquire(sleeper, &epoch, proc_limits(), &ctl)
        .expect("acquire foreign sleeper");
    let sview = sobs
        .read_mountinfo(proc_limits(), &ctl)
        .expect("sleeper mountinfo");
    let foreign_sees_churn = sview
        .snapshot()
        .entries()
        .any(|e| e.mount_point().decoded().ends_with(point_name.as_bytes()));
    assert!(
        !foreign_sees_churn,
        "foreign view must not see observer-namespace churn"
    );
    drive("restore");
    assert_eq!(
        std::fs::read(&point).unwrap(),
        b"churn-payload-a\n",
        "churn point must restore payload A"
    );
    let ledger_text = std::fs::read_to_string(&ledger).unwrap_or_default();
    assert!(
        ledger_text.contains("bind-b") && ledger_text.contains("restore"),
        "churn ledger must record both operations"
    );
    pass(
        "FS08-churn",
        "bind-b landed, retained FD kept A, foreign view \
        unaffected, restore landed, ledger complete",
    );
}

/// Privileged ExactRange positive: with real map_files authority the
/// independent per-range association yields ExactRange, and the
/// map_files identity equals the held key. Run ONLY this cell under
/// sudo; the rest of the suite must stay unprivileged.
#[test]
fn exact_range_positive_privileged() {
    if unsafe { libc::geteuid() } != 0 {
        skip(
            "FS-exact",
            "missing root map_files authority \
            (run ONLY this cell under sudo)",
        );
        return;
    }
    let dir = temp_dir("exact");
    let file = dir.join("exact.bin");
    std::fs::write(&file, pattern_bytes(74, 8192)).unwrap();
    let target = OwnedTarget::mapping(&file).expect("exact target");
    let (start, end) = target.range().expect("mapping target has range");
    let range = MapRange::new(start, end).unwrap();
    let ctl = control();
    let epoch = epoch();
    let pid = Pid::new(target.pid() as i32).unwrap();
    let obs = ProcessObservation::acquire(pid, &epoch, proc_limits(), &ctl)
        .expect("acquire exact target");
    // Oracle first: map_files must actually grant here.
    let link = format!("/proc/{}/map_files/{start:x}-{end:x}", target.pid());
    let meta =
        std::fs::metadata(&link).expect("fixture unexercised: map_files still denied as root");
    let held = hold(&file);
    let held_stat = held.stat().expect("held stat");
    assert_eq!(
        (meta.dev() as u64, meta.ino()),
        (held_stat.key().device_raw(), held_stat.key().inode()),
        "fixture unexercised: map_files names another object"
    );
    let policy = MappingPolicy::NoNewTargetMappings;
    let pool = pool_for(&policy);
    match observe(&pool, &held, &obs, range, policy, &ctl) {
        Ok(MappingOutcome::ExactRange(proof)) => {
            assert_eq!(
                proof.map_files_identity(),
                (held_stat.key().device_raw(), held_stat.key().inode())
            );
        }
        other => panic!("privileged observe must be ExactRange, saw {other:?}"),
    }
    pass(
        "FS-exact",
        "root map_files association yields ExactRange with \
        matching identity",
    );
}

/// Policy-matrix audit: calibration yields a Calibrated proof with
/// retired custody when exact association is denied, and incoherent
/// policy/limits pairs refuse before any effect.
#[test]
fn calibration_policy_matrix() {
    let dir = temp_dir("calibration");
    let file = dir.join("cal.bin");
    std::fs::write(&file, pattern_bytes(75, 8192)).unwrap();
    let target = OwnedTarget::mapping(&file).expect("cal target");
    let (start, end) = target.range().expect("mapping target has range");
    let range = MapRange::new(start, end).unwrap();
    let ctl = control();
    let epoch = epoch();
    let pid = Pid::new(target.pid() as i32).unwrap();
    let obs =
        ProcessObservation::acquire(pid, &epoch, proc_limits(), &ctl).expect("acquire cal target");
    let held = hold(&file);
    // Denied exact route + calibration authority -> Calibrated proof.
    let cal = MappingPolicy::AllowPrivateCalibration {
        max_mapped_bytes: 4096,
    };
    let pool = pool_for(&cal);
    match observe(&pool, &held, &obs, range, cal, &ctl) {
        Ok(MappingOutcome::KeyCompatible(proof)) => {
            assert_eq!(
                proof.method(),
                scopebase_linux::mapping::ProofMethod::Calibrated
            );
        }
        Ok(MappingOutcome::ExactRange(_)) => {
            // Granted environments take the stronger route; allowed.
        }
        other => panic!("calibration observe must prove, saw {other:?}"),
    }
    assert_eq!(pool.status().active_mappings(), 0);
    assert_eq!(pool.status().unresolved_mappings(), 0);
    // Incoherent pairs refuse pre-effect.
    let none = MappingPolicy::NoNewTargetMappings;
    let bad = scopebase_linux::mapping::observe_mapping(
        MappingRequest {
            pool: &pool_for(&none),
            held: Arc::clone(&held),
            process: &obs,
            range,
            policy: none,
            retained: None,
            limits: mapping_limits(1),
        },
        &ctl,
    );
    assert!(bad.is_err(), "NoNew with live ceiling 1 must refuse");
    pass(
        "FS-calibration",
        "denied route calibrates (custody retired); \
        incoherent NoNew/1 refuses",
    );
}

/// Sub-page calibration caps stay inconclusive at calibration time.
#[test]
fn sub_page_cap_inconclusive() {
    let dir = temp_dir("subpage");
    let file = dir.join("sub.bin");
    std::fs::write(&file, pattern_bytes(76, 8192)).unwrap();
    let target = OwnedTarget::mapping(&file).expect("sub target");
    let (start, end) = target.range().expect("mapping target has range");
    let ctl = control();
    let epoch = epoch();
    let pid = Pid::new(target.pid() as i32).unwrap();
    let obs =
        ProcessObservation::acquire(pid, &epoch, proc_limits(), &ctl).expect("acquire sub target");
    let held = hold(&file);
    let cal = MappingPolicy::AllowPrivateCalibration {
        max_mapped_bytes: 512,
    };
    let pool = pool_for(&cal);
    match observe(
        &pool,
        &held,
        &obs,
        MapRange::new(start, end).unwrap(),
        cal,
        &ctl,
    ) {
        Ok(MappingOutcome::Inconclusive(reason)) => {
            let _ = reason.kind();
        }
        Ok(MappingOutcome::ExactRange(_)) => {
            // Granted environments never reach calibration; allowed.
        }
        other => panic!("sub-page cap must be inconclusive, saw {other:?}"),
    }
    pass("FS-subpage", "sub-page calibration cap inconclusive");
}

/// F05: stopped and exec-transition targets have no mapped range;
/// `range()` reports `None` instead of panicking (mapping targets
/// still report `Some`, as every range call above proves).
#[test]
fn non_mapping_targets_have_no_range() {
    let stopped = OwnedTarget::stopped().expect("stopped target");
    assert_eq!(stopped.range(), None);
    let exec = OwnedTarget::exec_transition().expect("exec target");
    assert_eq!(exec.range(), None);
    pass("FS-target-range", "stopped/exec range is None");
}

/// R05: an unrepresentable audit timeout refuses BEFORE the subject
/// spawns. The control proves the marker script executes in this
/// environment (skipped on noexec mounts); the audit itself must
/// return the overflow refusal with no marker and no spawn. Old code
/// panicked in `Instant + Duration` after spawning the subject.
#[cfg(target_arch = "x86_64")]
#[test]
fn audit_max_timeout_refuses_before_spawn() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("audit-maxtime");
    let script = dir.join("never-exec.sh");
    let marker = dir.join("spawned.marker");
    std::fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    // Control: the script really touches its marker when executed.
    let control = std::process::Command::new(&script).status();
    match control {
        Ok(status) if status.success() && marker.exists() => {}
        _ => {
            skip("FS10", "marker script cannot execute here (noexec mount?)");
            return;
        }
    }
    std::fs::remove_file(&marker).unwrap();
    let config = AuditConfig {
        target_dev: 0,
        target_ino: 0,
        max_entries: 8,
        timeout: Duration::MAX,
    };
    let err = audit::audit_subject(&script, &[], &config).unwrap_err();
    assert!(
        format!("{err}").contains("overflow"),
        "refusal must name the overflow: {err}"
    );
    assert!(
        !marker.exists(),
        "refused audit spawned its subject: marker exists"
    );
    pass(
        "FS10",
        "max timeout refuses before spawn; subject never ran",
    );
}

/// R06: a thread-plant worker that cannot spawn reports setup
/// failure (exit 2, `worker=15`) instead of panicking. RLIMIT_NPROC=1
/// in the child makes the clone fail deterministically; the report
/// write itself needs no threads.
#[test]
fn thread_plant_spawn_denial_is_setup_error() {
    use std::os::unix::process::CommandExt;
    let dir = temp_dir("audit-nproc");
    let target_file = dir.join("nproc-target.bin");
    std::fs::write(&target_file, pattern_bytes(9, 4096)).unwrap();
    let report = dir.join("nproc.report");
    let mut child = std::process::Command::new(audit_subject_bin());
    child.args([
        "thread-plant",
        "--target",
        &target_file.to_string_lossy(),
        "--report",
        &report.to_string_lossy(),
    ]);
    // SAFETY: the hook runs one raw syscall (setrlimit, async-signal-safe:
    // no allocation, no locks) and lowering a limit needs no privilege.
    unsafe {
        child.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            if libc::setrlimit(libc::RLIMIT_NPROC, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let status = match child.status() {
        Ok(status) => status,
        Err(e) => {
            skip("FS10", &format!("denial child would not spawn: {e}"));
            return;
        }
    };
    assert_eq!(
        status.code(),
        Some(2),
        "spawn denial must be a setup error, not a panic"
    );
    assert_eq!(
        std::fs::read_to_string(&report).unwrap_or_default().trim(),
        "worker=15",
        "denied spawn must report worker=15"
    );
    pass("FS10", "RLIMIT_NPROC denial exits 2 with worker=15");
}
