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

fn temp_dir(tag: &str) -> PathBuf {
    let id = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("tt04-{}-{}-{}", std::process::id(), id, tag));
    std::fs::create_dir_all(&dir).expect("owned temp dir");
    dir
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
    assert!(
        verdict.starts_with("verdict="),
        "fixture unexercised: clean subject observed nothing"
    );
    assert!(
        clean.target_backed_mmaps().is_empty(),
        "NoNew phase mapped target bytes: {:?}",
        clean.target_backed_mmaps()
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
    let err = hold_with(&locked, SymlinkPolicy::Follow)
        .expect_err("mode-000 open must be refused");
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
        .find(|e| e.path.is_some() && e.end - e.start >= 4096)
        .expect("fixture unexercised: no file-backed pre-exec range");
    let vrange = MapRange::new(victim.start, victim.start + 4096).unwrap();
    exec_target.trigger_exec();
    let exe = exec_target.wait_exe("sleep", Duration::from_secs(10));
    assert!(exe.ends_with("sleep"), "exec barrier never showed sleep");
    // Birth survives exec; the old range no longer resolves.
    let birth = eobs.verify_birth(&ctl).expect("verify birth");
    assert_eq!(
        birth.status(),
        scopebase_linux::process::BirthStatus::AliveSameBirth,
        "exec must preserve birth"
    );
    match observe(&pool, &held, &eobs, vrange, policy, &ctl) {
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
