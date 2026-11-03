#![cfg(feature = "walk")]
// SPDX-License-Identifier: Apache-2.0
//! LX10 bounded descriptor-relative discovery tests.
//!
//! Every expected traversal derives from the construction ledger built beside
//! the fixtures; assertions never depend on production enumeration order.

use scopebase_linux::{
    control::OperationControl,
    error::{LimitKind, Reason},
    walk::{
        walk, HeldDirectory, WalkBudget, WalkCharges, WalkEntry, WalkEpoch, WalkFailure,
        WalkFileType, WalkLimits, WalkPolicy,
    },
};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Owned scratch directory removed on drop. Restoration of denied modes is the
/// test's own job before this guard runs.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn fresh(prefix: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("lx10-{prefix}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture root");
        Self { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

const NON_UTF8_NAME: &[u8] = b"bad-\xff-name";

/// Ledger row: expected relative path, depth and type, independent of order.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Expected {
    path: PathBuf,
    depth: usize,
    kind: WalkFileType,
}

/// Build the standard 17-entry tree. `outside_secret` must exist outside the
/// root; the escape symlink points at it and the walk must never reach it.
fn build_tree(root: &Path, outside_secret: &Path) -> Vec<Expected> {
    let mut ledger = Vec::new();
    let push = |ledger: &mut Vec<Expected>, rel: PathBuf, depth: usize, kind: WalkFileType| {
        ledger.push(Expected {
            path: rel,
            depth,
            kind,
        });
    };
    for (rel, depth) in [
        ("a_dir", 1),
        ("a_dir/y_dir", 2),
        ("deep", 1),
        ("deep/d1", 2),
        ("deep/d1/d2", 3),
        ("deep/d1/d2/d3", 4),
    ] {
        std::fs::create_dir_all(root.join(rel)).expect("mkdir");
        push(
            &mut ledger,
            PathBuf::from(rel),
            depth,
            WalkFileType::Directory,
        );
    }
    for (rel, depth) in [
        ("a_dir/x_file", 2),
        ("a_dir/y_dir/z_file", 3),
        ("b_file", 1),
        ("deep/d1/d2/d3/leaf", 5),
    ] {
        std::fs::write(root.join(rel), b"payload").expect("write");
        push(
            &mut ledger,
            PathBuf::from(rel),
            depth,
            WalkFileType::Regular,
        );
    }
    for (rel, target) in [
        ("c_link", Path::new("b_file")),
        ("d_link", Path::new("a_dir")),
        ("e_link", outside_secret),
        ("loop1", Path::new("loop2")),
        ("loop2", Path::new("loop1")),
    ] {
        symlink(target, root.join(rel)).expect("symlink");
        push(&mut ledger, PathBuf::from(rel), 1, WalkFileType::Symlink);
    }
    std::fs::hard_link(root.join("b_file"), root.join("hard_b")).expect("hardlink");
    push(
        &mut ledger,
        PathBuf::from("hard_b"),
        1,
        WalkFileType::Regular,
    );
    let non_utf8 = OsString::from_vec(NON_UTF8_NAME.to_vec());
    std::fs::write(root.join(&non_utf8), b"n").expect("non-utf8 write");
    push(
        &mut ledger,
        PathBuf::from(non_utf8),
        1,
        WalkFileType::Regular,
    );
    assert_eq!(ledger.len(), 17, "ledger size is part of the contract");
    ledger
}

fn generous() -> WalkLimits {
    WalkLimits {
        max_entries_visited: 1 << 20,
        max_entries_queued: 1 << 20,
        max_depth: 64,
        max_path_bytes: 1 << 30,
        max_read_bytes: 1 << 30,
        max_output_bytes: 1 << 30,
        max_open_fds: 1 << 20,
        max_stat_calls: 1 << 20,
        max_read_calls: 1 << 20,
    }
}

fn open_stay(fixture: &Fixture) -> HeldDirectory {
    HeldDirectory::open(fixture.path(), WalkPolicy::StayOnMount).expect("open root")
}

fn budget(per_round: WalkLimits, total: WalkLimits, epoch: &WalkEpoch) -> WalkBudget {
    WalkBudget::new(per_round, total, epoch).expect("valid budget")
}

fn entry_key(entry: &WalkEntry) -> Expected {
    Expected {
        path: entry.path().to_path_buf(),
        depth: entry.depth(),
        kind: entry.file_type(),
    }
}

fn ledger_set(ledger: &[Expected]) -> BTreeSet<Expected> {
    ledger.iter().cloned().collect()
}

fn assert_within_batch_sorted(entries: &[WalkEntry]) {
    let mut prev: Option<&OsStr> = None;
    for entry in entries {
        let cur = entry.path().as_os_str();
        if let Some(p) = prev {
            assert!(p <= cur, "batch not sorted: {p:?} before {cur:?}");
        }
        prev = Some(cur);
    }
}

/// Drive walk() to completion, asserting within-batch order on every batch.
fn walk_all(root: &HeldDirectory, budget: &mut WalkBudget) -> Vec<WalkEntry> {
    let control = OperationControl::unlimited();
    let mut out = Vec::new();
    for _ in 0..1_000_000 {
        let batch = walk(root, budget, &control).expect("walk batch succeeds");
        assert_within_batch_sorted(batch.entries());
        assert_eq!(
            batch.round_charges().entries_visited() as usize,
            batch.entries().len(),
            "round charges match emitted entries"
        );
        out.extend(batch.entries().iter().cloned());
        if batch.is_done() {
            return out;
        }
    }
    panic!("walk did not finish within round cap");
}

fn to_set(entries: &[WalkEntry]) -> BTreeSet<Expected> {
    entries.iter().map(entry_key).collect()
}

/// Drive walk() until it fails. Completion or a round-cap breach panics: a
/// regression that never fails must fail fast, never hang the suite.
fn expect_failure(
    root: &HeldDirectory,
    budget: &mut WalkBudget,
    control: &OperationControl,
) -> WalkFailure {
    for _ in 0..1000 {
        match walk(root, budget, control) {
            Ok(batch) => assert!(
                !batch.is_done(),
                "expected a failure, the walk completed instead"
            ),
            Err(failure) => return failure,
        }
    }
    panic!("walk neither failed nor finished within round cap");
}

/// Bounded variant of `expect_failure` that keeps successful batches.
fn expect_failure_collect(
    root: &HeldDirectory,
    budget: &mut WalkBudget,
    control: &OperationControl,
    out: &mut Vec<WalkEntry>,
) -> WalkFailure {
    for _ in 0..1000 {
        match walk(root, budget, control) {
            Ok(batch) => {
                assert!(
                    !batch.is_done(),
                    "expected a failure, the walk completed instead"
                );
                out.extend(batch.entries().iter().cloned());
            }
            Err(failure) => return failure,
        }
    }
    panic!("walk neither failed nor finished within round cap");
}

struct Calibrated {
    tree: Fixture,
    #[allow(dead_code)]
    outside: Fixture,
    charges: WalkCharges,
    ledger: Vec<Expected>,
}

/// Build fixtures, walk to completion with generous bounds, and report the
/// observed totals so N/N+1 tests do not depend on readdir internals.
fn calibrate() -> Calibrated {
    let outside = Fixture::fresh("outside");
    let secret = outside.path().join("out_secret");
    std::fs::write(&secret, b"secret").expect("outside secret");
    let tree = Fixture::fresh("tree");
    let ledger = build_tree(tree.path(), &secret);
    let root = open_stay(&tree);
    let epoch = WalkEpoch::new();
    let mut b = budget(generous(), generous(), &epoch);
    let got = walk_all(&root, &mut b);
    assert_eq!(to_set(&got), ledger_set(&ledger), "ledger defines truth");
    let charges = b.cumulative_charges();
    Calibrated {
        tree,
        outside,
        charges,
        ledger,
    }
}

#[test]
fn full_tree_matches_ledger_with_exact_structural_charges() {
    let cal = calibrate();
    let c = &cal.charges;
    assert_eq!(c.entries_visited(), 17);
    assert_eq!(c.entries_queued(), 6, "six subdirs descended");
    assert_eq!(c.open_fds(), 7, "root level plus six subdir levels");
    assert_eq!(c.peak_open_fds(), 5, "deepest chain root/deep/d1/d2/d3");
    assert_eq!(
        c.stat_calls(),
        23,
        "one per entry plus one confirm per subdir"
    );
    assert_eq!(c.depth_pruned(), 0);
    assert_eq!(c.mount_pruned(), 0);
    assert_eq!(c.skipped_denied(), 0);
    assert_eq!(c.skipped_unstable(), 0);
    let path_sum: u64 = cal
        .ledger
        .iter()
        .map(|e| e.path.as_os_str().len() as u64)
        .sum();
    assert_eq!(c.path_bytes(), path_sum);
    assert_eq!(c.output_bytes(), path_sum, "no pruning, all emitted");
    let name_sum: u64 = cal
        .ledger
        .iter()
        .map(|e| e.path.file_name().expect("ledger file name").len() as u64)
        .sum();
    assert!(
        c.read_bytes() >= name_sum,
        "read bytes cover every observed name"
    );
    assert!(
        c.read_calls() >= 17 + 7,
        "reads cover every entry plus terminal end-of-dir reads"
    );
}

#[test]
fn types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<HeldDirectory>();
    assert_send_sync::<WalkBudget>();
    assert_send_sync::<WalkEpoch>();
    assert_send_sync::<WalkEntry>();
}

#[test]
fn per_round_visited_bounds_batches() {
    for k in [1u64, 5] {
        let cal = calibrate();
        let root = open_stay(&cal.tree);
        let epoch = WalkEpoch::new();
        let mut per = generous();
        per.max_entries_visited = k;
        let mut b = budget(per, generous(), &epoch);
        let control = OperationControl::unlimited();
        let mut out = Vec::new();
        let mut batches = 0;
        loop {
            let batch = walk(&root, &mut b, &control).expect("round ends, not fails");
            assert_within_batch_sorted(batch.entries());
            assert!(
                batch.entries().len() as u64 <= k,
                "batch respects per-round cap"
            );
            if !batch.is_done() {
                assert_eq!(
                    batch.entries().len() as u64,
                    k,
                    "only completion ends a non-full batch"
                );
            }
            out.extend(batch.entries().iter().cloned());
            batches += 1;
            assert!(batches < 1000, "round cap");
            if batch.is_done() {
                break;
            }
        }
        assert_eq!(
            to_set(&out),
            ledger_set(&cal.ledger),
            "same content in parts"
        );
    }
}

#[test]
fn tight_per_round_limits_still_complete() {
    let cal = calibrate();
    let root = open_stay(&cal.tree);
    let epoch = WalkEpoch::new();
    let mut per = generous();
    per.max_entries_visited = 2;
    per.max_entries_queued = 1;
    per.max_open_fds = 1;
    per.max_stat_calls = 3;
    per.max_read_calls = 4;
    let mut b = budget(per, generous(), &epoch);
    let got = walk_all(&root, &mut b);
    assert_eq!(to_set(&got), ledger_set(&cal.ledger));
    assert_eq!(b.cumulative_charges().entries_visited(), 17);
}

#[test]
fn repeated_partial_batch_matches_single() {
    let cal = calibrate();
    let root = open_stay(&cal.tree);
    let epoch = WalkEpoch::new();
    let mut per = generous();
    per.max_entries_visited = 3;
    let mut partial = budget(per, generous(), &epoch);
    let partial_got = walk_all(&root, &mut partial);
    let mut single = budget(generous(), generous(), &epoch);
    let single_got = walk_all(&root, &mut single);
    assert_eq!(to_set(&partial_got), to_set(&single_got));
    assert_eq!(to_set(&single_got), ledger_set(&cal.ledger));
    assert_eq!(partial.cumulative_charges(), single.cumulative_charges());
}

/// Total == calibrated actual completes; total == actual - 1 fails typed.
fn assert_total_boundary(
    cal: &Calibrated,
    set_total: impl Fn(&mut WalkLimits, u64),
    actual: u64,
    kind: LimitKind,
) {
    assert!(actual > 0, "calibration must be nonzero");
    for (limit, expect_ok) in [(actual, true), (actual - 1, false)] {
        let root = open_stay(&cal.tree);
        let epoch = WalkEpoch::new();
        // Calibrated totals sit below the generous per-round floors, so the
        // bound under test applies to both windows; batching may split rounds
        // but the completion/failure outcome is the total's verdict.
        let mut per = generous();
        set_total(&mut per, limit);
        let mut total = generous();
        set_total(&mut total, limit);
        let mut b = budget(per, total, &epoch);
        let control = OperationControl::unlimited();
        let mut done = false;
        let mut failure_reason = None;
        for _ in 0..1_000_000 {
            match walk(&root, &mut b, &control) {
                Ok(batch) => {
                    if batch.is_done() {
                        done = true;
                        break;
                    }
                }
                Err(failure) => {
                    assert!(b.pending() > 0, "failure retains remaining queue custody");
                    assert_eq!(failure.epoch_id(), epoch.id(), "failure carries its epoch");
                    let err = failure.error();
                    assert!(err.charges().syscall_attempts() > 0, "spent work is kept");
                    assert_eq!(
                        err.charges().fd_acquisitions(),
                        failure.charges().open_fds()
                    );
                    failure_reason = Some(err.reason());
                    break;
                }
            }
        }
        if expect_ok {
            assert!(done, "total == actual must complete for {kind:?}");
        } else {
            assert_eq!(
                failure_reason,
                Some(Reason::LimitExceeded(kind)),
                "total == actual - 1 must fail typed for {kind:?}"
            );
        }
    }
}

#[test]
fn total_visited_limit_enforced() {
    let cal = calibrate();
    assert_total_boundary(
        &cal,
        |l, v| l.max_entries_visited = v,
        cal.charges.entries_visited(),
        LimitKind::Entries,
    );
}

#[test]
fn total_queued_limit_enforced() {
    let cal = calibrate();
    assert_total_boundary(
        &cal,
        |l, v| l.max_entries_queued = v as usize,
        cal.charges.entries_queued(),
        LimitKind::QueuedEntries,
    );
}

#[test]
fn total_path_bytes_limit_enforced() {
    let cal = calibrate();
    assert_total_boundary(
        &cal,
        |l, v| l.max_path_bytes = v as usize,
        cal.charges.path_bytes(),
        LimitKind::PathBytes,
    );
}

#[test]
fn total_output_bytes_limit_enforced() {
    let cal = calibrate();
    assert_total_boundary(
        &cal,
        |l, v| l.max_output_bytes = v as usize,
        cal.charges.output_bytes(),
        LimitKind::OutputBytes,
    );
}

#[test]
fn total_open_fds_limit_enforced() {
    let cal = calibrate();
    assert_total_boundary(
        &cal,
        |l, v| l.max_open_fds = v as usize,
        cal.charges.open_fds(),
        LimitKind::OpenFds,
    );
}

#[test]
fn total_stat_calls_limit_enforced() {
    let cal = calibrate();
    assert_total_boundary(
        &cal,
        |l, v| l.max_stat_calls = v,
        cal.charges.stat_calls(),
        LimitKind::StatCalls,
    );
}

#[test]
fn total_read_calls_limit_enforced() {
    let cal = calibrate();
    assert_total_boundary(
        &cal,
        |l, v| l.max_read_calls = v,
        cal.charges.read_calls(),
        LimitKind::ReadCalls,
    );
}

#[test]
fn total_read_bytes_limit_enforced() {
    let cal = calibrate();
    assert_total_boundary(
        &cal,
        |l, v| l.max_read_bytes = v,
        cal.charges.read_bytes(),
        LimitKind::ReadBytes,
    );
}

#[test]
fn depth_limit_prunes_deeper_entries() {
    // Pruned counts cover observed too-deep entries only: a pruned directory
    // is never descended, so its hidden subtree is never observed.
    for (max_depth, keep, pruned) in [(1usize, 10u64, 3u64), (2, 13, 2)] {
        let cal = calibrate();
        let root = open_stay(&cal.tree);
        let epoch = WalkEpoch::new();
        let mut limits = generous();
        limits.max_depth = max_depth;
        let mut b = budget(limits, limits, &epoch);
        let got = walk_all(&root, &mut b);
        let expected: BTreeSet<Expected> = cal
            .ledger
            .iter()
            .filter(|e| e.depth <= max_depth)
            .cloned()
            .collect();
        assert_eq!(to_set(&got), expected);
        assert_eq!(b.cumulative_charges().entries_visited(), keep);
        assert_eq!(b.cumulative_charges().depth_pruned(), pruned);
    }
}

#[test]
fn raise_total_resumes_losslessly() {
    let cal = calibrate();
    let root = open_stay(&cal.tree);
    let epoch = WalkEpoch::new();
    let mut per = generous();
    per.max_entries_visited = 16;
    let mut total = generous();
    total.max_entries_visited = 16;
    let mut b = budget(per, total, &epoch);
    let control = OperationControl::unlimited();
    let mut out = Vec::new();
    let failure = expect_failure_collect(&root, &mut b, &control, &mut out);
    assert_eq!(
        failure.error().reason(),
        Reason::LimitExceeded(LimitKind::Entries)
    );
    assert_eq!(failure.charges().entries_visited(), 16);
    out.extend(failure.partial().iter().cloned());
    let pending_before = b.pending();
    assert!(pending_before > 0, "queue survives the failure");
    b.raise_total(&generous(), &epoch)
        .expect("same-epoch raise resumes");
    let rest = walk_all(&root, &mut b);
    out.extend(rest);
    assert_eq!(to_set(&out), ledger_set(&cal.ledger), "no entry lost");
    assert_eq!(b.cumulative_charges().entries_visited(), 17);
}

#[test]
fn raise_total_rejects_foreign_epoch_and_shrink() {
    let epoch = WalkEpoch::new();
    let other = WalkEpoch::new();
    assert_ne!(epoch.id(), other.id(), "epochs are unique");
    let mut b = budget(generous(), generous(), &epoch);
    let err = b
        .raise_total(&generous(), &other)
        .expect_err("foreign epoch must refuse");
    assert_eq!(err.reason(), Reason::WrongContext);
    let mut shrink = generous();
    shrink.max_entries_visited = 1;
    let err = b
        .raise_total(&shrink, &epoch)
        .expect_err("shrink must refuse");
    assert_eq!(err.reason(), Reason::InvalidInput);
}

#[test]
fn resume_with_new_epoch_is_refused() {
    let cal = calibrate();
    let root = open_stay(&cal.tree);
    let epoch = WalkEpoch::new();
    let mut per = generous();
    per.max_entries_visited = 16;
    let mut total = generous();
    total.max_entries_visited = 16;
    let mut b = budget(per, total, &epoch);
    let control = OperationControl::unlimited();
    let failure = expect_failure(&root, &mut b, &control);
    assert_eq!(failure.epoch_id(), epoch.id());
    assert_eq!(b.epoch_id(), epoch.id());
    b.assert_epoch(&epoch).expect("same epoch resumes");
    let other = WalkEpoch::new();
    let err = b.assert_epoch(&other).expect_err("new epoch must refuse");
    assert_eq!(err.reason(), Reason::WrongContext);
}

#[test]
fn symlink_escape_is_never_followed() {
    let cal = calibrate();
    let root = open_stay(&cal.tree);
    let epoch = WalkEpoch::new();
    let mut b = budget(generous(), generous(), &epoch);
    let got = walk_all(&root, &mut b);
    for name in ["c_link", "d_link", "e_link", "loop1", "loop2"] {
        assert!(
            got.iter()
                .any(|e| e.path() == Path::new(name) && e.file_type() == WalkFileType::Symlink),
            "{name} is reported as a symlink, never descended"
        );
    }
    assert!(
        !got.iter().any(|e| e
            .path()
            .as_os_str()
            .as_bytes()
            .windows(b"out_secret".len())
            .any(|w| w == b"out_secret")),
        "outside secret must never appear"
    );
    let a_children: Vec<_> = got
        .iter()
        .filter(|e| e.path().starts_with("a_dir") && e.depth() > 1)
        .collect();
    assert_eq!(
        a_children.len(),
        3,
        "a_dir subtree appears once, not again via d_link"
    );
}

#[test]
fn hardlink_aliases_are_both_reported() {
    let cal = calibrate();
    let root = open_stay(&cal.tree);
    let epoch = WalkEpoch::new();
    let mut b = budget(generous(), generous(), &epoch);
    let got = walk_all(&root, &mut b);
    let first = got
        .iter()
        .find(|e| e.path() == Path::new("b_file"))
        .expect("b_file");
    let alias = got
        .iter()
        .find(|e| e.path() == Path::new("hard_b"))
        .expect("hard_b");
    assert_eq!(first.device(), alias.device());
    assert_eq!(first.inode(), alias.inode());
}

#[test]
fn non_utf8_name_round_trips_exact_bytes() {
    let cal = calibrate();
    let root = open_stay(&cal.tree);
    let epoch = WalkEpoch::new();
    let mut b = budget(generous(), generous(), &epoch);
    let got = walk_all(&root, &mut b);
    let hit = got
        .iter()
        .find(|e| e.path().as_os_str().as_bytes() == NON_UTF8_NAME)
        .expect("non-UTF8 entry");
    assert_eq!(hit.depth(), 1);
    assert_eq!(hit.file_type(), WalkFileType::Regular);
}

#[test]
fn cancel_between_rounds_keeps_spent_charges() {
    let cal = calibrate();
    let root = open_stay(&cal.tree);
    let epoch = WalkEpoch::new();
    let mut per = generous();
    per.max_entries_visited = 5;
    let mut b = budget(per, generous(), &epoch);
    let token = scopebase_linux::control::CancelToken::new();
    let control = OperationControl::new(None, token.clone());
    let first = walk(&root, &mut b, &control).expect("first round");
    assert_eq!(first.entries().len(), 5);
    assert!(!first.is_done());
    let spent = b.cumulative_charges();
    let pending = b.pending();
    assert!(pending > 0);
    token.cancel();
    let failure = walk(&root, &mut b, &control).expect_err("cancelled round fails");
    assert_eq!(failure.error().reason(), Reason::Cancelled);
    assert!(failure.partial().is_empty(), "refused before new effects");
    assert_eq!(
        b.cumulative_charges(),
        spent,
        "spent work is never refunded"
    );
    assert_eq!(b.pending(), pending, "queue custody survives cancel");
    let rest = walk_all(&root, &mut b);
    let mut all: Vec<WalkEntry> = first.entries().to_vec();
    all.extend(rest);
    assert_eq!(to_set(&all), ledger_set(&cal.ledger));
}

#[test]
fn precancelled_control_refuses_before_effect() {
    let cal = calibrate();
    let root = open_stay(&cal.tree);
    let epoch = WalkEpoch::new();
    let mut b = budget(generous(), generous(), &epoch);
    let token = scopebase_linux::control::CancelToken::new();
    token.cancel();
    let control = OperationControl::new(None, token);
    let failure = walk(&root, &mut b, &control).expect_err("precancel refuses");
    assert_eq!(failure.error().reason(), Reason::Cancelled);
    assert_eq!(b.cumulative_charges(), WalkCharges::default());
    assert_eq!(b.pending(), 0);
}

#[test]
fn expired_deadline_refuses() {
    use std::time::Duration;
    let cal = calibrate();
    let root = open_stay(&cal.tree);
    let epoch = WalkEpoch::new();
    let mut b = budget(generous(), generous(), &epoch);
    let deadline =
        scopebase_linux::control::MonotonicDeadline::after(Duration::ZERO).expect("zero valid");
    let control =
        OperationControl::new(Some(deadline), scopebase_linux::control::CancelToken::new());
    let failure = walk(&root, &mut b, &control).expect_err("expired deadline refuses");
    assert_eq!(failure.error().reason(), Reason::Deadline);
}

#[cfg(target_os = "linux")]
fn device_of(path: &Path) -> u64 {
    std::os::unix::fs::MetadataExt::dev(&std::fs::metadata(path).expect("oracle stat"))
}

/// Independent oracle: depth-1 subdirectories whose own device differs.
#[cfg(target_os = "linux")]
fn mounted_children(root: &Path) -> Vec<OsString> {
    let root_dev = device_of(root);
    let mut mounts = Vec::new();
    for entry in std::fs::read_dir(root).expect("oracle readdir") {
        let entry = entry.expect("oracle entry");
        if entry.file_type().expect("oracle type").is_dir() && device_of(&entry.path()) != root_dev
        {
            mounts.push(entry.file_name());
        }
    }
    mounts
}

#[test]
#[cfg(target_os = "linux")]
fn stay_on_mount_prunes_crossings() {
    let mut qualified = 0;
    for candidate in ["/dev", "/sys"] {
        let root_path = Path::new(candidate);
        let mounts = mounted_children(root_path);
        if mounts.is_empty() {
            continue;
        }
        qualified += 1;
        let root_dev = device_of(root_path);
        let root = HeldDirectory::open(root_path, WalkPolicy::StayOnMount).expect("open");
        let epoch = WalkEpoch::new();
        let mut b = budget(generous(), generous(), &epoch);
        let got = walk_all(&root, &mut b);
        assert!(
            b.cumulative_charges().mount_pruned() >= mounts.len() as u64,
            "every mounted child prunes descent"
        );
        for m in &mounts {
            let mount_rel = PathBuf::from(m);
            assert!(
                got.iter().any(|e| e.path() == mount_rel && e.depth() == 1),
                "mountpoint itself is still reported: {m:?}"
            );
            assert!(
                !got.iter()
                    .any(|e| e.path().starts_with(&mount_rel) && e.depth() > 1),
                "never crossed into {m:?}"
            );
        }
        for e in &got {
            if e.depth() > 1 {
                assert_eq!(
                    e.device(),
                    root_dev,
                    "StayOnMount emits only root-device entries below depth 1: {e:?}"
                );
            }
        }
    }
    assert!(
        qualified >= 1,
        "environment must mount something under /dev or /sys"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn allow_mount_crossing_descends() {
    let mut crossed: Option<(PathBuf, PathBuf)> = None;
    for candidate in ["/dev", "/sys"] {
        let root_path = Path::new(candidate);
        let mounts = mounted_children(root_path);
        let nonempty: Vec<OsString> = mounts
            .into_iter()
            .filter(|m| {
                std::fs::read_dir(root_path.join(m))
                    .map(|mut d| d.next().is_some())
                    .unwrap_or(false)
            })
            .collect();
        if nonempty.is_empty() {
            continue;
        }
        let root = HeldDirectory::open(root_path, WalkPolicy::AllowMountCrossing).expect("open");
        let epoch = WalkEpoch::new();
        let mut b = budget(generous(), generous(), &epoch);
        let got = walk_all(&root, &mut b);
        for m in &nonempty {
            let mount_rel = PathBuf::from(m);
            if got
                .iter()
                .any(|e| e.path().starts_with(&mount_rel) && e.depth() > 1)
            {
                crossed = Some((root_path.to_path_buf(), mount_rel));
                break;
            }
        }
        if crossed.is_some() {
            break;
        }
    }
    assert!(
        crossed.is_some(),
        "explicit crossing must descend a non-empty mounted child"
    );
}

/// Restore mode on drop so the fixture guard can remove the tree.
struct RestoreMode(PathBuf);

impl Drop for RestoreMode {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

#[test]
fn denied_subdir_is_skipped_with_evidence() {
    let tree = Fixture::fresh("denied");
    let ledger = build_tree(tree.path(), &tree.path().join("nope"));
    assert_eq!(ledger.len(), 17);
    let priv_dir = tree.path().join("priv");
    std::fs::create_dir(&priv_dir).expect("priv dir");
    std::fs::write(priv_dir.join("inner"), b"i").expect("inner");
    std::fs::set_permissions(&priv_dir, std::fs::Permissions::from_mode(0)).expect("deny");
    let _restore = RestoreMode(priv_dir.clone());
    // Self-calibration: root can still read a mode-0 directory.
    let can_read = std::fs::read_dir(&priv_dir).is_ok();
    let root = open_stay(&tree);
    let epoch = WalkEpoch::new();
    let mut b = budget(generous(), generous(), &epoch);
    let got = walk_all(&root, &mut b);
    let inner_seen = got.iter().any(|e| e.path() == Path::new("priv/inner"));
    let priv_seen = got
        .iter()
        .any(|e| e.path() == Path::new("priv") && e.file_type() == WalkFileType::Directory);
    assert!(priv_seen, "the denied directory itself is still reported");
    if can_read {
        assert!(inner_seen, "privileged reader descends");
    } else {
        assert!(!inner_seen, "denied descent stays out");
        assert!(
            b.cumulative_charges().skipped_denied() >= 1,
            "denial leaves evidence"
        );
    }
}

#[test]
fn open_rejects_non_directory_symlink_missing_and_bad_input() {
    let tree = Fixture::fresh("openneg");
    build_tree(tree.path(), &tree.path().join("nope"));
    let file_err = HeldDirectory::open(&tree.path().join("b_file"), WalkPolicy::StayOnMount)
        .expect_err("regular file is not a directory");
    assert_eq!(file_err.reason(), Reason::NonRegular);
    let link_err = HeldDirectory::open(&tree.path().join("d_link"), WalkPolicy::StayOnMount)
        .expect_err("directory symlink root is refused");
    assert_eq!(link_err.reason(), Reason::WrongContext);
    let missing_err = HeldDirectory::open(&tree.path().join("absent"), WalkPolicy::StayOnMount)
        .expect_err("missing root disappears");
    assert_eq!(missing_err.reason(), Reason::Disappeared);
    let empty_err =
        HeldDirectory::open(Path::new(""), WalkPolicy::StayOnMount).expect_err("empty refuses");
    assert_eq!(empty_err.reason(), Reason::InvalidInput);
    assert_eq!(empty_err.charges().syscall_attempts(), 0);
    let nul = PathBuf::from(OsStr::from_bytes(b"a\0b"));
    let nul_err = HeldDirectory::open(&nul, WalkPolicy::StayOnMount).expect_err("NUL refuses");
    assert_eq!(nul_err.reason(), Reason::InvalidInput);
    assert_eq!(nul_err.charges().syscall_attempts(), 0);
}

#[test]
fn budget_new_rejects_bad_limits() {
    let epoch = WalkEpoch::new();
    let mut zero_field: Vec<(&str, Box<dyn Fn(&mut WalkLimits)>)> = Vec::new();
    zero_field.push(("visited", Box::new(|l| l.max_entries_visited = 0)));
    zero_field.push(("queued", Box::new(|l| l.max_entries_queued = 0)));
    zero_field.push(("depth", Box::new(|l| l.max_depth = 0)));
    zero_field.push(("path", Box::new(|l| l.max_path_bytes = 0)));
    zero_field.push(("read_bytes", Box::new(|l| l.max_read_bytes = 0)));
    zero_field.push(("output", Box::new(|l| l.max_output_bytes = 0)));
    zero_field.push(("open", Box::new(|l| l.max_open_fds = 0)));
    zero_field.push(("stat", Box::new(|l| l.max_stat_calls = 0)));
    zero_field.push(("read_calls", Box::new(|l| l.max_read_calls = 0)));
    for (name, zero) in &zero_field {
        let mut per = generous();
        zero(&mut per);
        let err = WalkBudget::new(per, generous(), &epoch)
            .expect_err(&format!("zero per-round {name} refuses"));
        assert_eq!(err.reason(), Reason::InvalidInput);
        let mut total = generous();
        zero(&mut total);
        let err = WalkBudget::new(generous(), total, &epoch)
            .expect_err(&format!("zero total {name} refuses"));
        assert_eq!(err.reason(), Reason::InvalidInput);
    }
    let mut per = generous();
    per.max_entries_visited = generous().max_entries_visited + 1;
    let err = WalkBudget::new(per, generous(), &epoch).expect_err("per-round above total refuses");
    assert_eq!(err.reason(), Reason::InvalidInput);
    WalkBudget::new(generous(), generous(), &epoch).expect("equal bounds admit");
}

#[test]
fn error_display_omits_paths() {
    let cal = calibrate();
    let root = open_stay(&cal.tree);
    let epoch = WalkEpoch::new();
    let mut per = generous();
    per.max_entries_visited = 16;
    let mut total = generous();
    total.max_entries_visited = 16;
    let mut b = budget(per, total, &epoch);
    let control = OperationControl::unlimited();
    let failure = expect_failure(&root, &mut b, &control);
    for text in [
        format!("{}", failure.error()),
        format!("{:?}", failure.error()),
    ] {
        assert!(!text.contains("lx10"), "no root path leaks: {text}");
        assert!(!text.contains("a_dir"), "no entry path leaks: {text}");
    }
}

#[test]
fn walk_after_done_is_empty_and_stable() {
    let cal = calibrate();
    let root = open_stay(&cal.tree);
    let epoch = WalkEpoch::new();
    let mut b = budget(generous(), generous(), &epoch);
    let got = walk_all(&root, &mut b);
    assert_eq!(to_set(&got), ledger_set(&cal.ledger));
    let control = OperationControl::unlimited();
    for _ in 0..3 {
        let tail = walk(&root, &mut b, &control).expect("tail call succeeds");
        assert!(tail.is_done());
        assert!(tail.entries().is_empty());
    }
}

#[test]
fn unsatisfiable_per_round_byte_cap_fails_typed() {
    let cal = calibrate();
    let root = open_stay(&cal.tree);
    let epoch = WalkEpoch::new();
    let mut per = generous();
    per.max_output_bytes = 1;
    let mut b = budget(per, generous(), &epoch);
    let control = OperationControl::unlimited();
    let mut rounds = 0;
    let reason = loop {
        rounds += 1;
        assert!(rounds <= 10, "no spin on unsatisfiable cap");
        match walk(&root, &mut b, &control) {
            Ok(batch) => {
                assert!(!batch.is_done(), "cannot complete under the cap");
            }
            Err(failure) => break failure.error().reason(),
        }
    };
    assert_eq!(reason, Reason::LimitExceeded(LimitKind::OutputBytes));
}

#[test]
fn charges_grow_monotonically_across_rounds() {
    let cal = calibrate();
    let root = open_stay(&cal.tree);
    let epoch = WalkEpoch::new();
    let mut per = generous();
    per.max_entries_visited = 4;
    let mut b = budget(per, generous(), &epoch);
    let control = OperationControl::unlimited();
    let mut last = WalkCharges::default();
    let mut emitted = 0;
    loop {
        let batch = walk(&root, &mut b, &control).expect("round ok");
        emitted += batch.entries().len() as u64;
        let now = b.cumulative_charges();
        assert!(now.entries_visited() >= last.entries_visited());
        assert!(now.open_fds() >= last.open_fds());
        assert!(now.stat_calls() >= last.stat_calls());
        assert_eq!(now.entries_visited(), emitted);
        last = now;
        if batch.is_done() {
            break;
        }
    }
    assert_eq!(emitted, 17);
}

/// Child side of the FD-exhaustion proof. The parent spawns this exact test in
/// a subprocess so the exhausted table never touches the main test process.
#[test]
fn fd_exhaustion_child_reports_unavailable() {
    if std::env::var("SCOPEBASE_LX10_FDEXHAUST").is_err() {
        return;
    }
    let tree = Fixture::fresh("fdex");
    std::fs::write(tree.path().join("f"), b"f").expect("write");
    let mut held = Vec::new();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(f) => held.push(f),
            Err(_) => break,
        }
        assert!(held.len() <= 1_000_000, "fd table unexpectedly large");
    }
    let err = HeldDirectory::open(tree.path(), WalkPolicy::StayOnMount)
        .expect_err("open under exhaustion must fail");
    assert_eq!(err.reason(), Reason::Unavailable, "EMFILE/ENFILE map here");
    assert!(err.source().is_some(), "primary errno is preserved");
    drop(held);
}

#[test]
fn fd_exhaustion_parent_spawns_child() {
    if std::env::var("SCOPEBASE_LX10_FDEXHAUST").is_ok() {
        return;
    }
    let exe = std::env::current_exe().expect("current test exe");
    let status = std::process::Command::new(exe)
        .args([
            "fd_exhaustion_child_reports_unavailable",
            "--exact",
            "--nocapture",
        ])
        .env("SCOPEBASE_LX10_FDEXHAUST", "1")
        .status()
        .expect("spawn child");
    assert!(status.success(), "child proved EMFILE behavior: {status}");
}

// S206: walk diagnostics omit paths and stay bounded like every other
// identity/payload type. Canary names reach entries via `path()` but
// must never appear in any `Debug` format, and each format stays short
// printable ASCII (mirrors the held.rs diagnostic-bound test).
#[test]
fn walk_debug_omits_paths_and_stays_bounded() {
    let tree = Fixture::fresh("canary");
    for name in ["CANARY-one", "CANARY-two", "CANARY-three"] {
        std::fs::write(tree.path().join(name), b"payload").expect("canary file");
    }
    let root = open_stay(&tree);
    let epoch = WalkEpoch::new();
    let mut one = generous();
    one.max_entries_visited = 1;
    let mut b = budget(one, one, &epoch);
    let mut seen = Vec::new();
    let failure = expect_failure_collect(
        &root,
        &mut b,
        &OperationControl::unlimited(),
        &mut seen,
    );
    seen.extend(failure.partial().iter().cloned());
    assert!(
        seen.iter()
            .any(|e| e.path().to_string_lossy().contains("CANARY")),
        "canary reaches entries via path()"
    );
    // A successful batch over the same canary tree.
    let root2 = open_stay(&tree);
    let epoch2 = WalkEpoch::new();
    let mut b2 = budget(generous(), generous(), &epoch2);
    let batch = walk(&root2, &mut b2, &OperationControl::unlimited()).expect("batch succeeds");
    assert!(!batch.entries().is_empty(), "batch carries entries");
    let mut texts = Vec::new();
    for entry in &seen {
        texts.push(format!("{entry:?}"));
        texts.push(format!("{entry:#?}"));
    }
    for entry in batch.entries() {
        texts.push(format!("{entry:?}"));
    }
    texts.push(format!("{batch:?}"));
    texts.push(format!("{batch:#?}"));
    texts.push(format!("{failure:?}"));
    texts.push(format!("{failure:#?}"));
    for text in &texts {
        assert!(text.len() <= 256, "diagnostic bounded: {text:?}");
        assert!(
            text.bytes().all(|b| (0x20..=0x7e).contains(&b)),
            "diagnostic printable: {text:?}"
        );
        assert!(!text.contains("CANARY"), "diagnostic omits paths: {text:?}");
    }
}
