// SPDX-License-Identifier: Apache-2.0
//! BP05: held-file attachment custody with explicit retirement.
//!
//! PORT/ADAPT provenance (all user-owned donor slices, blanket
//! `OWNER-2026-10-23`; third-party/upstream lines never copied):
//! - p11scope `.worktrees/v040-integration/crates/bpf-multi/src/lib.rs`
//!   @ `2c2713e66292b0d2688508a25f79e813ae823d81`: `BisectHalt` with
//!   `closed_leaves` (lines 338-348), the halt closure that closes
//!   already-created leaves and counts them (lines 411-421), and the
//!   halt-after-linked-leaf vector (lines 980-1014). ADAPT: silent
//!   drop-with-count becomes explicit per-link retirement; any unproven
//!   outcome becomes retained Unresolved custody, never a claimed close.
//! - KryProbe `crates/kryprobe-core/src/attach.rs` @ `d153f3aa`
//!   (`d153f3aaf9a3931337b47c9e1b046c692da55083`): issuance-only
//!   `LinkGroup` generation/base (lines 12-80) and `GenerationGuard`
//!   stale refusal (lines 260-274). ADAPT: move-only
//!   session/entry tickets with foreign/stale refusal.
//! - KryProbe `crates/kryprobe-privilege/src/attach.rs` @ `d153f3aa`:
//!   RAII `OwnedLink` (lines 53-72) and stale-guard rejection at the
//!   attach boundary (lines 94-102). ADAPT: stale-context refusal shape.
//! - OSSLscope `osslscope/src/plan.rs` @ `1a481831a85375ecb2d69ca65618d37c846de8b3`:
//!   `bisect_attach` returning live links plus refused indices
//!   (lines 579-611). ADAPT: split/rollback walk with per-index refusal.
//! - scopebase-linux `HeldFile` (LX02, same workspace): `from_file`
//!   adoption, `AsFd` borrows and creating-process checks. The HeldFile
//!   authority binding is tested here; no historical pathname is reopened.
//!
//! These tests use scripted fake backends (no native effects): every
//! custody/ordering/accounting claim is an ownership proof. Genuine
//! native retirement failure stays a TT05 live case, not replaced here.

#[path = "support/json_mini.rs"]
mod json_mini;

#[path = "support/fake_backend.rs"]
mod fake_backend;

use fake_backend::{RetireStep, ScriptBackend, ScriptOutcome};
use scopebase_bpf::attach::{
    execute_plan, AttachMode, AttachOutcome, AttachPlan, AttachSummary, ErrorAction, ErrorPolicy,
    PoolClose, PoolReconcile, PoolUsage, Retirement, RetirementBudget, RetirementCapacity,
    RetirementPool, Site,
};
use scopebase_bpf::{ErrorKind, Limits, OperationError, Stage};
use scopebase_linux::file::HeldFile;
use std::cell::Cell;
use std::os::fd::{AsFd, AsRawFd};
use std::panic::AssertUnwindSafe;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const FIXTURE: &str = include_str!("../fixtures/attach-v1/retirement.json");

fn sites(n: usize) -> Vec<Site> {
    (0..n)
        .map(|i| Site {
            offset: 0x1000 + i as u64 * 0x10,
            cookie: 500 + i as u64,
        })
        .collect()
}

fn generous_limits() -> Limits {
    Limits {
        input_bytes: usize::MAX,
        retained_bytes: usize::MAX,
        work_steps: u64::MAX,
        sites: usize::MAX,
        live_links: usize::MAX,
        pending_retirements: usize::MAX,
    }
}

fn generous_capacity() -> RetirementCapacity {
    RetirementCapacity {
        max_groups: usize::MAX,
        max_links: usize::MAX,
        max_retained_bytes: usize::MAX,
    }
}

fn plan_for(n: usize) -> AttachPlan {
    AttachPlan::checked(sites(n), AttachMode::EntryMulti, &generous_limits()).unwrap()
}

struct FixedPolicy(ErrorAction);

impl ErrorPolicy for FixedPolicy {
    fn classify(&mut self, _error: &OperationError, _batch_len: usize) -> ErrorAction {
        self.0
    }
}

struct CountingPolicy {
    action: ErrorAction,
    calls: usize,
}

impl ErrorPolicy for CountingPolicy {
    fn classify(&mut self, _error: &OperationError, _batch_len: usize) -> ErrorAction {
        self.calls += 1;
        self.action
    }
}

fn active_owner<P: ErrorPolicy>(
    pool: &mut RetirementPool<ScriptBackend>,
    backend: ScriptBackend,
    n: usize,
    policy: &mut P,
) -> scopebase_bpf::attach::AttachmentSet<ScriptBackend> {
    let plan = plan_for(n);
    match execute_plan(pool, backend, (), plan, policy, &generous_limits()) {
        AttachOutcome::Active { owner, .. } => owner,
        other => panic!("expected Active, found {other:?}"),
    }
}

fn summary_of(outcome: &AttachOutcome<ScriptBackend>) -> &AttachSummary {
    match outcome {
        AttachOutcome::Active { summary, .. }
        | AttachOutcome::RolledBack { summary, .. }
        | AttachOutcome::Unresolved { summary, .. } => summary,
    }
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Temp pathname that removes its file on drop, so retirement tests
/// never leak temp files even on assertion failure (S187).
struct TempPath(std::path::PathBuf);

impl std::ops::Deref for TempPath {
    type Target = std::path::PathBuf;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<std::path::Path> for TempPath {
    fn as_ref(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Create `path` with `contents`, refusing when the target already
/// exists (S187): `create_new` fails `AlreadyExists` on a pre-created
/// file or planted symlink instead of truncating through it.
fn create_temp_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(contents)
}

/// Create a temp regular file and adopt it as a `HeldFile` (LX02
/// `from_file`; no procfs, no pathname retention by the pool).
fn temp_held(contents: &[u8]) -> (TempPath, HeldFile) {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "bp05-held-{}-{}.bin",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    create_temp_file(&path, contents).unwrap();
    let held = HeldFile::from_file(std::fs::File::open(&path).unwrap()).unwrap();
    (TempPath(path), held)
}

/// Scripted backend with a real `Arc<HeldFile>` authority: delegates
/// scripting to an inner unit backend while borrowing (never reopening)
/// the held FD for every attach.
struct HeldBackend {
    inner: ScriptBackend,
    fd_seen: Rc<Cell<i32>>,
}

// SAFETY: test fake; delegates to the contract-honoring script core and
// only borrows the held FD through `AsFd`.
unsafe impl scopebase_bpf::attach::AttachBackend for HeldBackend {
    type Authority = Arc<HeldFile>;
    type Link = fake_backend::FakeLink;
    type Uncertain = fake_backend::FakeUncertain;

    fn custody_charge(
        &self,
        _authority: &Self::Authority,
        sites: &[Site],
    ) -> Result<scopebase_bpf::attach::CustodyCharge, OperationError> {
        self.inner.custody_charge(&(), sites)
    }

    fn attach(
        &mut self,
        authority: &Self::Authority,
        sites: &[Site],
        mode: AttachMode,
    ) -> scopebase_bpf::attach::NativeAttach<Self::Link, Self::Uncertain> {
        // Borrowed AsFd use only: record the live FD number, never a path.
        self.fd_seen.set(authority.as_fd().as_raw_fd());
        assert!(
            authority.stat().is_ok(),
            "held authority stays stat-able during attach"
        );
        self.inner.attach(&(), sites, mode)
    }

    fn retire(&mut self, link: &mut Self::Link) -> scopebase_bpf::attach::NativeRetire {
        self.inner.retire(link)
    }

    fn retire_uncertain(
        &mut self,
        custody: &mut Self::Uncertain,
    ) -> scopebase_bpf::attach::NativeRetire {
        self.inner.retire_uncertain(custody)
    }
}

#[test]
fn capacity_reserved_before_first_link() {
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    let backend = ScriptBackend::new(sites(2));
    let probe = Rc::clone(&backend.probe);
    let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
    let outcome = execute_plan(
        &mut pool,
        backend,
        (),
        plan_for(2),
        &mut policy,
        &generous_limits(),
    );
    assert!(matches!(outcome, AttachOutcome::Active { .. }));
    assert_eq!(probe.charge_calls.get(), 1, "one audited charge");
    assert!(
        probe.charge_precedes_first_attach(),
        "reservation precedes the first native call"
    );
    assert_eq!(probe.attach_order(), vec!["0-2".to_string()]);
    // Pool echoes the fake's audited charge exactly (2 sites: 3 slots,
    // 32 bytes); one group live.
    assert_eq!(
        pool.usage(),
        PoolUsage {
            groups: 1,
            links: 1,
            retained_bytes: 32
        }
    );
}

#[test]
fn over_capacity_refuses_with_zero_native_calls() {
    // Charge for n=2 is 3 slots / 32 bytes; cap links below that.
    let capacity = RetirementCapacity {
        max_groups: 8,
        max_links: 2,
        max_retained_bytes: usize::MAX,
    };
    let mut pool = RetirementPool::new(capacity).unwrap();
    let backend = ScriptBackend::new(sites(2));
    let probe = Rc::clone(&backend.probe);
    let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
    let outcome = execute_plan(
        &mut pool,
        backend,
        (),
        plan_for(2),
        &mut policy,
        &generous_limits(),
    );
    match outcome {
        AttachOutcome::RolledBack { summary, cause } => {
            assert_eq!(cause.kind(), ErrorKind::LimitExceeded);
            assert_eq!(summary.attempts, 0, "refused before any attempt");
            assert_eq!(summary.attached_sites, 0);
            assert!(summary.refused_sites.is_empty());
        }
        other => panic!("expected RolledBack refusal, found {other:?}"),
    }
    assert_eq!(
        probe.attach_calls.get(),
        0,
        "no native call after capacity refusal"
    );
    assert_eq!(
        pool.usage(),
        PoolUsage {
            groups: 0,
            links: 0,
            retained_bytes: 0
        }
    );
}

#[test]
fn zero_limits_refuse_before_effects() {
    let base = generous_limits();
    let cases: Vec<(&str, Limits)> = vec![
        (
            "input",
            Limits {
                input_bytes: 0,
                ..base
            },
        ),
        (
            "retained",
            Limits {
                retained_bytes: 0,
                ..base
            },
        ),
        (
            "work",
            Limits {
                work_steps: 0,
                ..base
            },
        ),
        ("sites", Limits { sites: 0, ..base }),
        (
            "links",
            Limits {
                live_links: 0,
                ..base
            },
        ),
        (
            "pending",
            Limits {
                pending_retirements: 0,
                ..base
            },
        ),
    ];
    for (name, limits) in cases {
        let mut pool = RetirementPool::new(generous_capacity()).unwrap();
        let backend = ScriptBackend::new(sites(2));
        let probe = Rc::clone(&backend.probe);
        let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
        let outcome = execute_plan(&mut pool, backend, (), plan_for(2), &mut policy, &limits);
        match outcome {
            AttachOutcome::RolledBack { summary, cause } => {
                assert_eq!(cause.kind(), ErrorKind::LimitExceeded, "case {name}");
                assert_eq!(summary.attempts, 0, "case {name}");
            }
            other => panic!("case {name}: expected refusal, found {other:?}"),
        }
        assert_eq!(probe.attach_calls.get(), 0, "case {name}: no effects");
        // Zero site cap refuses at plan construction too.
        if name == "sites" {
            assert!(AttachPlan::checked(sites(2), AttachMode::EntryMulti, &limits).is_err());
        }
    }
}

#[test]
fn worst_case_limits_are_exact() {
    // n=4 reserves 2n-1 = 7 attempts, 4 live links, 4 pending slots,
    // 64 input bytes; one less refuses, exact admits.
    let base = generous_limits();
    let exact = Limits {
        input_bytes: 64,
        work_steps: 7,
        live_links: 4,
        pending_retirements: 4,
        ..base
    };
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
    let outcome = execute_plan(
        &mut pool,
        ScriptBackend::new(sites(4)),
        (),
        plan_for(4),
        &mut policy,
        &exact,
    );
    assert!(
        matches!(outcome, AttachOutcome::Active { .. }),
        "exact worst-case limits admit"
    );
    for (name, limits) in [
        (
            "input",
            Limits {
                input_bytes: 63,
                ..exact
            },
        ),
        (
            "work",
            Limits {
                work_steps: 6,
                ..exact
            },
        ),
        (
            "links",
            Limits {
                live_links: 3,
                ..exact
            },
        ),
        (
            "pending",
            Limits {
                pending_retirements: 3,
                ..exact
            },
        ),
    ] {
        let mut pool = RetirementPool::new(generous_capacity()).unwrap();
        let backend = ScriptBackend::new(sites(4));
        let probe = Rc::clone(&backend.probe);
        let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
        let outcome = execute_plan(&mut pool, backend, (), plan_for(4), &mut policy, &limits);
        assert!(
            matches!(
                outcome,
                AttachOutcome::RolledBack { ref cause, .. }
                if cause.kind() == ErrorKind::LimitExceeded
            ),
            "case {name}: one-under refuses"
        );
        assert_eq!(probe.attach_calls.get(), 0, "case {name}: no effects");
    }
}

#[test]
fn pending_and_failed_keep_all_parents() {
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    let mut backend = ScriptBackend::new(sites(1));
    let probe = Rc::clone(&backend.probe);
    // Link 0: Pending, then Failed(Backend), then Retired.
    backend.retire_script.link_steps(
        0,
        vec![
            RetireStep::Pending,
            RetireStep::Failed(ErrorKind::Backend),
            RetireStep::Retired,
        ],
    );
    let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
    let owner = active_owner(&mut pool, backend, 1, &mut policy);
    let usage_before = pool.usage();
    assert_eq!(usage_before.links, 1);

    // First retire: Pending keeps every parent (link, authority, charge).
    let unresolved = match owner.retire(&mut pool) {
        Retirement::Pending(custody) => custody,
        other => panic!("expected Pending, found {other:?}"),
    };
    assert_eq!(pool.usage(), usage_before, "Pending releases no credit");
    assert_eq!(probe.link_drops.get(), 0, "link value not dropped");
    assert_eq!(unresolved.remaining_links(&pool).unwrap(), 1);

    // Second retire: Failed carries the typed error plus custody.
    let unresolved = match unresolved.retry_retire(&mut pool) {
        Retirement::Failed { custody, error } => {
            assert_eq!(error.kind(), ErrorKind::Backend);
            assert_eq!(error.stage(), Stage::Retire);
            custody
        }
        other => panic!("expected Failed, found {other:?}"),
    };
    assert_eq!(pool.usage(), usage_before, "Failed releases no credit");
    assert_eq!(probe.link_drops.get(), 0, "failed link value retained");
    assert_eq!(unresolved.remaining_links(&pool).unwrap(), 1);

    // Retry creates no links and finally confirms retirement.
    let attaches = probe.attach_calls.get();
    match unresolved.retry_retire(&mut pool) {
        Retirement::Retired => {}
        other => panic!("expected Retired, found {other:?}"),
    }
    assert_eq!(probe.attach_calls.get(), attaches, "no links during retry");
    assert_eq!(probe.link_drops.get(), 1, "value dropped after proof");
    assert_eq!(
        pool.usage(),
        PoolUsage {
            groups: 0,
            links: 0,
            retained_bytes: 0
        },
        "confirmed retirement releases the full charge"
    );
}

#[test]
fn foreign_ticket_refuses_and_returns_custody_unchanged() {
    let mut home = RetirementPool::new(generous_capacity()).unwrap();
    let mut foreign = RetirementPool::new(generous_capacity()).unwrap();
    let backend = ScriptBackend::new(sites(1));
    let probe = Rc::clone(&backend.probe);
    let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
    let owner = active_owner(&mut home, backend, 1, &mut policy);

    // Wrong pool: typed refusal, original ticket preserved as custody,
    // zero native calls against either pool.
    let custody = match owner.retire(&mut foreign) {
        Retirement::Failed { custody, error } => {
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
            assert_eq!(error.stage(), Stage::Retire);
            custody
        }
        other => panic!("expected foreign-pool Failed, found {other:?}"),
    };
    assert_eq!(probe.retire_calls.get(), 0, "no native calls");
    assert_eq!(
        home.usage().links,
        1,
        "home custody intact after foreign refusal"
    );
    assert_eq!(
        foreign.usage(),
        PoolUsage {
            groups: 0,
            links: 0,
            retained_bytes: 0
        },
        "foreign pool untouched"
    );

    // The returned custody permits exactly one home retry, then retires.
    assert_eq!(custody.remaining_links(&home).unwrap(), 1);
    assert!(custody.remaining_links(&foreign).is_err());
    match custody.retry_retire(&mut home) {
        Retirement::Retired => {}
        other => panic!("expected home Retired, found {other:?}"),
    }
    assert_eq!(probe.retire_order(), vec![0]);
}

#[test]
fn drop_unresolved_keeps_authority() {
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    let backend = ScriptBackend::new(sites(1));
    let probe = Rc::clone(&backend.probe);
    let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
    let owner = active_owner(&mut pool, backend, 1, &mut policy);
    let usage_before = pool.usage();

    // Dropping the ticket marks the entry orphaned: no native calls,
    // no credit, no link-value drops.
    drop(owner);
    assert_eq!(pool.usage(), usage_before, "drop releases nothing");
    assert_eq!(probe.retire_calls.get(), 0, "drop calls no native code");
    assert_eq!(probe.link_drops.get(), 0, "drop destroys no link value");

    // The orphaned entry is recoverable through reconcile, not lost.
    let report = pool.reconcile(RetirementBudget {
        max_native_calls: 8,
    });
    assert_eq!(report.retired_groups, 1);
    assert_eq!(report.pending_groups, 0);
    assert_eq!(report.failed_groups, 0);
    assert_eq!(probe.retire_order(), vec![0]);
    assert_eq!(
        pool.usage(),
        PoolUsage {
            groups: 0,
            links: 0,
            retained_bytes: 0
        }
    );
}

#[test]
fn reconcile_skips_active_held_tickets() {
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    let backend = ScriptBackend::new(sites(1));
    let probe = Rc::clone(&backend.probe);
    let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
    let owner = active_owner(&mut pool, backend, 1, &mut policy);

    // Active held tickets are excluded from orphan reconciliation.
    let report = pool.reconcile(RetirementBudget {
        max_native_calls: 8,
    });
    assert_eq!(report.retired_groups, 0);
    assert_eq!(report.pending_groups, 0, "active is not pending");
    assert_eq!(report.failed_groups, 0);
    assert_eq!(probe.retire_calls.get(), 0, "held ticket undisturbed");
    assert_eq!(pool.usage().links, 1);

    // The held ticket still retires normally afterwards.
    match owner.retire(&mut pool) {
        Retirement::Retired => {}
        other => panic!("expected Retired, found {other:?}"),
    }
}

#[test]
fn reconcile_honors_call_budget() {
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    // One pool, two plans, both tickets dropped: two orphaned entries.
    for _ in 0..2 {
        let backend = ScriptBackend::new(sites(1));
        let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
        let owner = active_owner(&mut pool, backend, 1, &mut policy);
        drop(owner);
    }
    assert_eq!(pool.usage().groups, 2);

    // Zero budget: nothing visited, everything still outstanding.
    let report = pool.reconcile(RetirementBudget {
        max_native_calls: 0,
    });
    assert_eq!(report.retired_groups, 0);
    assert_eq!(report.pending_groups, 2);
    assert_eq!(pool.usage().groups, 2);

    // Budget of one: exactly one group retired.
    let report = pool.reconcile(RetirementBudget {
        max_native_calls: 1,
    });
    assert_eq!(report.retired_groups, 1);
    assert_eq!(report.pending_groups, 1);
    assert_eq!(pool.usage().groups, 1);

    // Remaining budget clears the pool.
    let report = pool.reconcile(RetirementBudget {
        max_native_calls: 8,
    });
    assert_eq!(report.retired_groups, 1);
    assert_eq!(report.pending_groups, 0);
    assert_eq!(
        pool.usage(),
        PoolUsage {
            groups: 0,
            links: 0,
            retained_bytes: 0
        }
    );
}

#[test]
fn reconcile_reports_failed_groups_and_releases_exact_charge() {
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    let mut backend = ScriptBackend::new(sites(2));
    backend.script_node((0, 2), ScriptOutcome::NoEffect(ErrorKind::InvalidInput));
    backend
        .retire_script
        .link_steps(0, vec![RetireStep::Failed(ErrorKind::Backend)]);
    let mut policy = FixedPolicy(ErrorAction::IsolateSites);
    // Root splits; two singleton links attach (ids 0, 1).
    let owner = active_owner(&mut pool, backend, 2, &mut policy);
    drop(owner); // orphan with two active links
    let charged = pool.usage();
    assert_eq!(charged.groups, 1);
    assert_eq!(charged.links, 2);

    // Link 1 retires; link 0 fails. Reverse order: 1 before 0.
    let report = pool.reconcile(RetirementBudget {
        max_native_calls: 8,
    });
    assert_eq!(report.retired_groups, 0, "group not fully retired");
    assert_eq!(report.failed_groups, 1);
    assert_eq!(report.pending_groups, 0);
    // Partial proof releases no credit: the group and its full charge
    // stay, while the outstanding-object count drops by the one proof.
    assert_eq!(pool.usage().groups, charged.groups);
    assert_eq!(pool.usage().retained_bytes, charged.retained_bytes);
    assert_eq!(pool.usage().links, 1);

    // Retry the failure to confirmed: the exact full charge releases.
    let report = pool.reconcile(RetirementBudget {
        max_native_calls: 8,
    });
    assert_eq!(report.retired_groups, 1);
    assert_eq!(report.failed_groups, 0);
    assert_eq!(
        pool.usage(),
        PoolUsage {
            groups: 0,
            links: 0,
            retained_bytes: 0
        }
    );
}

#[test]
fn close_returns_unresolved_pool() {
    // Empty pool closes cleanly.
    let pool = RetirementPool::<ScriptBackend>::new(generous_capacity()).unwrap();
    assert!(matches!(pool.close(), PoolClose::Closed));

    // Live entries keep the pool recoverable through close.
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
    let owner = active_owner(&mut pool, ScriptBackend::new(sites(1)), 1, &mut policy);
    let mut pool = match pool.close() {
        PoolClose::Unresolved(pool) => pool,
        PoolClose::Closed => panic!("live pool must not report Closed"),
    };
    assert_eq!(pool.usage().links, 1);
    match owner.retire(&mut pool) {
        Retirement::Retired => {}
        other => panic!("expected Retired, found {other:?}"),
    }
    assert!(matches!(pool.close(), PoolClose::Closed));
}

#[test]
fn dropping_live_pool_leaks_without_silent_detach() {
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    let backend = ScriptBackend::new(sites(1));
    let probe = Rc::clone(&backend.probe);
    let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
    let owner = active_owner(&mut pool, backend, 1, &mut policy);
    drop(owner); // orphan; custody lives in the pool alone
    drop(pool); // last-resort Drop: retain/leak, never claim a clean close
    assert_eq!(probe.retire_calls.get(), 0, "Drop calls no native code");
    assert_eq!(
        probe.link_drops.get(),
        0,
        "leaked link destructors never run: no silent detach"
    );
}

struct PanicPolicy {
    calls: usize,
    panic_at: usize,
}

impl ErrorPolicy for PanicPolicy {
    fn classify(&mut self, _error: &OperationError, _batch_len: usize) -> ErrorAction {
        self.calls += 1;
        if self.calls == self.panic_at {
            panic!("scripted policy panic");
        }
        ErrorAction::IsolateSites
    }
}

#[test]
fn transfer_panic_is_owned() {
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    // Root fails (classify #1, isolate), left leaf links, right fails
    // (classify #2 panics). The linked leaf must stay pool-owned.
    let mut backend = ScriptBackend::new(sites(4));
    backend.script_node((0, 4), ScriptOutcome::NoEffect(ErrorKind::InvalidInput));
    backend.script_node((2, 4), ScriptOutcome::NoEffect(ErrorKind::InvalidInput));
    let probe = Rc::clone(&backend.probe);
    let mut policy = PanicPolicy {
        calls: 0,
        panic_at: 2,
    };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        execute_plan(
            &mut pool,
            backend,
            (),
            plan_for(4),
            &mut policy,
            &generous_limits(),
        )
    }));
    assert!(result.is_err(), "policy panic propagates");
    assert_eq!(policy.calls, 2);
    assert_eq!(probe.attach_order(), vec!["0-4", "0-2", "2-4"]);
    // The acquisition guard preserved the link, backend and charge.
    assert_eq!(
        pool.usage(),
        PoolUsage {
            groups: 1,
            links: 1,
            retained_bytes: 64
        },
        "panicking transfer stays pool-owned"
    );
    // No ticket was issued, so the entry is orphaned-but-recoverable.
    let report = pool.reconcile(RetirementBudget {
        max_native_calls: 8,
    });
    assert_eq!(report.retired_groups, 1);
    assert_eq!(probe.retire_order(), vec![0]);
    assert_eq!(
        pool.usage(),
        PoolUsage {
            groups: 0,
            links: 0,
            retained_bytes: 0
        }
    );
}

#[test]
fn backend_attach_panic_keeps_prior_custody() {
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    let mut backend = ScriptBackend::new(sites(4));
    backend.script_node((0, 4), ScriptOutcome::NoEffect(ErrorKind::InvalidInput));
    backend.panic_at_attach = Some(1); // panic on the second attach call
    let probe = Rc::clone(&backend.probe);
    let mut policy = FixedPolicy(ErrorAction::IsolateSites);
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        execute_plan(
            &mut pool,
            backend,
            (),
            plan_for(4),
            &mut policy,
            &generous_limits(),
        )
    }));
    assert!(result.is_err(), "backend panic propagates");
    assert_eq!(probe.attach_calls.get(), 2);
    // The reserved entry (backend, authority, charge) survives the panic.
    assert_eq!(pool.usage().groups, 1);
    let report = pool.reconcile(RetirementBudget {
        max_native_calls: 8,
    });
    assert_eq!(report.retired_groups, 1, "effect-free entry reaps");
    assert_eq!(
        pool.usage(),
        PoolUsage {
            groups: 0,
            links: 0,
            retained_bytes: 0
        }
    );
}

#[test]
fn uncertain_registers_before_policy_and_never_splits() {
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    let mut backend = ScriptBackend::new(sites(4));
    backend.script_node((0, 4), ScriptOutcome::Uncertain);
    let probe = Rc::clone(&backend.probe);
    let mut policy = CountingPolicy {
        action: ErrorAction::IsolateSites,
        calls: 0,
    };
    let outcome = execute_plan(
        &mut pool,
        backend,
        (),
        plan_for(4),
        &mut policy,
        &generous_limits(),
    );
    // Uncertain is terminal: one attempt, no split, no policy vote.
    assert_eq!(probe.attach_calls.get(), 1);
    assert_eq!(policy.calls, 0, "uncertain custody is not classified");
    let (custody, summary) = match outcome {
        AttachOutcome::Unresolved {
            custody,
            summary,
            cause,
        } => {
            assert_eq!(cause.kind(), ErrorKind::Backend);
            assert_eq!(cause.stage(), Stage::Attach);
            (custody, summary)
        }
        other => panic!("expected Unresolved, found {other:?}"),
    };
    assert_eq!(summary.attempts, 1);
    assert_eq!(summary.attached_sites, 0);
    assert!(summary.refused_sites.is_empty());
    assert_eq!(custody.remaining_links(&pool).unwrap(), 1);
    assert_eq!(
        pool.usage(),
        PoolUsage {
            groups: 1,
            links: 1,
            retained_bytes: 64
        },
        "uncertain custody fully charged"
    );
    // Recovery reconciles the uncertain acquisition through its backend.
    match custody.retry_retire(&mut pool) {
        Retirement::Retired => {}
        other => panic!("expected Retired, found {other:?}"),
    }
    assert_eq!(probe.uncertain_retire_order(), vec![0]);
    assert_eq!(probe.uncertain_drops.get(), 1);
}

#[test]
fn uncertain_after_success_rolls_back_links_and_retains_both() {
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    let mut backend = ScriptBackend::new(sites(4));
    backend.script_node((0, 4), ScriptOutcome::NoEffect(ErrorKind::InvalidInput));
    backend.script_node((2, 4), ScriptOutcome::Uncertain);
    let probe = Rc::clone(&backend.probe);
    let mut policy = FixedPolicy(ErrorAction::IsolateSites);
    let outcome = execute_plan(
        &mut pool,
        backend,
        (),
        plan_for(4),
        &mut policy,
        &generous_limits(),
    );
    // Left leaf linked, then the right node went uncertain: the link
    // rolls back (default Retired) while the uncertain custody stays.
    let custody = match outcome {
        AttachOutcome::Unresolved {
            custody, summary, ..
        } => {
            assert_eq!(summary.attempts, 3);
            assert_eq!(summary.attached_sites, 2);
            custody
        }
        other => panic!("expected Unresolved, found {other:?}"),
    };
    assert_eq!(probe.attach_order(), vec!["0-4", "0-2", "2-4"]);
    assert_eq!(probe.retire_order(), vec![0], "rollback retired the link");
    assert_eq!(custody.remaining_links(&pool).unwrap(), 1);
    assert_eq!(pool.usage().links, 1, "only uncertain custody remains");
    match custody.retry_retire(&mut pool) {
        Retirement::Retired => {}
        other => panic!("expected Retired, found {other:?}"),
    }
    assert_eq!(
        pool.usage(),
        PoolUsage {
            groups: 0,
            links: 0,
            retained_bytes: 0
        }
    );
}

#[test]
fn rollback_retires_in_reverse_attach_order() {
    // Split every multi node so seven singleton leaves attach before a
    // terminal denial on the last leaf rolls them back in reverse.
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    let mut backend = ScriptBackend::new(sites(8));
    // Fail every multi node isolatably; fail singleton 7 terminally so
    // leaves 0..7 attach first (visit order is left-first).
    for start in 0..8 {
        for end in start + 2..=8 {
            backend.script_node(
                (start, end),
                ScriptOutcome::NoEffect(ErrorKind::InvalidInput),
            );
        }
    }
    backend.script_node((7, 8), ScriptOutcome::NoEffect(ErrorKind::Denied));
    let probe = Rc::clone(&backend.probe);
    let mut policy = FixedPolicy(ErrorAction::IsolateSites);
    let outcome = execute_plan(
        &mut pool,
        backend,
        (),
        plan_for(8),
        &mut policy,
        &generous_limits(),
    );
    match outcome {
        AttachOutcome::RolledBack { summary, cause } => {
            assert_eq!(cause.kind(), ErrorKind::Denied);
            assert_eq!(summary.attempts, 15, "full 2n-1 walk");
            assert_eq!(summary.attached_sites, 7);
            assert_eq!(summary.refused_sites, vec![sites(8)[7]]);
        }
        other => panic!("expected RolledBack, found {other:?}"),
    }
    // Retirement ordering proof: link ids retire strictly reversed.
    assert_eq!(probe.retire_order(), vec![6, 5, 4, 3, 2, 1, 0]);
    assert_eq!(
        pool.usage(),
        PoolUsage {
            groups: 0,
            links: 0,
            retained_bytes: 0
        },
        "rollback released everything it proved"
    );
}

#[test]
fn repeated_unresolved_drop_saturates_same_pool() {
    // Capacity of two groups: two unresolved attaches fill it; dropped
    // tickets keep their charges, so a third refuses before any call.
    let capacity = RetirementCapacity {
        max_groups: 2,
        max_links: usize::MAX,
        max_retained_bytes: usize::MAX,
    };
    let mut pool = RetirementPool::new(capacity).unwrap();
    let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
    for _ in 0..2 {
        let mut backend = ScriptBackend::new(sites(1));
        backend.script_node((0, 1), ScriptOutcome::Uncertain);
        let outcome = execute_plan(
            &mut pool,
            backend,
            (),
            plan_for(1),
            &mut policy,
            &generous_limits(),
        );
        match outcome {
            AttachOutcome::Unresolved { custody, .. } => drop(custody),
            other => panic!("expected Unresolved, found {other:?}"),
        }
    }
    assert_eq!(pool.usage().groups, 2, "dropped tickets keep charges");

    // Third admission refuses despite fresh per-call Limits: no charge,
    // no attach, attempts stay zero.
    let backend = ScriptBackend::new(sites(1));
    let probe = Rc::clone(&backend.probe);
    let outcome = execute_plan(
        &mut pool,
        backend,
        (),
        plan_for(1),
        &mut policy,
        &generous_limits(),
    );
    match outcome {
        AttachOutcome::RolledBack { summary, cause } => {
            assert_eq!(cause.kind(), ErrorKind::LimitExceeded);
            assert_eq!(summary.attempts, 0);
        }
        other => panic!("expected saturated refusal, found {other:?}"),
    }
    assert_eq!(probe.charge_calls.get(), 0, "refused before charge");
    assert_eq!(probe.attach_calls.get(), 0, "refused before effects");

    // Pending/failed retries release no credit: script one entry Pending
    // then Failed, reconcile twice, usage stays saturated.
    let report = pool.reconcile(RetirementBudget {
        max_native_calls: 0,
    });
    assert_eq!(report.pending_groups, 2);

    // Reconcile exactly one entry to confirmed Retired: exactly one new
    // admission succeeds, and only one.
    let report = pool.reconcile(RetirementBudget {
        max_native_calls: 1,
    });
    assert_eq!(report.retired_groups, 1);
    assert_eq!(pool.usage().groups, 1);
    let mut backend = ScriptBackend::new(sites(1));
    backend.script_node((0, 1), ScriptOutcome::Uncertain);
    let outcome = execute_plan(
        &mut pool,
        backend,
        (),
        plan_for(1),
        &mut policy,
        &generous_limits(),
    );
    assert!(
        matches!(outcome, AttachOutcome::Unresolved { .. }),
        "exactly one admission succeeds after one release"
    );
    assert_eq!(pool.usage().groups, 2);
    let backend = ScriptBackend::new(sites(1));
    let probe = Rc::clone(&backend.probe);
    let outcome = execute_plan(
        &mut pool,
        backend,
        (),
        plan_for(1),
        &mut policy,
        &generous_limits(),
    );
    assert!(
        matches!(outcome, AttachOutcome::RolledBack { .. }),
        "pool saturated again after one admission"
    );
    assert_eq!(probe.attach_calls.get(), 0);
}

#[test]
fn aba_retains_original_fd_until_positive_retirement() {
    let (path, held) = temp_held(b"bp05-aba-original");
    let original = held.stat().unwrap().key();
    let authority = Arc::new(held);
    let weak = Arc::downgrade(&authority);

    let mut pool = RetirementPool::<HeldBackend>::new(generous_capacity()).unwrap();
    let mut inner = ScriptBackend::new(sites(1));
    inner.script_node((0, 1), ScriptOutcome::Uncertain);
    let probe = Rc::clone(&inner.probe);
    let fd_seen = Rc::new(Cell::new(-1));
    let backend = HeldBackend {
        inner,
        fd_seen: Rc::clone(&fd_seen),
    };
    let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
    let custody = match execute_plan(
        &mut pool,
        backend,
        authority,
        plan_for(1),
        &mut policy,
        &generous_limits(),
    ) {
        AttachOutcome::Unresolved { custody, .. } => custody,
        other => panic!("expected Unresolved, found {other:?}"),
    };
    assert!(fd_seen.get() >= 0, "attach borrowed the held FD");

    // A -> B -> A rename plus deletion: the held FD still names the
    // original inode; no historical pathname is consulted.
    let renamed = path.with_extension("bak");
    std::fs::rename(&path, &renamed).unwrap();
    std::fs::write(&path, b"bp05-aba-impostor").unwrap();
    let live = weak.upgrade().expect("authority retained while unresolved");
    assert_eq!(
        live.stat().unwrap().key(),
        original,
        "held FD is the original"
    );
    // The pathname now names a different inode than the held original.
    use std::os::unix::fs::MetadataExt;
    let current = std::fs::File::open(&path).unwrap().metadata().unwrap();
    assert!(
        current.dev() != original.device_raw() || current.ino() != original.inode(),
        "pathname now names a different file"
    );
    std::fs::remove_file(&renamed).unwrap();
    std::fs::remove_file(&*path).unwrap();
    assert_eq!(
        live.stat().unwrap().key(),
        original,
        "original survives all pathname deletion"
    );
    drop(live);

    // An unrelated close cannot satisfy custody: drop a decoy file and
    // confirm the pool still holds the original authority.
    let (decoy_path, decoy) = temp_held(b"decoy");
    drop(decoy);
    std::fs::remove_file(&*decoy_path).unwrap();
    assert_eq!(custody.remaining_links(&pool).unwrap(), 1);
    assert!(weak.upgrade().is_some(), "original still retained");

    // Positive retirement releases the original file.
    match custody.retry_retire(&mut pool) {
        Retirement::Retired => {}
        other => panic!("expected Retired, found {other:?}"),
    }
    assert_eq!(probe.uncertain_retire_order(), vec![0]);
    assert!(
        weak.upgrade().is_none(),
        "original file released after positive retirement"
    );
    assert_eq!(
        pool.usage(),
        PoolUsage {
            groups: 0,
            links: 0,
            retained_bytes: 0
        }
    );
}

#[test]
fn adopt_refusal_returns_original_file() {
    // LX02 adoption gate: a directory is not adoptable, and the refusal
    // returns the submitted File (including its FD) untouched.
    let dir = std::env::temp_dir();
    let file = std::fs::File::open(&dir).unwrap();
    let raw = file.as_raw_fd();
    match HeldFile::from_file(file) {
        Ok(_) => panic!("directory must not adopt as a held file"),
        Err(refusal) => {
            assert_eq!(refusal.file.as_raw_fd(), raw, "original FD returned");
        }
    }
}

#[test]
fn failed_cleanup_is_typed_error_never_inferred_success() {
    // Timeout-shaped Pending is not success: repeated Pending keeps the
    // link live with zero value drops, and the error stays typed.
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    let mut backend = ScriptBackend::new(sites(1));
    backend.retire_script.link_steps(
        0,
        vec![
            RetireStep::Pending,
            RetireStep::Pending,
            RetireStep::Failed(ErrorKind::Backend),
        ],
    );
    let probe = Rc::clone(&backend.probe);
    let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
    let owner = active_owner(&mut pool, backend, 1, &mut policy);

    // Mutant control: detach-success-on-timeout would report Retired
    // here; the oracle requires Pending with custody intact.
    let custody = match owner.retire(&mut pool) {
        Retirement::Pending(custody) => custody,
        other => panic!("timeout-shaped Pending is not Retired: {other:?}"),
    };
    assert_eq!(probe.link_drops.get(), 0);
    let custody = match custody.retry_retire(&mut pool) {
        Retirement::Pending(custody) => custody,
        other => panic!("second Pending is still not Retired: {other:?}"),
    };
    assert_eq!(probe.link_drops.get(), 0);
    assert_eq!(pool.usage().links, 1);
    let custody = match custody.retry_retire(&mut pool) {
        Retirement::Failed { custody, error } => {
            assert_eq!(error.kind(), ErrorKind::Backend);
            assert_eq!(error.stage(), Stage::Retire);
            assert!(error.raw_os_error().is_none(), "no errno invented");
            custody
        }
        other => panic!("expected typed Failed, found {other:?}"),
    };
    // Failure keeps custody for a later proven retirement.
    assert_eq!(custody.remaining_links(&pool).unwrap(), 1);
    match custody.retry_retire(&mut pool) {
        Retirement::Retired => {}
        other => panic!("expected eventual Retired, found {other:?}"),
    }
    assert_eq!(probe.link_drops.get(), 1);
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn pure_values_are_send_sync() {
    assert_send_sync::<PoolUsage>();
    assert_send_sync::<RetirementCapacity>();
    assert_send_sync::<RetirementBudget>();
    assert_send_sync::<PoolReconcile>();
    assert_send_sync::<AttachSummary>();
}

#[test]
fn retirement_json_fixture_scenarios() {
    let root = json_mini::parse(FIXTURE).expect("fixture parses");
    assert_eq!(root.get("version").unwrap().as_u64().unwrap(), 1);
    let scenarios = root.get("scenarios").unwrap().as_arr().unwrap();
    assert_eq!(scenarios.len(), 3);
    for scenario in scenarios {
        drive_fixture_scenario(scenario);
    }
}

fn fixture_outcome(text: &str) -> ScriptOutcome {
    match text {
        "attached" => ScriptOutcome::Attached,
        "noeffect-invalid" => ScriptOutcome::NoEffect(ErrorKind::InvalidInput),
        "noeffect-denied" => ScriptOutcome::NoEffect(ErrorKind::Denied),
        "uncertain" => ScriptOutcome::Uncertain,
        other => panic!("unknown fixture outcome {other:?}"),
    }
}

fn drive_fixture_scenario(scenario: &json_mini::Json) {
    let name = scenario.get("name").unwrap().as_str().unwrap();
    let n = scenario.get("sites").unwrap().as_usize().unwrap();
    let policy_action = match scenario.get("policy").unwrap().as_str().unwrap() {
        "isolate" => ErrorAction::IsolateSites,
        "abort" => ErrorAction::AbortAndRollback,
        other => panic!("scenario {name}: unknown policy {other:?}"),
    };
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    let mut backend = ScriptBackend::new(sites(n));
    for step in scenario.get("script").unwrap().as_arr().unwrap() {
        let node = step.get("node").unwrap().as_arr().unwrap();
        assert_eq!(node.len(), 2, "scenario {name}: node is a pair");
        let range = (node[0].as_usize().unwrap(), node[1].as_usize().unwrap());
        backend.script_node(
            range,
            fixture_outcome(step.get("outcome").unwrap().as_str().unwrap()),
        );
    }
    backend.set_default(fixture_outcome(
        scenario.get("default").unwrap().as_str().unwrap(),
    ));
    let probe = Rc::clone(&backend.probe);
    let mut policy = FixedPolicy(policy_action);
    let outcome = execute_plan(
        &mut pool,
        backend,
        (),
        plan_for(n),
        &mut policy,
        &generous_limits(),
    );
    let expected = scenario.get("expected").unwrap();
    let summary = summary_of(&outcome);
    assert_eq!(
        summary.attempts,
        expected.get("attempts").unwrap().as_usize().unwrap(),
        "scenario {name}: attempts"
    );
    assert_eq!(
        summary.attached_sites,
        expected.get("attached_sites").unwrap().as_usize().unwrap(),
        "scenario {name}: attached sites"
    );
    let refused: Vec<usize> = expected
        .get("refused")
        .unwrap()
        .as_arr()
        .unwrap()
        .iter()
        .map(|index| index.as_usize().unwrap())
        .collect();
    let expected_sites: Vec<Site> = refused.iter().map(|index| sites(n)[*index]).collect();
    assert_eq!(
        summary.refused_sites, expected_sites,
        "scenario {name}: refused"
    );

    let usage_after = expected.get("usage_after").unwrap();
    let expected_usage = PoolUsage {
        groups: usage_after.get("groups").unwrap().as_usize().unwrap(),
        links: usage_after.get("links").unwrap().as_usize().unwrap(),
        retained_bytes: usage_after.get("bytes").unwrap().as_usize().unwrap(),
    };

    match expected.get("outcome").unwrap().as_str().unwrap() {
        "rolled-back" => {
            assert!(
                matches!(outcome, AttachOutcome::RolledBack { .. }),
                "scenario {name}: rolled back"
            );
            let retired: Vec<u64> = expected
                .get("retired_seqs")
                .unwrap()
                .as_arr()
                .unwrap()
                .iter()
                .map(|seq| seq.as_u64().unwrap())
                .collect();
            assert_eq!(
                probe.retire_order(),
                retired,
                "scenario {name}: rollback order"
            );
            assert_eq!(pool.usage(), expected_usage, "scenario {name}: usage");
        }
        "unresolved" => {
            let custody = match outcome {
                AttachOutcome::Unresolved { custody, .. } => custody,
                other => panic!("scenario {name}: expected Unresolved, found {other:?}"),
            };
            assert_eq!(pool.usage(), expected_usage, "scenario {name}: usage");
            // Fixture pins the retained charge; clean up by retiring.
            match custody.retry_retire(&mut pool) {
                Retirement::Retired => {}
                other => panic!("scenario {name}: cleanup Retired, found {other:?}"),
            }
        }
        "active" => {
            let owner = match outcome {
                AttachOutcome::Active { owner, .. } => owner,
                other => panic!("scenario {name}: expected Active, found {other:?}"),
            };
            match owner.retire(&mut pool) {
                Retirement::Retired => {}
                other => panic!("scenario {name}: retire Retired, found {other:?}"),
            };
            let retired: Vec<u64> = expected
                .get("retired_seqs")
                .unwrap()
                .as_arr()
                .unwrap()
                .iter()
                .map(|seq| seq.as_u64().unwrap())
                .collect();
            assert_eq!(
                probe.retire_order(),
                retired,
                "scenario {name}: retire order"
            );
            assert_eq!(pool.usage(), expected_usage, "scenario {name}: usage");
        }
        other => panic!("scenario {name}: unknown expected outcome {other:?}"),
    }
}

/// Fork-without-exec reuse refuses before touching native owners.
///
/// The child path is allocation-free and lock-free (pid check, map
/// lookup, refcount bump, `_exit`); the parent reaps and then proves
/// the pool is intact by retiring normally.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64",
    target_endian = "little"
))]
#[test]
fn fork_child_native_owner_refuses_before_exec() {
    let mut pool = RetirementPool::new(generous_capacity()).unwrap();
    let backend = ScriptBackend::new(sites(1));
    let probe = Rc::clone(&backend.probe);
    let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
    let owner = active_owner(&mut pool, backend, 1, &mut policy);

    // SAFETY: the child performs only async-signal-safe work (pid
    // comparison, hash lookup, integer arithmetic) and `_exit`s; it
    // never returns into the test harness.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        let mut code = 0;
        // retire() must refuse with a typed Changed error and keep
        // custody for the parent; no native call may happen first.
        let retired = probe.retire_calls.get();
        match owner.retire(&mut pool) {
            Retirement::Failed { error, .. } if error.kind() == ErrorKind::Changed => {}
            _ => code = 1,
        }
        if probe.retire_calls.get() != retired {
            code = 2;
        }
        // reconcile() must report zero work without native calls.
        let report = pool.reconcile(RetirementBudget {
            max_native_calls: 8,
        });
        if report.retired_groups != 0 || report.pending_groups != 0 || report.failed_groups != 0 {
            code = 3;
        }
        if probe.retire_calls.get() != retired {
            code = 4;
        }
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    // SAFETY: `pid` is the live child above; `status` is a valid out-param.
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid, "reaped the refused child");
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child refusal checks passed, status={status}"
    );

    // Parent pool is intact: the ticket still retires normally.
    assert_eq!(probe.retire_calls.get(), 0, "child made no native calls");
    assert_eq!(pool.usage().links, 1);
    match owner.retire(&mut pool) {
        Retirement::Retired => {}
        other => panic!("expected parent Retired, found {other:?}"),
    }
}

#[test]
fn temp_create_refuses_precreated_target() {
    // S187: `create_new` — a pre-created file at the target (e.g. a
    // planted symlink) refuses instead of truncating through, and the
    // victim contents are unchanged.
    let path =
        std::env::temp_dir().join(format!("bp05-s187-retire-{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, b"victim").unwrap();
    let error = create_temp_file(&path, b"overwritten").expect_err("refuses");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&path).unwrap(), b"victim");
    std::fs::remove_file(&path).unwrap();
}
