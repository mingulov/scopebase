// SPDX-License-Identifier: Apache-2.0
//! BP04: neutral pure attachment planner and caller error policy.
//!
//! PORT/ADAPT: bisection discipline from p11scope
//! `.worktrees/v040-integration/crates/bpf-multi/src/lib.rs`
//! (`bisect_attach_counted`: bounded <= 2n-1 attempts, permission fail-fast,
//! halt on exhaustion/unsupported) and osslscope `osslscope/src/plan.rs`
//! (`bisect_attach`: salvage every non-permission failure by splitting).
//! The donors differ on terminal-vs-isolatable classification; this neutral
//! planner keeps that difference in the caller `ErrorPolicy`, with
//! library-terminal permission/resource failures no policy can split.
//! (Catalog anchor `src/plan.rs:675-707` is line-stale against the frozen
//! copy; the live bisection sources above were inspected instead.)
//!
//! These tests cover the pure production split primitive and a bounded
//! decision model without native effects. Effectful policy-panic and
//! uncertain-native tests belong to BP05 after its pool-backed executor
//! exists. Live attach cells are NOT_RUN (later owners).

use scopebase_bpf::attach::{
    adjudicate_split, is_terminal_error, AttachBackend, AttachMode, AttachPlan, CustodyCharge,
    ErrorAction, ErrorPolicy, NativeAttach, NativeRetire, Site,
};
use scopebase_bpf::{ErrorKind, Limits, OperationError, Stage};
use std::collections::HashSet;
use std::ops::Range;

#[path = "support/json_mini.rs"]
mod json_mini;

const FIXTURE: &str = include_str!("../fixtures/attach-v1/split-trees.json");

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

fn sites(n: usize) -> Vec<Site> {
    (0..n)
        .map(|i| Site {
            offset: 0x1000 + i as u64 * 0x10,
            cookie: 500 + i as u64,
        })
        .collect()
}

fn plan_for(n: usize) -> AttachPlan {
    AttachPlan::checked(sites(n), AttachMode::EntryMulti, &generous_limits()).unwrap()
}

fn error(kind: ErrorKind) -> OperationError {
    OperationError::new(kind, Stage::Attach, None, None)
}

fn error_errno(kind: ErrorKind, errno: i32) -> OperationError {
    OperationError::new(kind, Stage::Attach, Some(errno), None)
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

#[test]
fn checked_accepts_distinct_sites() {
    let plan = AttachPlan::checked(sites(3), AttachMode::EntryMulti, &generous_limits()).unwrap();
    assert_eq!(
        plan.sites(),
        &[
            Site {
                offset: 0x1000,
                cookie: 500
            },
            Site {
                offset: 0x1010,
                cookie: 501
            },
            Site {
                offset: 0x1020,
                cookie: 502
            },
        ],
        "offset-cookie pairs round-trip exactly"
    );
    assert_eq!(plan.mode(), AttachMode::EntryMulti);
}

#[test]
fn checked_refuses_empty() {
    let err = AttachPlan::checked(Vec::new(), AttachMode::EntryMulti, &generous_limits())
        .expect_err("n=0 plan must refuse");
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert_eq!(err.stage(), Stage::Attach);
}

#[test]
fn checked_refuses_duplicate_offset() {
    let err = AttachPlan::checked(
        vec![
            Site {
                offset: 1,
                cookie: 1,
            },
            Site {
                offset: 1,
                cookie: 2,
            },
        ],
        AttachMode::EntryMulti,
        &generous_limits(),
    )
    .expect_err("duplicate offset must refuse");
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert_eq!(err.stage(), Stage::Attach);
}

#[test]
fn checked_refuses_duplicate_cookie() {
    let err = AttachPlan::checked(
        vec![
            Site {
                offset: 1,
                cookie: 5,
            },
            Site {
                offset: 2,
                cookie: 5,
            },
        ],
        AttachMode::EntryMulti,
        &generous_limits(),
    )
    .expect_err("duplicate cookie must refuse");
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert_eq!(err.stage(), Stage::Attach);
}

#[test]
fn checked_refuses_duplicate_pair() {
    let err = AttachPlan::checked(
        vec![
            Site {
                offset: 1,
                cookie: 5,
            },
            Site {
                offset: 1,
                cookie: 5,
            },
        ],
        AttachMode::EntryMulti,
        &generous_limits(),
    )
    .expect_err("duplicate site must refuse");
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
}

#[test]
fn checked_refuses_zero_site_cap() {
    let limits = Limits {
        sites: 0,
        ..generous_limits()
    };
    let err = AttachPlan::checked(sites(1), AttachMode::EntryMulti, &limits)
        .expect_err("zero site cap admits no positive plan");
    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(err.stage(), Stage::Attach);
}

#[test]
fn checked_refuses_over_site_cap() {
    let limits = Limits {
        sites: 2,
        ..generous_limits()
    };
    let err = AttachPlan::checked(sites(3), AttachMode::EntryMulti, &limits)
        .expect_err("n=3 exceeds sites=2");
    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(err.stage(), Stage::Attach);
}

#[test]
fn checked_reserves_worst_case_attempts() {
    // n=4 admits at most 2n-1 = 7 attempts; the reservation is exact.
    let exact = Limits {
        work_steps: 7,
        ..generous_limits()
    };
    assert!(AttachPlan::checked(sites(4), AttachMode::EntryMulti, &exact).is_ok());
    let short = Limits {
        work_steps: 6,
        ..generous_limits()
    };
    let err = AttachPlan::checked(sites(4), AttachMode::EntryMulti, &short)
        .expect_err("2n-1=7 attempts exceed work_steps=6");
    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(err.stage(), Stage::Attach);
    let zero = Limits {
        work_steps: 0,
        ..generous_limits()
    };
    assert!(AttachPlan::checked(sites(1), AttachMode::EntryMulti, &zero).is_err());
}

#[test]
fn checked_accepts_max_caps() {
    assert!(AttachPlan::checked(sites(8), AttachMode::ReturnMulti, &generous_limits()).is_ok());
}

#[test]
fn split_halves_even() {
    let plan = plan_for(8);
    assert_eq!(plan.split_sites(0..4).unwrap(), Some((0..2, 2..4)));
    assert_eq!(plan.split_sites(0..8).unwrap(), Some((0..4, 4..8)));
    assert_eq!(plan.split_sites(2..6).unwrap(), Some((2..4, 4..6)));
}

#[test]
fn split_halves_odd() {
    let plan = plan_for(8);
    assert_eq!(plan.split_sites(0..3).unwrap(), Some((0..1, 1..3)));
    assert_eq!(plan.split_sites(0..5).unwrap(), Some((0..2, 2..5)));
    assert_eq!(plan.split_sites(1..4).unwrap(), Some((1..2, 2..4)));
    assert_eq!(plan.split_sites(5..7).unwrap(), Some((5..6, 6..7)));
}

#[test]
fn split_singleton_returns_none() {
    let plan = plan_for(8);
    for i in 0..8 {
        assert_eq!(plan.split_sites(i..i + 1).unwrap(), None, "singleton {i}");
    }
}

#[test]
fn split_refuses_empty_reversed_and_out_of_bounds() {
    let plan = plan_for(8);
    for batch in [2..2, 8..8, 3..2, 0..9, 8..9, 7..9, 9..10] {
        let err = plan
            .split_sites(batch.clone())
            .expect_err(&format!("range {batch:?} must refuse"));
        assert_eq!(err.kind(), ErrorKind::InvalidInput, "range {batch:?}");
        assert_eq!(err.stage(), Stage::Attach, "range {batch:?}");
    }
}

#[test]
fn split_cover_is_disjoint_and_exact() {
    let plan = plan_for(8);
    for start in 0..8 {
        for end in start + 1..=8 {
            let batch = start..end;
            match plan.split_sites(batch.clone()).unwrap() {
                None => assert_eq!(end - start, 1, "only singletons return None"),
                Some((left, right)) => {
                    assert_eq!(left.start, start, "left start {batch:?}");
                    assert_eq!(right.end, end, "right end {batch:?}");
                    assert_eq!(left.end, right.start, "halves meet {batch:?}");
                    assert_eq!(left.end, start + (end - start) / 2, "midpoint {batch:?}");
                    assert!(!left.is_empty() && !right.is_empty(), "nonempty {batch:?}");
                }
            }
        }
    }
}

#[test]
fn terminal_denied_cannot_split_even_if_policy_requests() {
    for error in [
        error(ErrorKind::Denied),
        error_errno(ErrorKind::Denied, 1),  // EPERM-shaped
        error_errno(ErrorKind::Denied, 13), // EACCES-shaped
    ] {
        let mut policy = FixedPolicy(ErrorAction::IsolateSites);
        assert_eq!(
            adjudicate_split(&mut policy, &error, 4),
            ErrorAction::AbortAndRollback,
            "Denied multi cannot split"
        );
    }
}

#[test]
fn terminal_resource_cannot_split() {
    for kind in [ErrorKind::LimitExceeded, ErrorKind::Overflow] {
        let mut policy = FixedPolicy(ErrorAction::IsolateSites);
        assert_eq!(
            adjudicate_split(&mut policy, &error(kind), 4),
            ErrorAction::AbortAndRollback,
            "resource failure {kind:?} cannot split"
        );
    }
}

#[test]
fn backend_errno_is_not_terminal() {
    // H33: a Backend error carrying EPERM/EACCES (verifier/license refusal
    // shape) is policy-decided; errno alone never classifies.
    for errno in [1, 13] {
        let mut policy = FixedPolicy(ErrorAction::IsolateSites);
        assert_eq!(
            adjudicate_split(&mut policy, &error_errno(ErrorKind::Backend, errno), 4),
            ErrorAction::IsolateSites,
            "Backend errno {errno} defers to policy"
        );
    }
    let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
    assert_eq!(
        adjudicate_split(&mut policy, &error_errno(ErrorKind::Backend, 13), 4),
        ErrorAction::AbortAndRollback,
        "policy abort honored for Backend error"
    );
}

#[test]
fn policy_vote_honored_for_isolatable_errors() {
    for kind in [
        ErrorKind::InvalidInput,
        ErrorKind::Malformed,
        ErrorKind::Incompatible,
        ErrorKind::Unsupported,
        ErrorKind::Backend,
        ErrorKind::Disappeared,
        ErrorKind::Changed,
        ErrorKind::Poisoned,
    ] {
        let mut isolate = FixedPolicy(ErrorAction::IsolateSites);
        assert_eq!(
            adjudicate_split(&mut isolate, &error(kind), 3),
            ErrorAction::IsolateSites,
            "isolate vote honored for {kind:?}"
        );
        let mut abort = FixedPolicy(ErrorAction::AbortAndRollback);
        assert_eq!(
            adjudicate_split(&mut abort, &error(kind), 3),
            ErrorAction::AbortAndRollback,
            "abort vote honored for {kind:?}"
        );
    }
}

#[test]
fn singleton_cannot_split() {
    let mut policy = FixedPolicy(ErrorAction::IsolateSites);
    assert_eq!(
        adjudicate_split(&mut policy, &error(ErrorKind::InvalidInput), 1),
        ErrorAction::AbortAndRollback,
        "singleton cannot split"
    );
    assert_eq!(
        adjudicate_split(&mut policy, &error(ErrorKind::InvalidInput), 0),
        ErrorAction::AbortAndRollback,
        "empty batch cannot split"
    );
}

#[test]
fn is_terminal_error_pins_kinds() {
    for kind in [
        ErrorKind::Denied,
        ErrorKind::LimitExceeded,
        ErrorKind::Overflow,
    ] {
        assert!(is_terminal_error(&error(kind)), "{kind:?} is terminal");
        assert!(
            is_terminal_error(&error_errno(kind, 22)),
            "{kind:?} terminal regardless of errno"
        );
    }
    for kind in [
        ErrorKind::InvalidInput,
        ErrorKind::Malformed,
        ErrorKind::Incompatible,
        ErrorKind::Unsupported,
        ErrorKind::Backend,
        ErrorKind::Disappeared,
        ErrorKind::Changed,
        ErrorKind::Poisoned,
    ] {
        assert!(
            !is_terminal_error(&error(kind)),
            "{kind:?} is policy-decided"
        );
        assert!(
            !is_terminal_error(&error_errno(kind, 13)),
            "{kind:?} with EACCES still policy-decided"
        );
    }
}

#[test]
fn policy_is_consulted_before_terminal_override() {
    let mut policy = CountingPolicy {
        action: ErrorAction::IsolateSites,
        calls: 0,
    };
    let _ = adjudicate_split(&mut policy, &error(ErrorKind::Denied), 4);
    assert_eq!(
        policy.calls, 1,
        "policy sees the error even when overridden"
    );
}

/// Pure decision-model walk: no backend, no effects. Each node is attempted
/// once; only side-effect-free isolatable multi nodes split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeOutcome {
    Attach,
    FailIsolatable,
    FailTerminal,
}

#[derive(Debug, Default)]
struct Walk {
    attempts: usize,
    order: Vec<Range<usize>>,
    attached: Vec<Range<usize>>,
    refused: Vec<usize>,
    terminal_at: Option<Range<usize>>,
}

fn drive_model<P: ErrorPolicy>(
    plan: &AttachPlan,
    script: &mut dyn FnMut(&Range<usize>) -> NodeOutcome,
    policy: &mut P,
) -> Walk {
    let mut walk = Walk::default();
    let mut stack = vec![0..plan.sites().len()];
    while let Some(node) = stack.pop() {
        walk.attempts += 1;
        walk.order.push(node.clone());
        match script(&node) {
            NodeOutcome::Attach => walk.attached.push(node),
            NodeOutcome::FailIsolatable => {
                let action = adjudicate_split(policy, &error(ErrorKind::InvalidInput), node.len());
                if node.len() > 1 && action == ErrorAction::IsolateSites {
                    let (left, right) = plan.split_sites(node).unwrap().unwrap();
                    stack.push(right);
                    stack.push(left);
                } else {
                    // Refused leaves and policy-aborted ranges are reported;
                    // the walk continues to isolate the remaining siblings.
                    walk.refused.extend(node.clone());
                }
            }
            NodeOutcome::FailTerminal => {
                let _ = adjudicate_split(policy, &error(ErrorKind::Denied), node.len());
                walk.refused.extend(node.clone());
                walk.terminal_at = Some(node);
                break;
            }
        }
    }
    walk.refused.sort_unstable();
    walk
}

fn assert_walk_sound(walk: &Walk, n: usize) {
    assert!(
        walk.attempts <= 2 * n - 1,
        "attempts {} exceed 2*{n}-1; order {:?}",
        walk.attempts,
        walk.order
    );
    let mut seen: HashSet<Range<usize>> = HashSet::new();
    for node in &walk.order {
        assert!(seen.insert(node.clone()), "node {node:?} attempted twice");
    }
    let mut covered: HashSet<usize> = HashSet::new();
    for group in &walk.attached {
        for i in group.clone() {
            assert!(covered.insert(i), "site {i} attached twice");
        }
    }
    for i in &walk.refused {
        assert!(covered.insert(*i), "site {i} covered twice");
    }
    if walk.terminal_at.is_none() {
        assert_eq!(
            covered.len(),
            n,
            "non-terminal walk covers every site exactly once"
        );
    }
}

/// First-profile outcome: all sites required, so any refused leaf rolls
/// back every successful node in the eventual effectful operation.
fn first_profile_rolls_back(walk: &Walk) -> bool {
    walk.terminal_at.is_some() || !walk.refused.is_empty()
}

#[test]
fn model_all_success_single_attempt() {
    for n in 1..=8 {
        let plan = plan_for(n);
        let mut policy = FixedPolicy(ErrorAction::AbortAndRollback);
        let walk = drive_model(&plan, &mut |_| NodeOutcome::Attach, &mut policy);
        assert_eq!(walk.attempts, 1, "n={n} all-success attempts");
        assert_eq!(walk.attached, vec![0..n], "n={n} single group");
        assert!(walk.refused.is_empty());
        assert!(!first_profile_rolls_back(&walk), "n={n} commits");
        assert_walk_sound(&walk, n);
    }
}

fn fixture_nodes(n: usize) -> Vec<Range<usize>> {
    let root = json_mini::parse(FIXTURE).expect("fixture parses");
    assert_eq!(root.get("version").unwrap().as_u64().unwrap(), 1);
    let trees = root.get("trees").unwrap().as_arr().unwrap();
    let tree = trees
        .iter()
        .find(|t| t.get("n").unwrap().as_usize().unwrap() == n)
        .unwrap_or_else(|| panic!("fixture lacks n={n}"));
    assert_eq!(
        tree.get("attempts").unwrap().as_usize().unwrap(),
        2 * n - 1,
        "fixture bound n={n}"
    );
    tree.get("nodes")
        .unwrap()
        .as_arr()
        .unwrap()
        .iter()
        .map(|node| {
            let pair = node.as_arr().unwrap();
            assert_eq!(pair.len(), 2);
            pair[0].as_usize().unwrap()..pair[1].as_usize().unwrap()
        })
        .collect()
}

#[test]
fn split_trees_fixture_is_internally_consistent() {
    for n in 1..=8 {
        let nodes = fixture_nodes(n);
        assert_eq!(nodes.len(), 2 * n - 1, "node count n={n}");
        assert_eq!(nodes[0], 0..n, "root n={n}");
        let mut multis = 0;
        let mut singletons = 0;
        for node in &nodes {
            assert!(!node.is_empty() && node.end <= n, "range {node:?} n={n}");
            if node.len() == 1 {
                singletons += 1;
            } else {
                multis += 1;
                let mid = node.start + node.len() / 2;
                assert!(
                    nodes.contains(&(node.start..mid)) && nodes.contains(&(mid..node.end)),
                    "exact halves of {node:?} n={n}"
                );
            }
        }
        assert_eq!(singletons, n, "leaves n={n}");
        assert_eq!(multis, n - 1, "internal nodes n={n}");
    }
}

#[test]
fn model_full_split_matches_fixture() {
    for n in 1..=8 {
        let plan = plan_for(n);
        let mut policy = FixedPolicy(ErrorAction::IsolateSites);
        let walk = drive_model(&plan, &mut |_| NodeOutcome::FailIsolatable, &mut policy);
        assert_eq!(walk.order, fixture_nodes(n), "visit order n={n}");
        assert_eq!(walk.attempts, 2 * n - 1, "attempts n={n}");
        assert!(walk.attached.is_empty());
        assert_eq!(walk.refused, (0..n).collect::<Vec<_>>(), "refused n={n}");
        assert_walk_sound(&walk, n);
    }
}

#[test]
fn model_every_terminal_position() {
    for n in 1..=8 {
        let visit = fixture_nodes(n);
        for (k, terminal) in visit.iter().enumerate() {
            let plan = plan_for(n);
            let mut policy = FixedPolicy(ErrorAction::IsolateSites);
            // Nodes before k attach at their widest attempted grouping is not
            // guaranteed under all-success-then-terminal; instead fail every
            // node isolatably except node k, which fails terminally.
            let walk = drive_model(
                &plan,
                &mut |node| {
                    if node == terminal {
                        NodeOutcome::FailTerminal
                    } else {
                        NodeOutcome::FailIsolatable
                    }
                },
                &mut policy,
            );
            assert_eq!(walk.terminal_at, Some(terminal.clone()), "n={n} k={k}");
            assert_eq!(walk.attempts, k + 1, "n={n} k={k} attempts");
            assert!(first_profile_rolls_back(&walk), "n={n} k={k} rolls back");
            assert_walk_sound(&walk, n);
            // Successful groups are attempted once: every attached range
            // appears exactly once in the visit order.
            for group in &walk.attached {
                assert_eq!(
                    walk.order.iter().filter(|o| *o == group).count(),
                    1,
                    "group {group:?} attempted once n={n} k={k}"
                );
            }
        }
    }
}

#[test]
fn model_mixed_bad_leaves() {
    let plan = plan_for(8);
    let bad: HashSet<usize> = [1, 5].into_iter().collect();
    let mut policy = FixedPolicy(ErrorAction::IsolateSites);
    let walk = drive_model(
        &plan,
        &mut |node| {
            if node.len() == 1 && bad.contains(&node.start) {
                NodeOutcome::FailIsolatable
            } else if node.len() == 1 || node.clone().all(|i| !bad.contains(&i)) {
                NodeOutcome::Attach
            } else {
                NodeOutcome::FailIsolatable
            }
        },
        &mut policy,
    );
    assert_eq!(walk.refused, vec![1, 5]);
    assert!(first_profile_rolls_back(&walk), "refused leaves roll back");
    assert_walk_sound(&walk, 8);
    let mut covered: HashSet<usize> = HashSet::new();
    for group in &walk.attached {
        for i in group.clone() {
            assert!(!bad.contains(&i), "bad site {i} attached");
            assert!(covered.insert(i));
        }
    }
    for i in 0..8 {
        if !bad.contains(&i) {
            assert!(covered.contains(&i), "good site {i} covered");
        }
    }
}

#[test]
fn model_exhaustive_bad_subsets() {
    for n in 1..=8 {
        for mask in 0..(1u32 << n) {
            let bad: HashSet<usize> = (0..n).filter(|i| mask & (1 << i) != 0).collect();
            let plan = plan_for(n);
            let mut policy = FixedPolicy(ErrorAction::IsolateSites);
            let walk = drive_model(
                &plan,
                &mut |node| {
                    if node.clone().any(|i| bad.contains(&i)) {
                        NodeOutcome::FailIsolatable
                    } else {
                        NodeOutcome::Attach
                    }
                },
                &mut policy,
            );
            let expected: Vec<usize> = (0..n).filter(|i| bad.contains(i)).collect();
            assert_eq!(walk.refused, expected, "n={n} mask={mask:08b}");
            assert_walk_sound(&walk, n);
        }
    }
}

#[test]
fn model_offset_cookie_pairs_exact() {
    let plan = plan_for(8);
    let mut policy = FixedPolicy(ErrorAction::IsolateSites);
    let mut observed: Vec<(Range<usize>, Vec<(u64, u64)>)> = Vec::new();
    let walk = drive_model(
        &plan,
        &mut |node| {
            observed.push((
                node.clone(),
                plan.sites()[node.clone()]
                    .iter()
                    .map(|site| (site.offset, site.cookie))
                    .collect(),
            ));
            NodeOutcome::FailIsolatable
        },
        &mut policy,
    );
    assert_eq!(walk.attempts, 2 * 8 - 1);
    for (range, pairs) in &observed {
        let expected: Vec<(u64, u64)> = range
            .clone()
            .map(|i| (0x1000 + i as u64 * 0x10, 500 + i as u64))
            .collect();
        assert_eq!(pairs, &expected, "pairs for {range:?}");
    }
}

#[test]
fn model_is_deterministic() {
    let plan = plan_for(6);
    let mut script = |node: &Range<usize>| {
        if node.start % 3 == 0 && node.len() > 1 {
            NodeOutcome::FailIsolatable
        } else if node.len() == 1 && node.start == 4 {
            NodeOutcome::FailTerminal
        } else {
            NodeOutcome::Attach
        }
    };
    let mut first_policy = FixedPolicy(ErrorAction::IsolateSites);
    let first = drive_model(&plan, &mut script, &mut first_policy);
    let mut second_policy = FixedPolicy(ErrorAction::IsolateSites);
    let second = drive_model(&plan, &mut script, &mut second_policy);
    assert_eq!(first.attempts, second.attempts);
    assert_eq!(first.order, second.order);
    assert_eq!(first.attached, second.attached);
    assert_eq!(first.refused, second.refused);
    assert_eq!(first.terminal_at, second.terminal_at);
}

/// Deterministic bounded sweep (seeded xorshift64): stands in for the
/// planned Proptest trees because the shared Cargo lock cannot take a new
/// dev-dependency from this lane; the integration owner runs the Proptest
/// gate separately.
fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[test]
fn model_bounded_sweep_seeded() {
    let mut rng = 0x243f_6a88_85a3_08d3u64;
    for _ in 0..2000 {
        let n = 1 + (xorshift64(&mut rng) % 64) as usize;
        let plan = plan_for(n);
        let isolate = xorshift64(&mut rng) % 2 == 0;
        let mut policy = FixedPolicy(if isolate {
            ErrorAction::IsolateSites
        } else {
            ErrorAction::AbortAndRollback
        });
        // Seeded per-node script drawn before the walk for determinism.
        let draws: Vec<NodeOutcome> = (0..2 * n)
            .map(|_| match xorshift64(&mut rng) % 4 {
                0 => NodeOutcome::Attach,
                1 | 2 => NodeOutcome::FailIsolatable,
                _ => NodeOutcome::FailTerminal,
            })
            .collect();
        let mut cursor = 0usize;
        let walk = drive_model(
            &plan,
            &mut |_| {
                let outcome = draws[cursor % draws.len()];
                cursor += 1;
                outcome
            },
            &mut policy,
        );
        assert_walk_sound(&walk, n);
    }
}

#[test]
fn mutant_unbounded_singleton_retry_violates_bound() {
    // Mutant: retry a failing singleton three times instead of refusing it.
    // With n=4 all-bad leaves the mutant needs 3 multi attempts plus
    // 4*3 singleton attempts = 15, violating the 2n-1 = 7 bound the
    // oracle enforces.
    let plan = plan_for(4);
    let mut attempts = 0usize;
    let mut stack = vec![0..4];
    while let Some(node) = stack.pop() {
        if node.len() == 1 {
            attempts += 3;
        } else {
            attempts += 1;
            let (left, right) = plan.split_sites(node).unwrap().unwrap();
            stack.push(right);
            stack.push(left);
        }
    }
    assert!(
        attempts > 2 * 4 - 1,
        "mutant needs {attempts} attempts; bound assertion discriminates"
    );
    // Valid twin restores the bound.
    let mut policy = FixedPolicy(ErrorAction::IsolateSites);
    let valid = drive_model(&plan, &mut |_| NodeOutcome::FailIsolatable, &mut policy);
    assert_eq!(valid.attempts, 2 * 4 - 1);
}

#[test]
fn mutant_offset_cookie_swap_breaks_grouping() {
    // Mutant: build attempt slices from parallel offset/cookie vectors with
    // the cookie vector rotated by one, as two divergent vectors would.
    let plan = plan_for(4);
    let offsets: Vec<u64> = plan.sites().iter().map(|site| site.offset).collect();
    let mut cookies: Vec<u64> = plan.sites().iter().map(|site| site.cookie).collect();
    cookies.rotate_left(1);
    let mutant_pairs: Vec<(u64, u64)> = offsets.into_iter().zip(cookies.into_iter()).collect();
    let expected: Vec<(u64, u64)> = plan
        .sites()
        .iter()
        .map(|site| (site.offset, site.cookie))
        .collect();
    assert_ne!(
        mutant_pairs, expected,
        "swapped parallel vectors diverge; grouping assertion discriminates"
    );
    assert_eq!(mutant_pairs[0], (0x1000, 501), "mutant shape pinned");
}

#[test]
fn mutant_split_on_terminal_denial_over_attempts() {
    // Mutant: split a Denied multi failure instead of aborting. With n=4
    // and a Denied root the mutant walks the whole tree (7 attempts);
    // the valid twin aborts after 1 attempt.
    let plan = plan_for(4);
    let mut mutant_attempts = 0usize;
    let mut stack = vec![0..4];
    while let Some(node) = stack.pop() {
        mutant_attempts += 1;
        if node.len() > 1 {
            let (left, right) = plan.split_sites(node).unwrap().unwrap();
            stack.push(right);
            stack.push(left);
        }
    }
    assert_eq!(mutant_attempts, 7, "mutant splits the Denied root");
    let mut policy = FixedPolicy(ErrorAction::IsolateSites);
    let valid = drive_model(&plan, &mut |_| NodeOutcome::FailTerminal, &mut policy);
    assert_eq!(valid.attempts, 1, "valid twin aborts on terminal denial");
    assert!(
        mutant_attempts > valid.attempts,
        "call-count assertion discriminates split-on-denial"
    );
}

#[derive(Debug)]
struct FakeLink {
    id: u64,
}

#[derive(Debug)]
struct FakeUncertain {
    id: u64,
}

#[derive(Debug)]
struct FakeBackend {
    charges: usize,
    attaches: usize,
    retires: usize,
    uncertain_retires: usize,
}

// SAFETY: test fake; charge/retirement statements are only asserted, never trusted.
unsafe impl AttachBackend for FakeBackend {
    type Authority = ();
    type Link = FakeLink;
    type Uncertain = FakeUncertain;

    fn custody_charge(
        &self,
        _authority: &Self::Authority,
        sites: &[Site],
    ) -> Result<CustodyCharge, OperationError> {
        Ok(CustodyCharge {
            link_slots: sites.len(),
            retained_bytes: sites.len() * 16,
        })
    }

    fn attach(
        &mut self,
        _authority: &Self::Authority,
        sites: &[Site],
        mode: AttachMode,
    ) -> NativeAttach<Self::Link, Self::Uncertain> {
        self.attaches += 1;
        match mode {
            AttachMode::EntrySingle | AttachMode::ReturnSingle if sites.len() == 1 => {
                NativeAttach::Attached(FakeLink {
                    id: sites[0].cookie,
                })
            }
            _ if sites.is_empty() => NativeAttach::NoEffect(error(ErrorKind::InvalidInput)),
            _ => NativeAttach::Uncertain {
                custody: FakeUncertain { id: 7 },
                cause: error(ErrorKind::Backend),
            },
        }
    }

    fn retire(&mut self, _link: &mut Self::Link) -> NativeRetire {
        self.retires += 1;
        NativeRetire::Retired
    }

    fn retire_uncertain(&mut self, _custody: &mut Self::Uncertain) -> NativeRetire {
        self.uncertain_retires += 1;
        NativeRetire::Pending
    }
}

#[test]
fn fake_backend_exercises_unsafe_contract() {
    let mut backend = FakeBackend {
        charges: 0,
        attaches: 0,
        retires: 0,
        uncertain_retires: 0,
    };
    let plan = plan_for(2);
    let charge = backend.custody_charge(&(), plan.sites()).unwrap();
    backend.charges += 1;
    assert_eq!(charge.link_slots, 2);
    assert_eq!(charge.retained_bytes, 32);
    match backend.attach(&(), &plan.sites()[0..1], AttachMode::EntrySingle) {
        NativeAttach::Attached(mut link) => {
            assert_eq!(link.id, 500);
            assert!(matches!(backend.retire(&mut link), NativeRetire::Retired));
        }
        other => panic!("expected Attached, found {other:?}"),
    }
    match backend.attach(&(), &[], AttachMode::EntryMulti) {
        NativeAttach::NoEffect(err) => assert_eq!(err.kind(), ErrorKind::InvalidInput),
        other => panic!("expected NoEffect, found {other:?}"),
    }
    match backend.attach(&(), plan.sites(), AttachMode::EntryMulti) {
        NativeAttach::Uncertain { mut custody, cause } => {
            assert_eq!(custody.id, 7, "uncertain carries custody, never ownerless");
            assert_eq!(cause.kind(), ErrorKind::Backend);
            assert!(matches!(
                backend.retire_uncertain(&mut custody),
                NativeRetire::Pending
            ));
        }
        other => panic!("expected Uncertain, found {other:?}"),
    }
    assert!(matches!(
        NativeRetire::Failed(error(ErrorKind::Backend)),
        NativeRetire::Failed(_)
    ));
    assert_eq!(backend.attaches, 3);
    assert_eq!(backend.retires, 1);
    assert_eq!(backend.uncertain_retires, 1);
    assert_eq!(backend.charges, 1);
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn pure_values_are_send_sync() {
    assert_send_sync::<Site>();
    assert_send_sync::<AttachMode>();
    assert_send_sync::<AttachPlan>();
    assert_send_sync::<ErrorAction>();
    assert_send_sync::<CustodyCharge>();
    assert_send_sync::<NativeRetire>();
    assert_send_sync::<NativeAttach<FakeLink, FakeUncertain>>();
}
