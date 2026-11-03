// SPDX-License-Identifier: Apache-2.0
//! Pool-backed effectful attachment executor: bounded split-tree walk,
//! first-profile rollback and explicit retirement.
//!
//! ADAPT of the donor bisection discipline: p11scope
//! `.worktrees/v040-integration/crates/bpf-multi/src/lib.rs`
//! @ `2c2713e66292b0d2688508a25f79e813ae823d81`
//! (`bisect_attach_counted`, lines 405-465: one attempt per node,
//! midpoint LIFO walk, terminal halt that closes created leaves) and
//! OSSLscope `osslscope/src/plan.rs` @ `1a481831a85375ecb2d69ca65618d37c846de8b3`
//! (`bisect_attach`, lines 579-611: live links plus refused indices).
//! The donor synchronous drop becomes a pool-registered rollback with
//! per-object proof: each attached link and uncertain acquisition is
//! registered in the reserved pool entry before any further backend or
//! policy call, so a policy panic propagates with all native owners
//! preserved in the pool. All user-owned donor slices under blanket
//! `OWNER-2026-10-23`; third-party/upstream lines never copied.

use crate::attach::plan::{
    adjudicate_split_verbose, is_terminal_error, AttachBackend, AttachPlan, ErrorAction,
    ErrorPolicy,
    NativeAttach,
};
use crate::attach::pool::{LinkSlot, LinkState, RetirementPool, UncertainSlot, UncertainState};
use crate::attach::retire::{AttachOutcome, AttachSummary, AttachmentSet, UnresolvedAttachments};
use crate::{ErrorKind, Limits, OperationError, Stage};

/// Refused admission with no attempts, no attachments and no custody.
fn refused<B: AttachBackend>(cause: OperationError) -> AttachOutcome<B> {
    AttachOutcome::RolledBack {
        summary: AttachSummary {
            attempts: 0,
            attached_sites: 0,
            refused_sites: Vec::new(),
        },
        cause,
    }
}

/// Execute one validated plan against a backend through a persistent pool.
///
/// Admission (per-call [`Limits`], one group slot, the backend's audited
/// charge against pool capacity) completes before the first native call;
/// any refusal returns `RolledBack` with an empty summary and no custody.
/// The walk below then visits the split tree LIFO (right pushed, left
/// visited first) through [`AttachPlan::split_sites`] and
/// [`adjudicate_split_verbose`]: each node is attempted once (at most
/// `2n-1` calls), only side-effect-free isolatable multi failures
/// split, and terminal denials, caller-voted aborts and uncertain
/// acquisitions end the walk (library-forced singleton aborts refuse
/// in place while salvage continues). Every attached link and
/// uncertain custody is registered in
/// the reserved pool entry before the next backend or policy call, so a
/// policy panic propagates with all native owners and the authority
/// preserved in the pool. Uncertain results are terminal and never
/// split. The first profile requires all sites: any refused leaf rolls
/// back every successful node through explicit per-link retirement; a
/// fully proven rollback returns `RolledBack`, anything less returns
/// `Unresolved` custody for later recovery. Full success returns
/// `Active` with the single move-only ticket.
pub fn execute_plan<B: AttachBackend, P: ErrorPolicy>(
    pool: &mut RetirementPool<B>,
    backend: B,
    authority: B::Authority,
    plan: AttachPlan,
    policy: &mut P,
    limits: &Limits,
) -> AttachOutcome<B> {
    if pool.check_process(Stage::Attach).is_err() {
        // Fork-without-exec reuse: refuse before native effects. The
        // passed backend/authority drop here; callers that need the
        // file afterwards keep their own authority clone.
        return refused(OperationError::new(
            ErrorKind::Changed,
            Stage::Attach,
            None,
            None,
        ));
    }
    let sites = plan.sites().len();
    // Worst-case per-call reservation: 16 input bytes per site, the
    // plan's sites within the site cap, one live link and one pending
    // slot per site, 2n-1 split attempts.
    let input_bytes = match sites.checked_mul(16) {
        Some(bytes) => bytes,
        None => {
            return refused(OperationError::new(
                ErrorKind::Overflow,
                Stage::Attach,
                None,
                None,
            ))
        }
    };
    let worst_attempts = match sites
        .checked_mul(2)
        .and_then(|doubled| doubled.checked_sub(1))
    {
        Some(attempts) => attempts,
        None => {
            return refused(OperationError::new(
                ErrorKind::Overflow,
                Stage::Attach,
                None,
                None,
            ))
        }
    };
    let worst_attempts = match u64::try_from(worst_attempts) {
        Ok(attempts) => attempts,
        Err(_) => {
            return refused(OperationError::new(
                ErrorKind::Overflow,
                Stage::Attach,
                None,
                None,
            ))
        }
    };
    if input_bytes > limits.input_bytes
        || sites > limits.sites
        || sites > limits.live_links
        || sites > limits.pending_retirements
        || worst_attempts > limits.work_steps
    {
        return refused(OperationError::new(
            ErrorKind::LimitExceeded,
            Stage::Attach,
            None,
            None,
        ));
    }
    // Group slot before charge: saturation refuses without consulting
    // the backend at all.
    if !pool.has_group_slot() {
        return refused(OperationError::new(
            ErrorKind::LimitExceeded,
            Stage::Attach,
            None,
            None,
        ));
    }
    let charge = match backend.custody_charge(&authority, plan.sites()) {
        Ok(charge) => charge,
        Err(cause) => return refused(cause),
    };
    if charge.retained_bytes > limits.retained_bytes {
        return refused(OperationError::new(
            ErrorKind::LimitExceeded,
            Stage::Attach,
            None,
            None,
        ));
    }
    let id = match pool.reserve(backend, authority, charge) {
        Ok(id) => id,
        Err(cause) => return refused(cause),
    };

    let mode = plan.mode();
    // One-element work stack (a Vec of one Range, not the range spread).
    let mut stack: Vec<std::ops::Range<usize>> = Vec::new();
    stack.push(0..sites);
    let mut attempts = 0usize;
    let mut attached_sites = 0usize;
    let mut refused_sites: Vec<usize> = Vec::new();
    let mut cause: Option<OperationError> = None;
    while let Some(node) = stack.pop() {
        attempts += 1;
        let outcome = {
            let entry = pool
                .entry_mut(id)
                .expect("reserved entry lives for the whole walk");
            entry
                .backend
                .attach(&entry.authority, &plan.sites()[node.clone()], mode)
        };
        match outcome {
            NativeAttach::Attached(link) => {
                let entry = pool
                    .entry_mut(id)
                    .expect("reserved entry lives for the whole walk");
                entry.links.push(LinkSlot {
                    state: LinkState::Active(link),
                });
                attached_sites += node.len();
            }
            NativeAttach::NoEffect(error) => {
                if is_terminal_error(&error) {
                    // S180: terminal errors break, but the policy is
                    // still consulted exactly once (vote recorded for
                    // audit). Stacked ranges refuse with the node so
                    // the summary accounts every site.
                    let _ = adjudicate_split_verbose(policy, &error, node.len());
                    refused_sites.extend(node.clone());
                    for range in stack.drain(..) {
                        refused_sites.extend(range);
                    }
                    if cause.is_none() {
                        cause = Some(error);
                    }
                    break;
                }
                let (action, voted_abort) =
                    adjudicate_split_verbose(policy, &error, node.len());
                match action {
                    ErrorAction::IsolateSites => {
                        match plan.split_sites(node.clone()) {
                            Ok(Some((left, right))) => {
                                stack.push(right);
                                stack.push(left);
                            }
                            _ => {
                                // Unreachable: adjudication only votes
                                // isolate for multi nodes, and every
                                // walked node is a valid plan range.
                                // Fail safe by refusing the range.
                                refused_sites.extend(node.clone());
                                if cause.is_none() {
                                    cause = Some(error);
                                }
                            }
                        }
                    }
                    ErrorAction::AbortAndRollback => {
                        refused_sites.extend(node.clone());
                        if cause.is_none() {
                            cause = Some(error);
                        }
                        if voted_abort {
                            // S162: caller-voted abort is fail-fast and
                            // ends the walk. Unvisited stacked ranges
                            // refuse with the aborted node so the summary
                            // accounts every site. Library-forced
                            // singleton aborts refuse in place while
                            // salvage continues.
                            for range in stack.drain(..) {
                                refused_sites.extend(range);
                            }
                            break;
                        }
                    }
                }
            }
            NativeAttach::Uncertain {
                custody,
                cause: ucause,
            } => {
                // Terminal: register custody before anything else, then
                // end the walk. Never split, never classified.
                let entry = pool
                    .entry_mut(id)
                    .expect("reserved entry lives for the whole walk");
                entry.uncertain.push(UncertainSlot {
                    state: UncertainState::Open(custody),
                });
                if cause.is_none() {
                    cause = Some(ucause);
                }
                break;
            }
        }
    }
    refused_sites.sort_unstable();
    let refused: Vec<_> = refused_sites
        .iter()
        .map(|index| plan.sites()[*index])
        .collect();
    let summary = AttachSummary {
        attempts,
        attached_sites,
        refused_sites: refused,
    };
    match cause {
        None => {
            let live = pool.issue_ticket(id);
            AttachOutcome::Active {
                owner: AttachmentSet::issued(pool.session(), id, live),
                summary,
            }
        }
        Some(cause) => {
            // First profile: roll back every success with proof. Links
            // retire in reverse sequence; uncertain acquisitions stay
            // open for ticket-driven recovery.
            pool.rollback_links(id);
            if pool.reap_if_empty(id) {
                AttachOutcome::RolledBack { summary, cause }
            } else {
                let live = pool.issue_ticket(id);
                AttachOutcome::Unresolved {
                    custody: UnresolvedAttachments::issued(pool.session(), id, live),
                    summary,
                    cause,
                }
            }
        }
    }
}
