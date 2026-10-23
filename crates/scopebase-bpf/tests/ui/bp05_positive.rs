// SPDX-License-Identifier: Apache-2.0
//! BP05 UI positive: pool/ticket APIs used correctly, including
//! move-only ticket transfers. Must compile.
use scopebase_bpf::attach::*;
use scopebase_bpf::{ErrorKind, Limits, OperationError, Stage};

struct Stub;

#[derive(Debug)]
struct Link;
#[derive(Debug)]
struct Uncertain;

// SAFETY: UI stub; contract-honoring outcomes only.
unsafe impl AttachBackend for Stub {
    type Authority = ();
    type Link = Link;
    type Uncertain = Uncertain;
    fn custody_charge(
        &self,
        _authority: &Self::Authority,
        sites: &[Site],
    ) -> Result<CustodyCharge, OperationError> {
        Ok(CustodyCharge {
            link_slots: sites.len(),
            retained_bytes: 0,
        })
    }
    fn attach(
        &mut self,
        _authority: &Self::Authority,
        _sites: &[Site],
        _mode: AttachMode,
    ) -> NativeAttach<Self::Link, Self::Uncertain> {
        NativeAttach::Attached(Link)
    }
    fn retire(&mut self, _link: &mut Self::Link) -> NativeRetire {
        NativeRetire::Retired
    }
    fn retire_uncertain(&mut self, _custody: &mut Self::Uncertain) -> NativeRetire {
        NativeRetire::Retired
    }
}

struct Abort;

impl ErrorPolicy for Abort {
    fn classify(&mut self, _error: &OperationError, _batch_len: usize) -> ErrorAction {
        ErrorAction::AbortAndRollback
    }
}

fn main() {
    let limits = Limits {
        input_bytes: usize::MAX,
        retained_bytes: usize::MAX,
        work_steps: u64::MAX,
        sites: usize::MAX,
        live_links: usize::MAX,
        pending_retirements: usize::MAX,
    };
    let plan = AttachPlan::checked(
        vec![Site { offset: 1, cookie: 1 }],
        AttachMode::EntrySingle,
        &limits,
    )
    .unwrap();
    let mut pool = RetirementPool::new(RetirementCapacity {
        max_groups: 1,
        max_links: 1,
        max_retained_bytes: 0,
    })
    .unwrap();
    let mut policy = Abort;
    let outcome = execute_plan(&mut pool, Stub, (), plan, &mut policy, &limits);
    let owner = match outcome {
        AttachOutcome::Active { owner, summary } => {
            assert_eq!(summary.attempts, 1);
            owner
        }
        AttachOutcome::RolledBack { cause, .. } => panic!("{cause:?}"),
        AttachOutcome::Unresolved { cause, .. } => panic!("{cause:?}"),
    };
    assert!(matches!(owner.retire(&mut pool), Retirement::Retired));
    let _ = pool.usage();
    let report = pool.reconcile(RetirementBudget { max_native_calls: 1 });
    assert_eq!(report.retired_groups, 0);
    assert!(matches!(pool.close(), PoolClose::Closed));
    let _ = ErrorKind::Backend;
    let _ = Stage::Attach;
}
