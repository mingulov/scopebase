// SPDX-License-Identifier: Apache-2.0
//! Optional producer task/exec identity protocol (pure host values).
//!
//! ADAPT p11scope 2c2713e `crates/ebpf-common/src/lib.rs:1316-1332`
//! (producer transport identity: cookie 0 invalid, exec 0 valid,
//! `image_pair_matches` same-execution comparison) and
//! `src/history.rs:65-102` (`Registry::admit`: retained-consumer domain,
//! stale-exec and capacity refusals, predecessor retirement on advance).
//! ADAPT `crates/ebpf/native/image_identity.c:38-119` (zero-cell and quota
//! refusal, bounded ticket allocation), `:121-137` (same typed task
//! supplies both fields; outputs start zeroed) and `:147-159`
//! (group-leader identity); `image_identity_fork.c:16-63` (CLONE_THREAD is
//! not a new process; fork identities originate at the birth hook).
//! ADAPT `crates/ebpf/native/exec_task.c:18-76` (CO-RE existence guards
//! precede size/offset/read paths; newer `exec_state` layouts refuse
//! without reading; older scalar and nested bitmap flag shapes keep
//! dumpability in the low bits) as the host [`plan_exec_read`] decision.
//! VECTORS mirror `tests/exec_task_continuity.rs:171-241` outcome classes
//! (supported vs unknown shapes take safe compiled paths).
//! Grant: OWNER-2026-10-23 + D03 (user-owned GPL donor, library destination).
//! Product START/privacy/discovery layouts, loader control cells, BPF maps,
//! task-storage allocation, PID/root/affiliation state and the production
//! hooks stay in the donor; only the generic cookie/exec/domain discipline,
//! guard order and admit/retire rules port. The session domain here is a
//! 16-byte value (spec wire layout), not the donor's retained u64 consumer
//! id; the refusal semantics are unchanged.
//!
//! A [`ProducerIdentity`] binds one producer session ([`ProducerDomain`]),
//! one non-reused task ticket ([`TaskCookie`]) and one exec epoch
//! ([`ExecGeneration`], zero valid). [`same_execution`] is the only lineage
//! predicate: equal domain, task and exec. There is no PID, starttime or
//! polling input; a cookie observed across an exec boundary never verifies
//! as the pre-exec execution. Generation wrap is refused, never silent.
//!
//! [`IdentityRegistry`] is the consumer-side attach/verify/refuse flow: the
//! registry domain comes from the retained session, never a wire field, so
//! a forged foreign-domain identity refuses with [`ErrorKind::Incompatible`].
//! A stale exec epoch refuses with [`ErrorKind::Changed`]; a registry that
//! reaches its bound refuses new cookies with [`ErrorKind::LimitExceeded`].
//! An exec advance retires its exact predecessor.
//!
//! No BPF toolchain, privileged setup or live kernel is needed. Production
//! hooks (task-storage allocation, successful-exec transitions), exact-object
//! cells and TT05 live H01/H03/H08 continuity cells are separate bindings,
//! recorded as follow-ups, not implemented here.
//!
//! ```
//! use scopebase_bpf::identity::{IdentityRegistry, ProducerDomain, ProducerIdentity};
//! let domain = ProducerDomain([0xA0; 16]);
//! let birth = ProducerIdentity::checked(domain, 7, 0).expect("nonzero cookie");
//! let mut registry = IdentityRegistry::new(domain, 16);
//! assert!(registry.admit(&birth).is_ok());
//! ```

use crate::{ErrorKind as K, OperationError, Stage as S};
use std::collections::BTreeMap;
use std::num::NonZeroU64;

fn invalid() -> OperationError {
    OperationError::new(K::InvalidInput, S::Admission, None, None)
}

fn incompatible() -> OperationError {
    OperationError::new(K::Incompatible, S::Admission, None, None)
}

fn changed() -> OperationError {
    OperationError::new(K::Changed, S::Admission, None, None)
}

fn exhausted() -> OperationError {
    OperationError::new(K::LimitExceeded, S::Admission, None, None)
}

fn overflow() -> OperationError {
    OperationError::new(K::Overflow, S::Admission, None, None)
}

/// Producer session domain: 16 bytes of session provenance.
///
/// The value identifies the producer session that minted the task tickets
/// it travels with. It is provenance, not evidence of a successfully loaded
/// identity protocol, and it never crosses sessions: a registry admits only
/// its own retained domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProducerDomain(pub [u8; 16]);

/// Non-reused task ticket. Zero is unavailable, never an identity.
///
/// Tickets are minted once per task by the producer (donor: bounded CAS
/// allocation from a ticket budget); this host type only carries the
/// nonzero invariant so a zero cookie cannot be constructed silently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TaskCookie(pub NonZeroU64);

impl TaskCookie {
    /// Admit a nonzero task ticket. Zero refuses.
    pub fn new(cookie: u64) -> Result<Self, OperationError> {
        NonZeroU64::new(cookie).map(Self).ok_or_else(invalid)
    }

    /// The admitted nonzero ticket value.
    pub fn get(self) -> u64 {
        self.0.get()
    }
}

/// Exec epoch within one task ticket. Zero is a valid birth epoch.
///
/// The generation advances only on a successful exec of the same typed
/// task (leader/nonleader transitions per the selected native protocol;
/// failed exec is a non-transition). Generations never wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecGeneration(pub u64);

impl ExecGeneration {
    /// The birth epoch: a freshly minted task starts here.
    pub const ZERO: Self = Self(0);

    /// Mint the next exec epoch. Minting past `u64::MAX` refuses: no wrap.
    pub fn next(&self) -> Result<Self, OperationError> {
        self.0.checked_add(1).map(Self).ok_or_else(overflow)
    }
}

/// One producer task/exec identity: session, task ticket and exec epoch.
///
/// All three fields participate in lineage. Comparing fewer fields (cookie
/// alone, or any PID/starttime substitute) is not same-execution evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProducerIdentity {
    /// The minting producer session.
    pub domain: ProducerDomain,
    /// The non-reused task ticket.
    pub task: TaskCookie,
    /// The exec epoch within the task.
    pub exec: ExecGeneration,
}

impl ProducerIdentity {
    /// Admit a wire-shaped identity. A zero task cookie refuses; a zero
    /// exec epoch is valid.
    pub fn checked(
        domain: ProducerDomain,
        task_cookie: u64,
        exec: u64,
    ) -> Result<Self, OperationError> {
        Ok(Self {
            domain,
            task: TaskCookie::new(task_cookie)?,
            exec: ExecGeneration(exec),
        })
    }

    /// Render the fixed 32-byte wire form shared with the packaged C ABI.
    pub fn to_wire(&self) -> IdentityWire {
        IdentityWire {
            domain: self.domain.0,
            task_cookie: self.task.get(),
            exec_generation: self.exec.0,
        }
    }
}

/// Fixed C-compatible wire form: 32 bytes, 8-byte alignment, offsets
/// domain=0, task_cookie=16, exec_generation=24 (initial x86-64 profile).
///
/// Mirrors `struct scopebase_producer_identity_v1`; the packaged C header
/// carries the matching `_Static_assert` checks for real consumers.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityWire {
    /// Session domain bytes at offset 0.
    pub domain: [u8; 16],
    /// Task ticket at offset 16. Zero never decodes.
    pub task_cookie: u64,
    /// Exec epoch at offset 24. Zero is valid.
    pub exec_generation: u64,
}

const _: () = assert!(size_of::<IdentityWire>() == 32);
const _: () = assert!(align_of::<IdentityWire>() == 8);

impl IdentityWire {
    /// Decode a wire record. A zero task cookie refuses; no identity with
    /// an unavailable ticket can be decoded from forged zeroed bytes.
    pub fn from_wire(wire: &Self) -> Result<ProducerIdentity, OperationError> {
        ProducerIdentity::checked(
            ProducerDomain(wire.domain),
            wire.task_cookie,
            wire.exec_generation,
        )
    }
}

/// True only when domain, task ticket and exec epoch all match.
///
/// Both operands are well-typed (nonzero cookies by construction), so this
/// is the typed form of the donor's pair-match: equal cookie plus equal
/// exec within the same session. Anything less is not same execution.
pub fn same_execution(left: &ProducerIdentity, right: &ProducerIdentity) -> bool {
    left == right
}

/// Consumer-side exec-epoch binding outcome for one observed epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecAdvance {
    /// The observed epoch is current; the execution continues.
    Current(ProducerIdentity),
    /// The observed epoch is newer; the caller now holds the advanced
    /// identity and must treat the predecessor as retired.
    Advanced(ProducerIdentity),
}

impl ExecAdvance {
    /// The bound identity, current or advanced.
    pub fn identity(&self) -> ProducerIdentity {
        match *self {
            Self::Current(identity) | Self::Advanced(identity) => identity,
        }
    }
}

/// Bind an observed exec epoch against the current identity.
///
/// An older epoch is stale and refuses with [`K::Changed`]; the current
/// epoch verifies; a newer epoch advances (no wrap check applies to the
/// observation itself, since any `u64` above current is a forward step —
/// the no-wrap rule constrains the producer mint in [`ExecGeneration::next`]).
pub fn advance_exec(
    current: &ProducerIdentity,
    observed_exec: u64,
) -> Result<ExecAdvance, OperationError> {
    if observed_exec < current.exec.0 {
        return Err(changed());
    }
    let bound = ProducerIdentity {
        exec: ExecGeneration(observed_exec),
        ..*current
    };
    if observed_exec == current.exec.0 {
        Ok(ExecAdvance::Current(bound))
    } else {
        Ok(ExecAdvance::Advanced(bound))
    }
}

/// Attach/verify outcome for one admitted identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// First sighting of this task ticket in this session.
    Attached(ProducerIdentity),
    /// The observed identity matches the bound execution exactly.
    Verified(ProducerIdentity),
    /// The exec epoch advanced; `retired` is the exact predecessor and
    /// must no longer verify.
    Advanced {
        /// The current (advanced) identity.
        current: ProducerIdentity,
        /// The retired predecessor generation.
        retired: ProducerIdentity,
    },
}

impl Admission {
    /// The identity bound by this admission.
    pub fn identity(&self) -> ProducerIdentity {
        match *self {
            Self::Attached(identity) | Self::Verified(identity) => identity,
            Self::Advanced { current, .. } => current,
        }
    }
}

/// Consumer-side session registry: attach/verify/refuse with exec binding.
///
/// The registry domain is retained from the session owner, never taken
/// from a wire field or a live process lookup, so a forged identity from
/// another session refuses instead of binding. Capacity is a hard bound:
/// a full registry refuses new task tickets while admitted tickets keep
/// verifying. There is no PID input and no polling: lineage comes only
/// from producer-issued domain/task/exec triples.
#[derive(Clone, Debug)]
pub struct IdentityRegistry {
    domain: ProducerDomain,
    limit: usize,
    epochs: BTreeMap<u64, ExecGeneration>,
}

impl IdentityRegistry {
    /// Retain a session domain with a task-ticket capacity. A zero limit
    /// is structurally valid and admits no positive work.
    pub fn new(domain: ProducerDomain, limit: usize) -> Self {
        Self {
            domain,
            limit,
            epochs: BTreeMap::new(),
        }
    }

    /// The retained session domain.
    pub fn domain(&self) -> ProducerDomain {
        self.domain
    }

    /// The number of bound task tickets.
    pub fn len(&self) -> usize {
        self.epochs.len()
    }

    /// True when no task ticket is bound.
    pub fn is_empty(&self) -> bool {
        self.epochs.is_empty()
    }

    /// Attach, verify or refuse one observed identity.
    ///
    /// A foreign domain refuses with [`K::Incompatible`], a stale exec
    /// epoch with [`K::Changed`], and a new ticket past capacity with
    /// [`K::LimitExceeded`]; every refusal binds nothing. A newer exec
    /// epoch advances and retires its exact predecessor.
    pub fn admit(&mut self, observed: &ProducerIdentity) -> Result<Admission, OperationError> {
        if observed.domain != self.domain {
            return Err(incompatible());
        }
        let cookie = observed.task.get();
        if let Some(bound) = self.epochs.get(&cookie) {
            if observed.exec.0 < bound.0 {
                return Err(changed());
            }
            if observed.exec.0 == bound.0 {
                return Ok(Admission::Verified(*observed));
            }
            let retired = ProducerIdentity {
                exec: *bound,
                ..*observed
            };
            self.epochs.insert(cookie, observed.exec);
            return Ok(Admission::Advanced {
                current: *observed,
                retired,
            });
        }
        if self.epochs.len() >= self.limit {
            return Err(exhausted());
        }
        self.epochs.insert(cookie, observed.exec);
        Ok(Admission::Attached(*observed))
    }
}

/// Probed kernel exec-field shape: one boolean per CO-RE guard.
///
/// The fields follow the donor predicate's guard order: newer-layout
/// existence first, then `mm` existence/size, then scalar shape, then
/// bitmap shape. Each flag answers one guard; the plan consumes them in
/// that order and never reads past a failed guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecShapeProbe {
    /// A newer `exec_state` layout is present: refuse without reading it.
    pub newer_exec_state_present: bool,
    /// The task `mm` pointer field exists.
    pub mm_present: bool,
    /// The `mm` field has pointer width.
    pub mm_size_ok: bool,
    /// Scalar `mm->flags` exists.
    pub scalar_present: bool,
    /// Scalar flags are a full-width unsigned word (size, signedness and
    /// both shifts checked).
    pub scalar_word_ok: bool,
    /// Nested bitmap `mm->flags.__mm_flags` exists.
    pub bitmap_present: bool,
    /// Bitmap words all have full word width.
    pub bitmap_word_ok: bool,
}

/// Host read plan for one probed exec-field shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecReadPlan {
    /// No safe read exists for this shape; refuse before reading.
    Refuse,
    /// Read the scalar `mm->flags` word (low 2 bits carry dumpability).
    ReadScalarMmFlags,
    /// Read the nested bitmap `mm->flags.__mm_flags[0]` word.
    ReadBitmapMmFlags,
}

/// Decide the safe exec-field read for one probed shape.
///
/// Guard order is the ported contract: newer-layout existence refuses
/// first, then `mm` existence/size, then the scalar word checks, then the
/// bitmap word checks. A failed guard yields [`ExecReadPlan::Refuse`]; no
/// plan reads past its guards. The actual kernel read stays with the
/// production hooks, which must apply these guards before optional-field
/// access on the selected profile.
pub fn plan_exec_read(probe: &ExecShapeProbe) -> ExecReadPlan {
    if probe.newer_exec_state_present {
        return ExecReadPlan::Refuse;
    }
    if !probe.mm_present || !probe.mm_size_ok {
        return ExecReadPlan::Refuse;
    }
    if probe.scalar_present {
        if probe.scalar_word_ok {
            return ExecReadPlan::ReadScalarMmFlags;
        }
        return ExecReadPlan::Refuse;
    }
    if probe.bitmap_present && probe.bitmap_word_ok {
        return ExecReadPlan::ReadBitmapMmFlags;
    }
    ExecReadPlan::Refuse
}
