// SPDX-License-Identifier: Apache-2.0
//! Immutable selected views over bounded, epoch-local consumed evidence.
// ADAPT M 8307a17 engine.mojo:291-318 and mappings.mojo:265-299,789-856,999-1012.
//! Empty reasons mean only that this ledger recorded no applicable reason.
//! Limits bound cardinalities, not allocator bytes, execution time or authority.
use crate::{
    domain::{ChannelId, ClaimId, Epoch, SourceRef},
    loss::{CappedLossSignal, LossFact, LossKind, LossMagnitude},
    quantity::{self, Unit, UnitTag},
    ContractError,
};
use std::cmp::Ordering;
/// Why a selected claim is qualified. Vocabulary is not a completeness token.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualityReason {
    /// Accepted damaging consumed evidence affects this claim.
    ConsumedLoss,
    /// Required evidence is absent (vocabulary; no mutator in this increment).
    MissingEvidence,
    /// This particular query selected a partial view.
    QueryPartial,
    /// Caller evidence is ambiguous (vocabulary only here).
    Ambiguous,
    /// Caller capacity affected evidence (vocabulary only here).
    Capacity,
}
/// Independent cardinality limits. Every value, including zero, is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerLimits {
    /// Maximum registered or selected claims.
    pub claims: usize,
    /// Maximum distinct reasons in each returned assessment.
    pub reasons_per_claim: usize,
    /// Maximum accepted loss and signal occurrences, including zero/empty ones.
    pub loss_facts: usize,
}
/// An immutable, caller-owned assessment of one selected claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimAssessment {
    claim: ClaimId,
    reasons: Vec<QualityReason>,
}
impl ClaimAssessment {
    /// The selected application claim.
    pub fn claim(&self) -> ClaimId {
        self.claim
    }
    /// Distinct reasons in declaration order; absence proves no completeness.
    pub fn reasons(&self) -> &[QualityReason] {
        &self.reasons
    }
}
/// An owned sorted set of call-local partial claims. Outsiders are ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryOverlay {
    partial_claims: Vec<ClaimId>,
}
impl QueryOverlay {
    /// Length and duplicates are checked before allocation. Duplicate preflight
    /// is O(n²), sorting O(n log n), with O(n) owned cardinality.
    pub fn new(partial_claims: &[ClaimId], max_claims: usize) -> Result<Self, ContractError> {
        Self::new_attempt(partial_claims, max_claims, &mut Attempt::default())
    }
    fn new_attempt(ids: &[ClaimId], max: usize, a: &mut Attempt) -> Result<Self, ContractError> {
        validate(ids, max)?;
        let mut partial_claims = Vec::new();
        a.reserve(&mut partial_claims, ids.len(), "overlay_owned_copy")?;
        partial_claims.extend_from_slice(ids);
        partial_claims.sort_unstable();
        Ok(Self { partial_claims })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum RetainedMagnitude {
    Exact(u64),
    AtLeast(u64),
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum RetainedObservation {
    Loss {
        kind: LossKind,
        magnitude: RetainedMagnitude,
    },
    Signal {
        observed: u8,
        cap: u8,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct RetainedFact {
    source: SourceRef,
    channel: ChannelId,
    unit: UnitTag,
    observation: RetainedObservation,
    affected: Vec<ClaimId>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaimState {
    claim: ClaimId,
    consumed_loss: bool,
}
/// Bounded consumed evidence for exactly one complete epoch. No eviction,
/// deduplication, query taint, identity acquisition or global state occurs.
pub struct ClaimLedger {
    epoch: Epoch,
    limits: LedgerLimits,
    claims: Vec<ClaimState>,
    facts: Vec<RetainedFact>,
}
impl ClaimLedger {
    /// Lazy construction: this does not reserve the supplied maximum capacities.
    pub fn new(epoch: Epoch, limits: LedgerLimits) -> Result<Self, ContractError> {
        Ok(Self {
            epoch,
            limits,
            claims: Vec::new(),
            facts: Vec::new(),
        })
    }
    /// Retain every accepted occurrence, preserving provenance, unit and magnitude.
    /// Exact zero is non-degrading; AtLeast(0) and Unknown remain damaging.
    pub fn record_loss<U: Unit>(
        &mut self,
        fact: &LossFact<U>,
        affected: &[ClaimId],
    ) -> Result<(), ContractError> {
        let (magnitude, damaging) = match fact.magnitude() {
            LossMagnitude::Exact(n) => (RetainedMagnitude::Exact(n.get()), n.get() != 0),
            LossMagnitude::AtLeast(n) => (RetainedMagnitude::AtLeast(n.get()), true),
            LossMagnitude::Unknown => (RetainedMagnitude::Unknown, true),
        };
        self.record(
            fact.source(),
            fact.channel(),
            quantity::unit_tag::<U>(),
            RetainedObservation::Loss {
                kind: fact.kind(),
                magnitude,
            },
            damaging,
            affected,
            &mut Attempt::default(),
        )
    }
    /// Retain raw observed/cap as a diagnostic signal, never an event magnitude.
    pub fn record_signal(
        &mut self,
        fact: &CappedLossSignal,
        affected: &[ClaimId],
    ) -> Result<(), ContractError> {
        self.record(
            fact.source(),
            fact.channel(),
            UnitTag::DiagnosticSignals,
            RetainedObservation::Signal {
                observed: fact.observed(),
                cap: fact.cap(),
            },
            fact.observed() != 0,
            affected,
            &mut Attempt::default(),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn record(
        &mut self,
        source: &SourceRef,
        channel: ChannelId,
        unit: UnitTag,
        observation: RetainedObservation,
        damaging: bool,
        affected: &[ClaimId],
        a: &mut Attempt,
    ) -> Result<(), ContractError> {
        if source.epoch() != &self.epoch {
            return Err(ContractError::DomainMismatch);
        }
        validate(affected, self.limits.claims)?;
        let added = affected
            .iter()
            .filter(|&&id| self.claims.binary_search_by_key(&id, |s| s.claim).is_err())
            .count();
        let projected = self
            .claims
            .len()
            .checked_add(added)
            .ok_or(ContractError::CapacityExceeded)?;
        if projected > self.limits.claims {
            return Err(ContractError::CapacityExceeded);
        }
        if self
            .facts
            .len()
            .checked_add(1)
            .ok_or(ContractError::CapacityExceeded)?
            > self.limits.loss_facts
        {
            return Err(ContractError::CapacityExceeded);
        }
        if damaging && !affected.is_empty() && self.limits.reasons_per_claim < 1 {
            return Err(ContractError::CapacityExceeded);
        }
        let mut owned = Vec::new();
        a.reserve(&mut owned, affected.len(), "affected_copy")?;
        owned.extend_from_slice(affected);
        owned.sort_unstable();
        let mut claims = Vec::new();
        a.reserve(&mut claims, projected, "claim_stage")?;
        // CP06: forward merge of two sorted unique inputs. Both cursors only
        // advance; each old claim and each affected ID is emitted exactly once
        // after the O(A log A) affected sort above, so staging work past
        // sorting is O(C + A) for C old claims and A affected IDs. Emission
        // order is sorted by construction, overlaps keep every old row with an
        // OR of the damaging flag, and no entry is shifted or revisited.
        let mut i = 0;
        let mut j = 0;
        while i < self.claims.len() && j < owned.len() {
            match self.claims[i].claim.cmp(&owned[j]) {
                Ordering::Less => {
                    claims.push(self.claims[i].clone());
                    i += 1;
                }
                Ordering::Greater => {
                    claims.push(ClaimState {
                        claim: owned[j],
                        consumed_loss: damaging,
                    });
                    j += 1;
                }
                Ordering::Equal => {
                    let mut merged = self.claims[i].clone();
                    merged.consumed_loss |= damaging;
                    claims.push(merged);
                    i += 1;
                    j += 1;
                }
            }
        }
        claims.extend_from_slice(&self.claims[i..]);
        claims.extend(owned[j..].iter().map(|&id| ClaimState {
            claim: id,
            consumed_loss: damaging,
        }));
        let pending = RetainedFact {
            source: source.clone(),
            channel,
            unit,
            observation,
            affected: owned,
        };
        a.reserve(&mut self.facts, 1, "fact_append")?;
        // CP06_COMMIT: all fallible work precedes these library-owned moves.
        self.facts.push(pending);
        self.claims = claims;
        Ok(())
    }
    /// Return a complete selected-order result without changing this ledger.
    /// Whole-result reason admission precedes output allocation; no prefix escapes.
    /// Normally returned errors preserve logical state, not Vec capacity/address.
    pub fn snapshot(
        &self,
        selected: &[ClaimId],
        overlay: &QueryOverlay,
    ) -> Result<Vec<ClaimAssessment>, ContractError> {
        self.snapshot_attempt(selected, overlay, &mut Attempt::default())
    }
    fn snapshot_attempt(
        &self,
        selected: &[ClaimId],
        overlay: &QueryOverlay,
        a: &mut Attempt,
    ) -> Result<Vec<ClaimAssessment>, ContractError> {
        validate(selected, self.limits.claims)?;
        for &id in selected {
            let (loss, partial) = self.flags(id, overlay);
            if usize::from(loss) + usize::from(partial) > self.limits.reasons_per_claim {
                return Err(ContractError::CapacityExceeded);
            }
        }
        let mut out = Vec::new();
        a.reserve(&mut out, selected.len(), "output_rows")?;
        for &id in selected {
            let (loss, partial) = self.flags(id, overlay);
            let mut reasons = Vec::new();
            a.reserve(
                &mut reasons,
                usize::from(loss) + usize::from(partial),
                "output_reasons",
            )?;
            if loss {
                reasons.push(QualityReason::ConsumedLoss);
            }
            if partial {
                reasons.push(QualityReason::QueryPartial);
            }
            out.push(ClaimAssessment { claim: id, reasons });
        }
        Ok(out)
    }
    fn flags(&self, id: ClaimId, overlay: &QueryOverlay) -> (bool, bool) {
        (
            self.claims
                .binary_search_by_key(&id, |s| s.claim)
                .is_ok_and(|i| self.claims[i].consumed_loss),
            overlay.partial_claims.binary_search(&id).is_ok(),
        )
    }
}
fn validate<T: Eq>(ids: &[T], max: usize) -> Result<(), ContractError> {
    if ids.len() > max {
        return Err(ContractError::CapacityExceeded);
    }
    for i in 0..ids.len() {
        if ids[..i].contains(&ids[i]) {
            return Err(ContractError::DuplicateKey);
        }
    }
    Ok(())
}
// Ephemeral attempt-local test context. Production has no callback, failpoint
// state, global/thread-local hook or public parameter/feature.
#[derive(Default)]
struct Attempt {
    #[cfg(test)]
    fail: Option<&'static str>,
    #[cfg(test)]
    visited: Vec<&'static str>,
}
impl Attempt {
    fn reserve<T>(
        &mut self,
        v: &mut Vec<T>,
        additional: usize,
        _site: &'static str,
    ) -> Result<(), ContractError> {
        v.len()
            .checked_add(additional)
            .and_then(|n| n.checked_mul(std::mem::size_of::<T>()))
            .ok_or(ContractError::CapacityExceeded)?;
        #[cfg(test)]
        let result = {
            self.visited.push(_site);
            if self.fail == Some(_site) {
                Vec::<u8>::new().try_reserve_exact(usize::MAX)
            } else {
                v.try_reserve_exact(additional)
            }
        };
        #[cfg(not(test))]
        let result = v.try_reserve_exact(additional);
        // The injected and ordinary reserve results use this identical mapping.
        result.map_err(|_| ContractError::CapacityExceeded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{BindingId, CaptureId, Origin, ProducerId},
        quantity::*,
    };
    fn epoch() -> Epoch {
        Epoch::new(
            CaptureId::new([1; 16]).unwrap(),
            ProducerId::new([2; 16]).unwrap(),
            0,
        )
    }
    fn source(binding: u8, origin: Origin) -> SourceRef {
        SourceRef::new(epoch(), BindingId::new([binding; 32]).unwrap(), origin)
    }
    fn id(n: u32) -> ClaimId {
        ClaimId::new(n)
    }
    fn exact(channel: u32, value: u64) -> LossFact<Events> {
        LossFact::new(
            source(4, Origin::Synthetic),
            ChannelId::new(channel),
            LossKind::Transport,
            LossMagnitude::Exact(Count::new(value)),
        )
        .unwrap()
    }
    fn ledger() -> ClaimLedger {
        ClaimLedger::new(
            epoch(),
            LedgerLimits {
                claims: 2,
                reasons_per_claim: 2,
                loss_facts: 20,
            },
        )
        .unwrap()
    }
    fn raw_record(
        l: &mut ClaimLedger,
        ids: &[ClaimId],
        a: &mut Attempt,
    ) -> Result<(), ContractError> {
        l.record(
            &source(4, Origin::Synthetic),
            ChannelId::new(0),
            UnitTag::Events,
            RetainedObservation::Loss {
                kind: LossKind::Transport,
                magnitude: RetainedMagnitude::Unknown,
            },
            true,
            ids,
            a,
        )
    }
    #[test]
    fn erased_record_retains_all_tags() {
        let mut l = ledger();
        let mut expected = Vec::new();
        fn row<U: Unit>(
            l: &mut ClaimLedger,
            expected: &mut Vec<RetainedFact>,
            tag: UnitTag,
            binding: u8,
            origin: Origin,
            kind: LossKind,
            m: LossMagnitude<U>,
            want: RetainedMagnitude,
        ) {
            let f = LossFact::new(source(binding, origin), ChannelId::new(0), kind, m).unwrap();
            l.record_loss(&f, &[id(2), id(1)]).unwrap();
            expected.push(RetainedFact {
                source: source(binding, origin),
                channel: ChannelId::new(0),
                unit: tag,
                observation: RetainedObservation::Loss {
                    kind,
                    magnitude: want,
                },
                affected: vec![id(1), id(2)],
            });
            assert_eq!(
                f.source(),
                &source(binding, origin),
                "CP06:borrowed source survives"
            );
        }
        row::<Events>(
            &mut l,
            &mut expected,
            UnitTag::Events,
            4,
            Origin::Synthetic,
            LossKind::Transport,
            LossMagnitude::Exact(Count::new(0)),
            RetainedMagnitude::Exact(0),
        );
        row::<Records>(
            &mut l,
            &mut expected,
            UnitTag::Records,
            5,
            Origin::Replayed,
            LossKind::Discovery,
            LossMagnitude::Exact(Count::new(u64::MAX)),
            RetainedMagnitude::Exact(u64::MAX),
        );
        row::<Bytes>(
            &mut l,
            &mut expected,
            UnitTag::Bytes,
            4,
            Origin::AdapterReported,
            LossKind::Attribution,
            LossMagnitude::AtLeast(Count::new(0)),
            RetainedMagnitude::AtLeast(0),
        );
        row::<Objects>(
            &mut l,
            &mut expected,
            UnitTag::Objects,
            6,
            Origin::Synthetic,
            LossKind::KernelNonexecution,
            LossMagnitude::Unknown,
            RetainedMagnitude::Unknown,
        );
        row::<Attempts>(
            &mut l,
            &mut expected,
            UnitTag::Attempts,
            4,
            Origin::Replayed,
            LossKind::QueueOverflow,
            LossMagnitude::AtLeast(Count::new(1)),
            RetainedMagnitude::AtLeast(1),
        );
        row::<Nonexecutions>(
            &mut l,
            &mut expected,
            UnitTag::Nonexecutions,
            7,
            Origin::AdapterReported,
            LossKind::MalformedInput,
            LossMagnitude::Exact(Count::new(1)),
            RetainedMagnitude::Exact(1),
        );
        row::<DiagnosticSignals>(
            &mut l,
            &mut expected,
            UnitTag::DiagnosticSignals,
            4,
            Origin::Synthetic,
            LossKind::DiagnosticTruncation,
            LossMagnitude::Unknown,
            RetainedMagnitude::Unknown,
        );
        for observed in [0, 255] {
            let f = CappedLossSignal::new(
                source(8, Origin::Replayed),
                ChannelId::new(1),
                observed,
                255,
            )
            .unwrap();
            l.record_signal(&f, &[]).unwrap();
            expected.push(RetainedFact {
                source: source(8, Origin::Replayed),
                channel: ChannelId::new(1),
                unit: UnitTag::DiagnosticSignals,
                observation: RetainedObservation::Signal { observed, cap: 255 },
                affected: vec![],
            });
        }
        let repeated = LossFact::<Events>::new(
            source(4, Origin::Synthetic),
            ChannelId::new(0),
            LossKind::Transport,
            LossMagnitude::Exact(Count::new(0)),
        )
        .unwrap();
        l.record_loss(&repeated, &[id(2), id(1)]).unwrap();
        expected.push(expected[0].clone());
        assert_eq!(
            l.facts, expected,
            "CP06:literal retained tags/order/occurrences"
        );
        assert_eq!(
            l.claims,
            vec![
                ClaimState {
                    claim: id(1),
                    consumed_loss: true
                },
                ClaimState {
                    claim: id(2),
                    consumed_loss: true
                }
            ]
        );
    }
    #[test]
    fn forward_merge_keeps_sorted_survivors_and_overlaps() {
        let mut l = ClaimLedger::new(
            epoch(),
            LedgerLimits {
                claims: 72,
                reasons_per_claim: 2,
                loss_facts: 2,
            },
        )
        .unwrap();
        // Seed 64 pristine high IDs with a non-degrading occurrence so the two
        // overlaps start unconsumed and the merge must apply damage itself.
        let high: Vec<ClaimId> = (64..128).map(id).collect();
        l.record_loss(&exact(0, 0), &high).unwrap();
        assert!(l.claims.iter().all(|s| !s.consumed_loss));
        let earlier = l
            .snapshot(&[id(64), id(127)], &QueryOverlay::new(&[], 72).unwrap())
            .unwrap();
        // Unsorted affected input: eight unseen IDs plus old 67 and 127.
        let affected = vec![
            id(7),
            id(3),
            id(0),
            id(5),
            id(1),
            id(6),
            id(2),
            id(4),
            id(127),
            id(67),
        ];
        l.record_loss(&exact(0, 1), &affected).unwrap();
        let mut want: Vec<ClaimId> = (0..8).map(id).chain((64..128).map(id)).collect();
        want.sort_unstable();
        let got: Vec<ClaimId> = l.claims.iter().map(|s| s.claim).collect();
        assert_eq!(got, want, "CP06:merge keeps every survivor");
        let flag = |n: u32| {
            l.claims
                .iter()
                .find(|s| s.claim == id(n))
                .unwrap()
                .consumed_loss
        };
        for n in (0..8).chain([67, 127]) {
            assert!(flag(n), "CP06:merge applies overlap damage");
        }
        for n in [64, 65, 66, 68, 100, 126] {
            assert!(!flag(n), "CP06:merge keeps old rows intact");
        }
        let fresh = l
            .snapshot(
                &(0..8).map(id).collect::<Vec<_>>(),
                &QueryOverlay::new(&[], 72).unwrap(),
            )
            .unwrap();
        for a in &fresh {
            assert_eq!(
                a.reasons(),
                [QualityReason::ConsumedLoss],
                "CP06:new reasons admitted"
            );
        }
        let mut sorted_affected = affected.clone();
        sorted_affected.sort_unstable();
        assert_eq!(l.facts.len(), 2);
        assert_eq!(
            l.facts[1],
            RetainedFact {
                source: source(4, Origin::Synthetic),
                channel: ChannelId::new(0),
                unit: UnitTag::Events,
                observation: RetainedObservation::Loss {
                    kind: LossKind::Transport,
                    magnitude: RetainedMagnitude::Exact(1),
                },
                affected: sorted_affected,
            },
            "CP06:retained affected set exact"
        );
        assert_eq!(
            earlier,
            vec![
                ClaimAssessment {
                    claim: id(64),
                    reasons: vec![],
                },
                ClaimAssessment {
                    claim: id(127),
                    reasons: vec![],
                },
            ],
            "CP06:earlier assessment stable"
        );
    }
    #[test]
    fn reserve_failures_preserve_all_logical_state() {
        for site in ["affected_copy", "claim_stage", "fact_append"] {
            let mut l = ledger();
            raw_record(&mut l, &[id(1)], &mut Attempt::default()).unwrap();
            let before = (l.facts.clone(), l.claims.clone());
            let input = [id(2), id(1)];
            let mut a = Attempt {
                fail: Some(site),
                ..Attempt::default()
            };
            assert_eq!(
                raw_record(&mut l, &input, &mut a),
                Err(ContractError::CapacityExceeded),
                "CP06:reserve normal capacity"
            );
            assert!(a.visited.contains(&site), "CP06:reserve site reached");
            assert_eq!(
                (&l.facts, &l.claims),
                (&before.0, &before.1),
                "CP06:reserve refuses before publication"
            );
            assert_eq!(input, [id(2), id(1)]);
            raw_record(&mut l, &input, &mut Attempt::default()).unwrap();
            assert_eq!(l.facts.len(), 2);
        }
    }
    #[test]
    fn snapshot_reserves_never_mutate_owner() {
        for site in ["output_rows", "output_reasons"] {
            let mut l = ledger();
            raw_record(&mut l, &[id(1)], &mut Attempt::default()).unwrap();
            let before = (l.facts.clone(), l.claims.clone());
            let overlay = QueryOverlay::new(&[id(2)], 2).unwrap();
            let mut a = Attempt {
                fail: Some(site),
                ..Attempt::default()
            };
            assert_eq!(
                l.snapshot_attempt(&[id(1), id(2)], &overlay, &mut a),
                Err(ContractError::CapacityExceeded),
                "CP06:snapshot reserve capacity"
            );
            assert!(a.visited.contains(&site));
            assert_eq!((&l.facts, &l.claims), (&before.0, &before.1));
            assert!(l.snapshot(&[id(1), id(2)], &overlay).is_ok());
        }
    }
    #[test]
    fn overlay_constructor_reserve_order() {
        let input = [id(1), id(0)];
        let mut a = Attempt {
            fail: Some("overlay_owned_copy"),
            ..Attempt::default()
        };
        assert_eq!(
            QueryOverlay::new_attempt(&input, 2, &mut a),
            Err(ContractError::CapacityExceeded),
            "CP06:overlay reserve maps capacity"
        );
        assert_eq!(a.visited, ["overlay_owned_copy"]);
        assert_eq!(input, [id(1), id(0)]);
        for (input, want) in [
            (vec![id(1), id(0), id(2)], ContractError::CapacityExceeded),
            (vec![id(1), id(1), id(0)], ContractError::CapacityExceeded),
            (vec![id(1), id(1)], ContractError::DuplicateKey),
        ] {
            let mut a = Attempt {
                fail: Some("overlay_owned_copy"),
                ..Attempt::default()
            };
            assert_eq!(
                QueryOverlay::new_attempt(&input, 2, &mut a),
                Err(want),
                "CP06:overlay preflight order"
            );
            assert!(
                a.visited.is_empty(),
                "CP06:no overlay reserve before validation"
            );
        }
        let overlay = QueryOverlay::new(&input, 2).unwrap();
        assert_eq!(overlay.partial_claims, [id(0), id(1)]);
    }
    #[test]
    fn record_checks_precede_reservation() {
        let mut l = ledger();
        for (input, want) in [
            (vec![id(1), id(1), id(0)], ContractError::CapacityExceeded),
            (vec![id(1), id(1)], ContractError::DuplicateKey),
        ] {
            let mut a = Attempt {
                fail: Some("affected_copy"),
                ..Attempt::default()
            };
            assert_eq!(raw_record(&mut l, &input, &mut a), Err(want));
            assert!(
                a.visited.is_empty(),
                "CP06:no record allocation before preflight"
            );
        }
        assert!(l.facts.is_empty());
        assert!(l.claims.is_empty());
    }
    #[test]
    fn snapshot_semantic_refusals_precede_reserves() {
        let mut l = ClaimLedger::new(
            epoch(),
            LedgerLimits {
                claims: 2,
                reasons_per_claim: 1,
                loss_facts: 3,
            },
        )
        .unwrap();
        raw_record(&mut l, &[id(1)], &mut Attempt::default()).unwrap();
        let overlay = QueryOverlay::new(&[id(1)], 2).unwrap();
        let mut a = Attempt {
            fail: Some("output_rows"),
            ..Attempt::default()
        };
        assert_eq!(
            l.snapshot_attempt(&[id(1)], &overlay, &mut a),
            Err(ContractError::CapacityExceeded)
        );
        assert!(
            a.visited.is_empty(),
            "CP06:no snapshot reserve before final reasons"
        );
        for (selected, want) in [
            (vec![id(1), id(1), id(0)], ContractError::CapacityExceeded),
            (vec![id(1), id(1)], ContractError::DuplicateKey),
        ] {
            let mut a = Attempt {
                fail: Some("output_rows"),
                ..Attempt::default()
            };
            assert_eq!(l.snapshot_attempt(&selected, &overlay, &mut a), Err(want));
            assert!(
                a.visited.is_empty(),
                "CP06:no snapshot reserve before selected admission"
            );
        }
        for scenario in 0..3 {
            let mut l = ClaimLedger::new(
                epoch(),
                LedgerLimits {
                    claims: 2,
                    reasons_per_claim: if scenario == 0 { 0 } else { 2 },
                    loss_facts: if scenario == 2 { 1 } else { 3 },
                },
            )
            .unwrap();
            if scenario == 1 {
                raw_record(&mut l, &[id(1), id(2)], &mut Attempt::default()).unwrap();
            }
            if scenario == 2 {
                raw_record(&mut l, &[id(1)], &mut Attempt::default()).unwrap();
            }
            let before = (l.facts.clone(), l.claims.clone());
            let mut a = Attempt {
                fail: Some("affected_copy"),
                ..Attempt::default()
            };
            assert_eq!(
                raw_record(&mut l, &[id(0)], &mut a),
                Err(ContractError::CapacityExceeded)
            );
            assert!(
                a.visited.is_empty(),
                "CP06:no record reserve before projected capacities"
            );
            assert_eq!((&l.facts, &l.claims), (&before.0, &before.1));
        }
    }
    #[test]
    fn ordinary_reserve_error_uses_the_same_capacity_mapping() {
        let mut values = Vec::<u8>::new();
        let mut a = Attempt::default();
        // Deterministic capacity overflow, without allocating usize::MAX bytes.
        assert_eq!(
            a.reserve(&mut values, usize::MAX, "normal_capacity_error"),
            Err(ContractError::CapacityExceeded),
            "CP06:normal reserve maps capacity"
        );
        assert!(values.is_empty());
        assert_eq!(a.visited, ["normal_capacity_error"]);
    }
}
