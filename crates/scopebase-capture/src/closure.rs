// SPDX-License-Identifier: Apache-2.0
//! Bounded closure-evidence checking over caller-selected predicate DAGs.
//!
//! NEW for CP09 (T1 model only): no `is_complete()`, no live fence
//! constructor, no sleep/poll/detach/session state. Concept references:
//! MemVeil `src/memveil/capture/stop.mojo` (admission close, writer
//! quiescence, bounded drain, post-drain sample; late submit invalidates
//! the drain and its sample; a deadline never settles quiescence),
//! KryProbe every-program/every-CPU obligations, and the OSSLscope
//! delayed admitted hit. None of those runtimes is qualified here.
//!
//! A [`ClosureProfile`] is a versioned acyclic graph of required
//! predicates; a [`ClosureRecord`] holds bounded same-context
//! observations plus explicit invalidations. [`assess_closure`] reports
//! satisfied/missing/invalidated sets in profile order. Observations of
//! predicates the profile does not require are ignored by assessment:
//! a weaker profile reports only its own predicates. Refusals happen at
//! admission (profile/record/observe/invalidate); assessment over an
//! admitted record is total.
//!
//! Assessment costs O(P*E) time over predicates and edges with O(P)
//! extra storage; no time, thread or cleanup bound is claimed.
use crate::{
    domain::{Epoch, SourceRef},
    ContractError,
};
use std::fmt;

/// Hard cap on required predicates per profile.
const MAX_PROFILE_PREDICATES: usize = 64;

/// A caller-selected closure predicate identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PredicateId(u16);
impl PredicateId {
    /// Construct an identifier; every value is an ordinary predicate label.
    pub fn new(value: u16) -> Self {
        Self(value)
    }
}

/// A caller-supplied boundary serial; orders observations, proves no boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundarySerial(u64);
impl BoundarySerial {
    /// Retain the supplied serial without inferring any boundary occurred.
    pub fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Why a predicate cannot stand in an assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosureGap {
    Missing,
    LateEvidence,
    StaleSample,
    UnresolvedCleanup,
    ContextChanged,
}

/// A versioned acyclic dependency graph over required predicates.
pub struct ClosureProfile {
    version: u32,
    required: Vec<PredicateId>,
    edges: Vec<(PredicateId, PredicateId)>,
}

impl ClosureProfile {
    /// Admit a versioned DAG: nonzero version, at most 64 predicates,
    /// caller limit, duplicate-free required IDs, edges over required
    /// IDs only, no cycles. Duplicate edges dedupe harmlessly.
    pub fn new(
        version: u32,
        required: &[PredicateId],
        before: &[(PredicateId, PredicateId)],
        max_predicates: usize,
    ) -> Result<Self, ContractError> {
        if version == 0 {
            return Err(ContractError::IncompatibleVersion);
        }
        if required.len() > MAX_PROFILE_PREDICATES {
            return Err(ContractError::InvalidProfile);
        }
        if required.len() > max_predicates {
            return Err(ContractError::CapacityExceeded);
        }
        for (index, id) in required.iter().enumerate() {
            if required[..index].contains(id) {
                return Err(ContractError::DuplicateKey);
            }
        }
        let mut edges: Vec<(PredicateId, PredicateId)> = Vec::new();
        for (from, to) in before {
            if !required.contains(from) || !required.contains(to) {
                return Err(ContractError::InvalidProfile);
            }
            if !edges.contains(&(*from, *to)) {
                edges.push((*from, *to));
            }
        }
        // Cycle check over the admitted graph (Kahn's algorithm).
        let profile = Self { version, required: required.to_vec(), edges };
        if profile.has_cycle() {
            return Err(ContractError::InvalidProfile);
        }
        Ok(profile)
    }

    /// The retained profile version; distinct versions never compare equal.
    pub fn version(&self) -> u32 {
        self.version
    }

    fn has_cycle(&self) -> bool {
        // Kahn's algorithm: repeatedly remove nodes with no incoming edge.
        let mut pending: Vec<PredicateId> = self.required.clone();
        loop {
            let free: Vec<PredicateId> = pending
                .iter()
                .filter(|id| {
                    !self
                        .edges
                        .iter()
                        .any(|(from, to)| to == *id && pending.contains(from))
                })
                .copied()
                .collect();
            if free.is_empty() {
                return !pending.is_empty();
            }
            pending.retain(|id| !free.contains(id));
        }
    }
}

/// One reported predicate observation with its source and order metadata.
pub struct PredicateObservation {
    id: PredicateId,
    source: SourceRef,
    serial: BoundarySerial,
    drain_generation: u64,
}

impl PredicateObservation {
    /// Move the supplied report without validating any boundary occurred.
    pub fn new(
        id: PredicateId,
        source: SourceRef,
        serial: BoundarySerial,
        drain_generation: u64,
    ) -> Self {
        Self { id, source, serial, drain_generation }
    }
}

/// Bounded same-context observations plus explicit invalidations.
pub struct ClosureRecord {
    epoch: Epoch,
    source: Option<SourceRef>,
    observations: Vec<PredicateObservation>,
    invalidations: Vec<(PredicateId, ClosureGap)>,
    max_observations: usize,
}

impl ClosureRecord {
    /// Open a record for one epoch with an explicit observation budget.
    /// A zero budget refuses: no observation could ever be admitted.
    pub fn new(epoch: Epoch, max_observations: usize) -> Result<Self, ContractError> {
        if max_observations == 0 {
            return Err(ContractError::CapacityExceeded);
        }
        Ok(Self { epoch, source: None, observations: Vec::new(), invalidations: Vec::new(), max_observations })
    }

    /// Admit one observation: same epoch/binding/origin as the record,
    /// no duplicate predicate, within the shared observation-plus-
    /// invalidation budget. Refusals change nothing.
    pub fn observe(&mut self, item: PredicateObservation) -> Result<(), ContractError> {
        if item.source.epoch() != &self.epoch {
            return Err(ContractError::DomainMismatch);
        }
        if let Some(pinned) = &self.source {
            if pinned.binding() != item.source.binding() || pinned.origin() != item.source.origin() {
                return Err(ContractError::DomainMismatch);
            }
        }
        if self.observations.iter().any(|prior| prior.id == item.id) {
            return Err(ContractError::DuplicateKey);
        }
        if self.observations.len() + self.invalidations.len() >= self.max_observations {
            return Err(ContractError::CapacityExceeded);
        }
        self.source = Some(item.source.clone());
        self.observations.push(item);
        Ok(())
    }

    /// Record late evidence against predicates. Every affected ID is
    /// validated before any mutation: re-invalidation refuses
    /// (`DuplicateKey`) atomically, and invalidations share the record's
    /// admission budget (`CapacityExceeded`).
    pub fn invalidate(
        &mut self,
        affected: &[PredicateId],
        gap: ClosureGap,
    ) -> Result<(), ContractError> {
        for (index, id) in affected.iter().enumerate() {
            if affected[..index].contains(id)
                || self.invalidations.iter().any(|(prior, _)| prior == id)
            {
                return Err(ContractError::DuplicateKey);
            }
        }
        if self.observations.len() + self.invalidations.len() + affected.len() > self.max_observations {
            return Err(ContractError::CapacityExceeded);
        }
        for id in affected {
            self.invalidations.push((*id, gap));
        }
        Ok(())
    }
}

/// The assessed predicate sets plus the record's common source, if any.
///
/// There is deliberately no completeness flag: callers read the three
/// sets. Sets follow profile-required order.
pub struct ClosureAssessment {
    satisfied: Vec<PredicateId>,
    missing: Vec<PredicateId>,
    invalidated: Vec<(PredicateId, ClosureGap)>,
    source: Option<SourceRef>,
}

impl ClosureAssessment {
    /// Required predicates with met ordering/context/dependency proof.
    pub fn satisfied(&self) -> &[PredicateId] {
        &self.satisfied
    }
    /// Required predicates never observed and not invalidated.
    pub fn missing(&self) -> &[PredicateId] {
        &self.missing
    }
    /// Required predicates withheld with their gaps, in profile order.
    pub fn invalidated(&self) -> &[(PredicateId, ClosureGap)] {
        &self.invalidated
    }
    /// The record's common observation source, if anything was observed.
    pub fn source(&self) -> Option<&SourceRef> {
        self.source.as_ref()
    }
}

/// Assess one record against one profile; total over admitted inputs.
///
/// Named invalidations propagate transitively to profile dependents
/// with the caller's gap. A predicate is satisfied when observed, not
/// invalidated, and every prerequisite is satisfied with a strictly
/// smaller serial and equal drain generation. Observed-but-blocked
/// predicates report `Missing` (absent/misordered prerequisite) or
/// `ContextChanged` (drain-generation mismatch). Non-required
/// observations are ignored.
pub fn assess_closure(
    profile: &ClosureProfile,
    record: &ClosureRecord,
) -> Result<ClosureAssessment, ContractError> {
    // Named invalidation closure over profile dependents.
    let mut invalidated: Vec<(PredicateId, ClosureGap)> = Vec::new();
    for id in &profile.required {
        if let Some((_, gap)) = record.invalidations.iter().find(|(named, _)| named == id) {
            invalidated.push((*id, *gap));
        }
    }
    loop {
        let mut added = false;
        for (from, to) in &profile.edges {
            if invalidated.iter().any(|(p, _)| p == from)
                && !invalidated.iter().any(|(p, _)| p == to)
                && profile.required.contains(to)
            {
                let gap = invalidated.iter().find(|(p, _)| p == from).unwrap().1;
                invalidated.push((*to, gap));
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    let observation = |id: &PredicateId| record.observations.iter().find(|o| &o.id == id);
    let is_invalid = |list: &[(PredicateId, ClosureGap)], id: &PredicateId| {
        list.iter().any(|(p, _)| p == id)
    };
    // Satisfaction is recursive over prerequisites; iterative fixpoint
    // over the finite DAG (at most required.len() rounds).
    let mut satisfied: Vec<PredicateId> = Vec::new();
    for _ in 0..profile.required.len().saturating_add(1) {
        let mut added = false;
        for id in &profile.required {
            if satisfied.contains(id) || is_invalid(&invalidated, id) {
                continue;
            }
            let Some(obs) = observation(id) else { continue };
            let mut ok = true;
            for (from, to) in &profile.edges {
                if to != id {
                    continue;
                }
                let Some(prev) = observation(from) else {
                    ok = false;
                    break;
                };
                if !satisfied.contains(from)
                    || prev.serial >= obs.serial
                    || prev.drain_generation != obs.drain_generation
                {
                    ok = false;
                    break;
                }
            }
            if ok {
                satisfied.push(*id);
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    // Observed-but-blocked predicates gain explicit gaps: drain mismatch
    // is ContextChanged, otherwise the prerequisite reads Missing.
    for id in &profile.required {
        if satisfied.contains(id) || is_invalid(&invalidated, id) {
            continue;
        }
        let Some(obs) = observation(id) else { continue };
        let mut gap = ClosureGap::Missing;
        for (from, to) in &profile.edges {
            if to != id {
                continue;
            }
            if let Some(prev) = observation(from) {
                if satisfied.contains(from)
                    && prev.serial < obs.serial
                    && prev.drain_generation != obs.drain_generation
                {
                    gap = ClosureGap::ContextChanged;
                    break;
                }
            }
        }
        invalidated.push((*id, gap));
    }
    // Stable profile order for every set.
    let order = |id: &PredicateId| profile.required.iter().position(|r| r == id).unwrap_or(usize::MAX);
    satisfied.sort_by_key(order);
    invalidated.sort_by_key(|(id, _)| order(id));
    let missing: Vec<PredicateId> = profile
        .required
        .iter()
        .filter(|id| !satisfied.contains(id) && !is_invalid(&invalidated, id))
        .copied()
        .collect();
    Ok(ClosureAssessment { satisfied, missing, invalidated, source: record.source.clone() })
}

impl Clone for ClosureProfile {
    fn clone(&self) -> Self {
        Self { version: self.version, required: self.required.clone(), edges: self.edges.clone() }
    }
}
impl PartialEq for ClosureProfile {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.required == other.required
            && self.edges == other.edges
    }
}
impl Eq for ClosureProfile {}
impl fmt::Debug for ClosureProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClosureProfile")
            .field("version", &self.version)
            .field("required", &self.required)
            .field("edges", &self.edges)
            .finish()
    }
}
impl Clone for PredicateObservation {
    fn clone(&self) -> Self {
        Self { id: self.id, source: self.source.clone(), serial: self.serial, drain_generation: self.drain_generation }
    }
}
impl PartialEq for PredicateObservation {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.source == other.source
            && self.serial == other.serial
            && self.drain_generation == other.drain_generation
    }
}
impl Eq for PredicateObservation {}
impl fmt::Debug for PredicateObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PredicateObservation")
            .field("id", &self.id)
            .field("source", &self.source)
            .field("serial", &self.serial)
            .field("drain_generation", &self.drain_generation)
            .finish()
    }
}
impl Clone for ClosureRecord {
    fn clone(&self) -> Self {
        Self {
            epoch: self.epoch.clone(),
            source: self.source.clone(),
            observations: self.observations.clone(),
            invalidations: self.invalidations.clone(),
            max_observations: self.max_observations,
        }
    }
}
impl PartialEq for ClosureRecord {
    fn eq(&self, other: &Self) -> bool {
        self.epoch == other.epoch
            && self.source == other.source
            && self.observations == other.observations
            && self.invalidations == other.invalidations
            && self.max_observations == other.max_observations
    }
}
impl Eq for ClosureRecord {}
impl fmt::Debug for ClosureRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClosureRecord")
            .field("epoch", &self.epoch)
            .field("source", &self.source)
            .field("observations", &self.observations)
            .field("invalidations", &self.invalidations)
            .finish()
    }
}
impl Clone for ClosureAssessment {
    fn clone(&self) -> Self {
        Self {
            satisfied: self.satisfied.clone(),
            missing: self.missing.clone(),
            invalidated: self.invalidated.clone(),
            source: self.source.clone(),
        }
    }
}
impl PartialEq for ClosureAssessment {
    fn eq(&self, other: &Self) -> bool {
        self.satisfied == other.satisfied
            && self.missing == other.missing
            && self.invalidated == other.invalidated
            && self.source == other.source
    }
}
impl Eq for ClosureAssessment {}
impl fmt::Debug for ClosureAssessment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClosureAssessment")
            .field("satisfied", &self.satisfied)
            .field("missing", &self.missing)
            .field("invalidated", &self.invalidated)
            .finish()
    }
}
