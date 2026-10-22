// SPDX-License-Identifier: Apache-2.0
//! CP09 profiles: versioned predicate DAGs admit bounded observations;
//! assessment reports satisfied/missing/invalidated sets, never completeness.
use scopebase_capture::{
    closure::{
        assess_closure, BoundarySerial, ClosureGap, ClosureProfile, ClosureRecord, PredicateId,
        PredicateObservation,
    },
    domain::{BindingId, CaptureId, Epoch, Origin, ProducerId, SourceRef},
    ContractError,
};

pub fn epoch() -> Epoch {
    Epoch::new(CaptureId::new([1; 16]).unwrap(), ProducerId::new([2; 16]).unwrap(), 0)
}
pub fn source() -> SourceRef {
    SourceRef::new(epoch(), BindingId::new([3; 32]).unwrap(), Origin::AdapterReported)
}
// Local script IDs: 1=baseline 2=admission 3=closed 4=quiescence 5=drain 6=sample.
pub fn pid(n: u16) -> PredicateId {
    PredicateId::new(n)
}
pub fn full_profile() -> ClosureProfile {
    ClosureProfile::new(
        1,
        &[pid(1), pid(2), pid(3), pid(4), pid(5), pid(6)],
        &[
            (pid(1), pid(2)),
            (pid(2), pid(3)),
            (pid(3), pid(4)),
            (pid(4), pid(5)),
            (pid(5), pid(6)),
        ],
        64,
    )
    .unwrap()
}
pub fn observe(record: &mut ClosureRecord, id: u16, serial: u64, drain: u64) {
    record
        .observe(PredicateObservation::new(
            pid(id),
            source(),
            BoundarySerial::new(serial),
            drain,
        ))
        .unwrap();
}

#[test]
fn cycle_duplicate_and_limit_profiles_refuse() {
    // Version zero refuses: no unversioned profile.
    assert_eq!(
        ClosureProfile::new(1 - 1, &[pid(1)], &[], 64),
        Err(ContractError::IncompatibleVersion)
    );
    // Duplicate required IDs refuse.
    assert_eq!(
        ClosureProfile::new(1, &[pid(1), pid(1)], &[], 64),
        Err(ContractError::DuplicateKey)
    );
    // Edges naming unknown predicates refuse.
    assert_eq!(
        ClosureProfile::new(1, &[pid(1)], &[(pid(1), pid(9))], 64),
        Err(ContractError::InvalidProfile)
    );
    assert_eq!(
        ClosureProfile::new(1, &[pid(1)], &[(pid(9), pid(1))], 64),
        Err(ContractError::InvalidProfile)
    );
    // Self-edges and two-cycles refuse.
    assert_eq!(
        ClosureProfile::new(1, &[pid(1)], &[(pid(1), pid(1))], 64),
        Err(ContractError::InvalidProfile)
    );
    assert_eq!(
        ClosureProfile::new(1, &[pid(1), pid(2)], &[(pid(1), pid(2)), (pid(2), pid(1))], 64),
        Err(ContractError::InvalidProfile)
    );
    // Longer cycles refuse.
    assert_eq!(
        ClosureProfile::new(
            1,
            &[pid(1), pid(2), pid(3)],
            &[(pid(1), pid(2)), (pid(2), pid(3)), (pid(3), pid(1))],
            64
        ),
        Err(ContractError::InvalidProfile)
    );
    // Caller limit and the hard 64-predicate cap refuse.
    assert_eq!(
        ClosureProfile::new(1, &[pid(1), pid(2)], &[], 1),
        Err(ContractError::CapacityExceeded)
    );
    let many: Vec<PredicateId> = (0..65).map(pid).collect();
    assert_eq!(
        ClosureProfile::new(1, &many, &[], 128),
        Err(ContractError::InvalidProfile)
    );
    // Exact-64 twin passes; duplicate edges dedupe harmlessly.
    let sixty_four: Vec<PredicateId> = (0..64).map(pid).collect();
    assert!(ClosureProfile::new(1, &sixty_four, &[], 64).is_ok());
    assert!(ClosureProfile::new(1, &[pid(1), pid(2)], &[(pid(1), pid(2)), (pid(1), pid(2))], 64).is_ok());
    // Record construction refuses a zero observation budget.
    assert_eq!(ClosureRecord::new(epoch(), 0), Err(ContractError::CapacityExceeded));
}

#[test]
fn full_script_satisfies_in_order() {
    let profile = full_profile();
    let mut record = ClosureRecord::new(epoch(), 16).unwrap();
    for (id, serial) in [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6)] {
        observe(&mut record, id, serial, 0);
    }
    let seen = assess_closure(&profile, &record).unwrap();
    assert_eq!(seen.satisfied(), &[pid(1), pid(2), pid(3), pid(4), pid(5), pid(6)]);
    assert!(seen.missing().is_empty());
    assert!(seen.invalidated().is_empty());
    assert_eq!(seen.source(), Some(&source()));
    // Empty record: everything missing, no source.
    let bare = ClosureRecord::new(epoch(), 16).unwrap();
    let seen = assess_closure(&profile, &bare).unwrap();
    assert!(seen.satisfied().is_empty());
    assert_eq!(seen.missing(), &[pid(1), pid(2), pid(3), pid(4), pid(5), pid(6)]);
    assert!(seen.invalidated().is_empty());
    assert_eq!(seen.source(), None);
}

#[test]
fn baseline_after_admission_cannot_satisfy_profile() {
    // Startup baseline ordering is checked: baseline serial 2 lands after
    // admission serial 1, so admission's prerequisite is unmet and the
    // whole chain withholds below it.
    let profile = full_profile();
    let mut record = ClosureRecord::new(epoch(), 16).unwrap();
    observe(&mut record, 1, 2, 0);
    observe(&mut record, 2, 1, 0);
    observe(&mut record, 3, 3, 0);
    let seen = assess_closure(&profile, &record).unwrap();
    assert_eq!(seen.satisfied(), &[pid(1)]);
    assert!(!seen.satisfied().contains(&pid(2)));
    assert!(seen.invalidated().iter().any(|(p, _)| *p == pid(2)));
    assert!(!seen.satisfied().contains(&pid(3)));
    // Restored twin: baseline serial 1 before admission serial 2 satisfies.
    let mut twin = ClosureRecord::new(epoch(), 16).unwrap();
    observe(&mut twin, 1, 1, 0);
    observe(&mut twin, 2, 2, 0);
    observe(&mut twin, 3, 3, 0);
    let seen = assess_closure(&profile, &twin).unwrap();
    assert_eq!(seen.satisfied(), &[pid(1), pid(2), pid(3)]);
}

#[test]
fn sample_before_drain_withholds_sample() {
    let profile = full_profile();
    let mut record = ClosureRecord::new(epoch(), 16).unwrap();
    for (id, serial) in [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5)] {
        observe(&mut record, id, serial, 0);
    }
    // Sample serial 4 precedes drain serial 5: drain stands, sample waits.
    observe(&mut record, 6, 4, 0);
    let seen = assess_closure(&profile, &record).unwrap();
    assert!(seen.satisfied().contains(&pid(5)));
    assert!(!seen.satisfied().contains(&pid(6)));
    // Dropped quiescence leaves drain/sample prerequisites unsatisfied.
    let mut record = ClosureRecord::new(epoch(), 16).unwrap();
    for (id, serial) in [(1, 1), (2, 2), (3, 3), (5, 5), (6, 6)] {
        observe(&mut record, id, serial, 0);
    }
    let seen = assess_closure(&profile, &record).unwrap();
    assert_eq!(seen.satisfied(), &[pid(1), pid(2), pid(3)]);
    assert_eq!(seen.missing(), &[pid(4)]);
}

#[test]
fn drain_generation_must_agree_across_dependencies() {
    let profile = full_profile();
    let mut record = ClosureRecord::new(epoch(), 16).unwrap();
    for (id, serial) in [(1, 1), (2, 2), (3, 3), (4, 4)] {
        observe(&mut record, id, serial, 0);
    }
    // Drain from a newer generation cannot settle the older sample line.
    observe(&mut record, 5, 5, 1);
    observe(&mut record, 6, 6, 0);
    let seen = assess_closure(&profile, &record).unwrap();
    assert!(!seen.satisfied().contains(&pid(5)));
    assert!(seen.invalidated().iter().any(|(p, g)| *p == pid(5) && *g == ClosureGap::ContextChanged));
    assert!(!seen.satisfied().contains(&pid(6)));
}

#[test]
fn foreign_epoch_or_origin_refuses() {
    let mut record = ClosureRecord::new(epoch(), 16).unwrap();
    observe(&mut record, 1, 1, 0);
    // Foreign epoch refuses.
    let foreign_epoch = Epoch::new(
        CaptureId::new([9; 16]).unwrap(),
        ProducerId::new([2; 16]).unwrap(),
        0,
    );
    assert_eq!(
        record.observe(PredicateObservation::new(
            pid(2),
            SourceRef::new(foreign_epoch, BindingId::new([3; 32]).unwrap(), Origin::AdapterReported),
            BoundarySerial::new(2),
            0
        )),
        Err(ContractError::DomainMismatch)
    );
    // Foreign binding refuses.
    assert_eq!(
        record.observe(PredicateObservation::new(
            pid(2),
            SourceRef::new(epoch(), BindingId::new([8; 32]).unwrap(), Origin::AdapterReported),
            BoundarySerial::new(2),
            0
        )),
        Err(ContractError::DomainMismatch)
    );
    // Relabeled origin refuses: synthetic/replayed history cannot be
    // promoted into this adapter-reported record.
    for origin in [Origin::Synthetic, Origin::Replayed] {
        assert_eq!(
            record.observe(PredicateObservation::new(
                pid(2),
                SourceRef::new(epoch(), BindingId::new([3; 32]).unwrap(), origin),
                BoundarySerial::new(2),
                0
            )),
            Err(ContractError::DomainMismatch)
        );
    }
    // Refusals are atomic: only baseline stands, and the valid twin passes.
    let seen = assess_closure(&full_profile(), &record).unwrap();
    assert_eq!(seen.satisfied(), &[pid(1)]);
    observe(&mut record, 2, 2, 0);
    let seen = assess_closure(&full_profile(), &record).unwrap();
    assert_eq!(seen.satisfied(), &[pid(1), pid(2)]);
    // Duplicate predicate observation refuses; capacity refuses.
    assert_eq!(
        record.observe(PredicateObservation::new(pid(1), source(), BoundarySerial::new(9), 0)),
        Err(ContractError::DuplicateKey)
    );
    let mut small = ClosureRecord::new(epoch(), 1).unwrap();
    observe(&mut small, 1, 1, 0);
    assert_eq!(
        small.observe(PredicateObservation::new(pid(2), source(), BoundarySerial::new(2), 0)),
        Err(ContractError::CapacityExceeded)
    );
    // Re-invalidation refuses atomically: the refused call records
    // nothing, so the assessment before and after is identical (6 stays
    // transitively invalidated from 5 either way, never newly named).
    let mut record = ClosureRecord::new(epoch(), 16).unwrap();
    observe(&mut record, 5, 5, 0);
    record.invalidate(&[pid(5)], ClosureGap::LateEvidence).unwrap();
    let before = assess_closure(&full_profile(), &record).unwrap();
    assert_eq!(
        record.invalidate(&[pid(5), pid(6)], ClosureGap::LateEvidence),
        Err(ContractError::DuplicateKey)
    );
    let after = assess_closure(&full_profile(), &record).unwrap();
    assert_eq!(before, after);
}

#[test]
fn profile_versions_stay_distinguishable() {
    // The versioned-DAG contract: the admitted version is retained, so the
    // same graph admitted under v1 and v2 never compares equal.
    let v1 = ClosureProfile::new(1, &[pid(1), pid(2)], &[(pid(1), pid(2))], 64).unwrap();
    let v2 = ClosureProfile::new(2, &[pid(1), pid(2)], &[(pid(1), pid(2))], 64).unwrap();
    assert_eq!(v1.version(), 1);
    assert_eq!(v2.version(), 2);
    assert_ne!(v1, v2);
    assert_eq!(v1, ClosureProfile::new(1, &[pid(1), pid(2)], &[(pid(1), pid(2))], 64).unwrap());
}

#[test]
fn observation_and_invalidation_share_one_budget() {
    // The record admission budget covers observations plus invalidations.
    // Observations filling the budget leave no room for invalidation.
    let mut full = ClosureRecord::new(epoch(), 2).unwrap();
    observe(&mut full, 1, 1, 0);
    observe(&mut full, 2, 2, 0);
    assert_eq!(
        full.invalidate(&[pid(3)], ClosureGap::LateEvidence),
        Err(ContractError::CapacityExceeded)
    );
    // And the reverse: invalidations filling the budget refuse observation.
    let mut invalidated = ClosureRecord::new(epoch(), 2).unwrap();
    invalidated.invalidate(&[pid(1), pid(2)], ClosureGap::LateEvidence).unwrap();
    assert_eq!(
        invalidated.observe(PredicateObservation::new(pid(3), source(), BoundarySerial::new(3), 0)),
        Err(ContractError::CapacityExceeded)
    );
    // Exactly at the boundary, a shared remainder still admits.
    let mut room = ClosureRecord::new(epoch(), 2).unwrap();
    observe(&mut room, 1, 1, 0);
    room.invalidate(&[pid(2)], ClosureGap::LateEvidence).unwrap();
}
