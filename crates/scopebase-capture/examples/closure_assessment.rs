// SPDX-License-Identifier: Apache-2.0
//! Closure profiles: ordered satisfaction, transitive invalidation, and no
//! completeness flag. Callers read the three sets, not a single verdict.
//! NEW (CP11): reference-only; no donor lines copied.
use scopebase_capture::{
    closure::{
        assess_closure, BoundarySerial, ClosureGap, ClosureProfile, ClosureRecord, PredicateId,
        PredicateObservation,
    },
    domain::{BindingId, CaptureId, Epoch, Origin, ProducerId, SourceRef},
    ContractError,
};

fn main() -> Result<(), ContractError> {
    let epoch = Epoch::new(CaptureId::new([51; 16])?, ProducerId::new([52; 16])?, 0);
    let source = SourceRef::new(epoch.clone(), BindingId::new([53; 32])?, Origin::Synthetic);
    let profile = ClosureProfile::new(
        1,
        &[PredicateId::new(0), PredicateId::new(1)],
        &[(PredicateId::new(0), PredicateId::new(1))],
        8,
    )?;
    let mut record = ClosureRecord::new(epoch, 8)?;
    record.observe(PredicateObservation::new(
        PredicateId::new(0),
        source.clone(),
        BoundarySerial::new(0),
        0,
    ))?;
    record.observe(PredicateObservation::new(
        PredicateId::new(1),
        source,
        BoundarySerial::new(1),
        0,
    ))?;
    let assessment = assess_closure(&profile, &record)?;
    assert_eq!(
        assessment.satisfied(),
        &[PredicateId::new(0), PredicateId::new(1)]
    );
    assert!(assessment.missing().is_empty());
    assert!(assessment.invalidated().is_empty());
    println!(
        "satisfied: {:?} missing: {:?} invalidated: {:?}",
        assessment.satisfied(),
        assessment.missing(),
        assessment.invalidated()
    );
    // Late evidence against the prerequisite invalidates its dependent too.
    record.invalidate(&[PredicateId::new(0)], ClosureGap::LateEvidence)?;
    let assessment = assess_closure(&profile, &record)?;
    assert!(assessment.satisfied().is_empty());
    assert_eq!(assessment.invalidated().len(), 2);
    println!(
        "after late evidence: invalidated {:?}",
        assessment.invalidated()
    );
    Ok(())
}
