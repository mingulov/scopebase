// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::*;
use std::sync::Arc;
fn main() {
    let limits = Limits {
        input_bytes: 65536,
        retained_bytes: 131072,
        work_steps: 8388608,
        sites: 0,
        live_links: 0,
        pending_retirements: 0,
    };
    let object = ArtifactId([1; 32]);
    let profile = ProfileId::new("cache-description").unwrap();
    let context = ProbeContext {
        kernel_build: [2; 32],
        btf: None,
        architecture: "x86_64".into(),
        namespace_context: [3; 32],
        security_context: [4; 32],
        topology: [5; 32],
    };
    let record = Arc::new(
        CapabilityObservation::new(
            CapabilityObservationInput {
                object: &object,
                profile: &profile,
                context: &context,
                state: CapabilityState::Unknown,
                stage: EvidenceStage::Metadata,
                hazard: Some(HazardState::Unknown),
                operation: "caller-model",
                step_id: None,
                outcome: ObservationOutcome::Completed,
                error: None,
                reason: b"fixture description",
                diagnostic: b"",
                cause: CauseDescriptionInput {
                    cause: DescribedCause::Unknown,
                    method: "caller-model",
                    evidence_ids: &[],
                },
            },
            &limits,
        )
        .unwrap(),
    );
    let shared = Arc::clone(&record);
    assert!(shared.applies_to(&object, &profile, &context));
    let mut changed = context.clone();
    changed.security_context[0] ^= 1;
    assert!(!record.applies_to(&object, &profile, &changed));
    assert_eq!(record.origin(), ObservationOrigin::CallerDescribed);
    #[cfg(feature = "json")]
    {
        let wire = record.to_json(&limits).unwrap();
        let imported = CapabilityObservation::from_json(&wire, &limits).unwrap();
        assert_eq!(imported.origin(), ObservationOrigin::Imported);
        assert_eq!(imported.reason(), b"fixture description");
        assert!(imported.applies_to(&object, &profile, &context));
        assert_ne!(&imported, record.as_ref());
    }
    println!("descriptive context cache checked; actual environment unknown");
}
