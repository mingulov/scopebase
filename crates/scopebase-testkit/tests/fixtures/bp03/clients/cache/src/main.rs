// SPDX-License-Identifier: Apache-2.0
//! Independent cache caller: its context key is application-owned fixed data.
use scopebase_bpf::*;
use scopebase_testkit::bpf::{profile_from_testkit, profile_to_testkit};
use std::{path::Path, sync::Arc};
fn limits() -> Limits {
    Limits {
        input_bytes: 65536,
        retained_bytes: 131072,
        work_steps: 8388608,
        sites: 0,
        live_links: 0,
        pending_retirements: 0,
    }
}
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    assert_eq!(args.len(), 2);
    let package = Path::new(&args[0]);
    let json = args[1] == "json-union";
    let mut completed = Vec::<&str>::new();
    let object = ArtifactId([9; 32]);
    let profile = ProfileId::new("cache-v1").unwrap();
    let context = ProbeContext {
        kernel_build: [1; 32],
        btf: Some(ArtifactId([0; 32])),
        architecture: "x86_64".into(),
        namespace_context: [2; 32],
        security_context: [3; 32],
        topology: [4; 32],
    };
    let cache = Arc::new(
        CapabilityObservation::new(
            CapabilityObservationInput {
                object: &object,
                profile: &profile,
                context: &context,
                state: CapabilityState::Unknown,
                stage: EvidenceStage::Metadata,
                hazard: Some(HazardState::Affected),
                operation: "cache-observation",
                step_id: None,
                outcome: ObservationOutcome::Incomplete,
                error: None,
                reason: &[0, 255, 10],
                diagnostic: &[128, 0],
                cause: CauseDescriptionInput {
                    cause: DescribedCause::Unknown,
                    method: "cache-model",
                    evidence_ids: &["cache-input"],
                },
            },
            &limits(),
        )
        .unwrap(),
    );
    let references = [Arc::clone(&cache), Arc::clone(&cache)];
    assert_eq!(Arc::strong_count(&cache), 3);
    for record in &references {
        assert_eq!(record.reason(), &[0, 255, 10], "description.fields");
        assert_eq!(record.diagnostic(), &[128, 0]);
        assert_eq!(record.hazard(), Some(HazardState::Affected));
        assert_eq!(record.state(), CapabilityState::Unknown);
        assert_eq!(record.origin(), ObservationOrigin::CallerDescribed);
        assert!(record.applies_to(&object, &profile, &context));
    }
    let mut current = context.clone();
    current.security_context[0] ^= 1;
    assert!(
        !cache.applies_to(&object, &profile, &current),
        "context.applies cache invalidation"
    );
    let received = profile_to_testkit(&profile).unwrap();
    assert_eq!(received.as_str(), "cache-v1");
    assert_eq!(profile_from_testkit(&received).unwrap(), profile);
    assert_eq!(
        profile_to_testkit(&ProfileId::new("cache/scoped").unwrap()).unwrap_err(),
        scopebase_testkit::IdError::InvalidCharacter
    );
    let upper = scopebase_testkit::ProfileId::parse("Cache").unwrap();
    let error = profile_from_testkit(&upper).unwrap_err();
    assert_eq!(
        (error.kind(), error.stage()),
        (ErrorKind::InvalidInput, Stage::Admission)
    );
    #[cfg(feature = "json")]
    {
        if json {
            let bytes =
                std::fs::read(package.join("fixtures/capability-v1/codec/valid-base.bytes"))
                    .unwrap();
            let imported = CapabilityObservation::from_json(&bytes, &limits()).unwrap();
            assert_eq!(
                imported.origin(),
                ObservationOrigin::Imported,
                "origin.imported"
            );
            assert_eq!(
                imported.claimed_origin(),
                ObservationOrigin::CallerDescribed
            );
            assert_eq!(
                imported.reason(),
                &[0, 10, 127, 255],
                "description.fields imported bytes"
            );
            assert_eq!(imported.diagnostic(), &[0, 101, 97, 99, 99, 101, 115, 255]);
            assert_eq!(imported.operation_error().unwrap().stage(), Stage::Execute);
            assert_eq!(imported.stage(), EvidenceStage::Load);
            assert_eq!(imported.cause(), DescribedCause::Permission);
            assert_eq!(imported.object(), &ArtifactId([1; 32]));
            assert_eq!(imported.profile().as_str(), "bpf-host-v1");
            assert_eq!(imported.context().kernel_build, [0x11; 32]);
            assert_eq!(imported.context().btf, Some(ArtifactId([0x22; 32])));
            assert_eq!(imported.context().architecture, "x86_64");
            assert_eq!(imported.context().namespace_context, [0x33; 32]);
            assert_eq!(imported.context().security_context, [0x44; 32]);
            assert_eq!(imported.context().topology, [0x55; 32]);
            assert_eq!(imported.state(), CapabilityState::Denied);
            assert_eq!(imported.hazard(), Some(HazardState::Clean));
            assert_eq!(imported.operation(), "BPF_PROG_LOAD");
            assert_eq!(imported.step_id(), Some("load"));
            assert_eq!(imported.outcome(), ObservationOutcome::Refused);
            assert_eq!(
                imported.operation_error().unwrap().kind(),
                ErrorKind::Denied
            );
            assert_eq!(imported.operation_error().unwrap().raw_os_error(), Some(13));
            assert_eq!(
                imported.operation_error().unwrap().required_size(),
                Some(128)
            );
            assert_eq!(imported.cause_method(), "caller-description");
            assert_eq!(
                imported.cause_evidence_ids(),
                &["model-evidence-a", "model-evidence-b"]
            );
            completed.push("cache.json-import-fields-origin");
            assert_eq!(imported.to_json(&limits()).unwrap(), bytes);
            completed.push("cache.json-reencode-literal");
        }
    }
    #[cfg(not(feature = "json"))]
    {
        let _ = package;
    }
    completed.sort_unstable();
    println!(
        "BP03_COMPLETION {{\"client\":\"bp03-cache\",\"groups\":[{}]}}",
        completed
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("bp03-cache: direct checked context/getter/ID{} assertions passed; actual environment unknown",if json{"/JSON"}else{""});
}
