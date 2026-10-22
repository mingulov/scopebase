// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::*;
use std::error::Error;
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
#[test]
fn strict_literal_codec_corpus() {
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/valid-base.bytes"),
        &limits(),
    );
    let value = result.expect("json.result valid-base");
    assert_eq!(
        value.origin(),
        ObservationOrigin::Imported,
        "origin.imported"
    );
    assert_eq!(value.claimed_origin(), ObservationOrigin::CallerDescribed);
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/valid-reordered.bytes"),
        &limits(),
    );
    let value = result.expect("json.result valid-reordered");
    assert_eq!(
        value.origin(),
        ObservationOrigin::Imported,
        "origin.imported"
    );
    assert_eq!(value.claimed_origin(), ObservationOrigin::CallerDescribed);
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/valid-whitespace.bytes"),
        &limits(),
    );
    let value = result.expect("json.result valid-whitespace");
    assert_eq!(
        value.origin(),
        ObservationOrigin::Imported,
        "origin.imported"
    );
    assert_eq!(value.claimed_origin(), ObservationOrigin::CallerDescribed);
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/duplicate-plus-version-first.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result duplicate-plus-version-first");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Malformed, Stage::Inspect, None, None),
        "json.result duplicate-plus-version-first"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/unknown-plus-version-first.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result unknown-plus-version-first");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Malformed, Stage::Inspect, None, None),
        "json.result unknown-plus-version-first"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/version-plus-bad-enum-hex-first.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result version-plus-bad-enum-hex-first");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Unsupported, Stage::Inspect, None, None),
        "json.result version-plus-bad-enum-hex-first"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/missing-null-plus-version-first.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result missing-null-plus-version-first");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Malformed, Stage::Inspect, None, None),
        "json.result missing-null-plus-version-first"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/version-plus-errno-overflow-first.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result version-plus-errno-overflow-first");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Unsupported, Stage::Inspect, None, None),
        "json.result version-plus-errno-overflow-first"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/duplicate-plus-version-last.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result duplicate-plus-version-last");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Malformed, Stage::Inspect, None, None),
        "json.result duplicate-plus-version-last"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/unknown-plus-version-last.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result unknown-plus-version-last");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Malformed, Stage::Inspect, None, None),
        "json.result unknown-plus-version-last"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/version-plus-bad-enum-hex-last.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result version-plus-bad-enum-hex-last");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Unsupported, Stage::Inspect, None, None),
        "json.result version-plus-bad-enum-hex-last"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/missing-null-plus-version-last.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result missing-null-plus-version-last");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Malformed, Stage::Inspect, None, None),
        "json.result missing-null-plus-version-last"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/version-plus-errno-overflow-last.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result version-plus-errno-overflow-last");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Unsupported, Stage::Inspect, None, None),
        "json.result version-plus-errno-overflow-last"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/bad-enum.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result bad-enum");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Malformed, Stage::Inspect, None, None),
        "json.result bad-enum"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/bad-hex.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result bad-hex");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Malformed, Stage::Inspect, None, None),
        "json.result bad-hex"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/errno-overflow.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result errno-overflow");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Overflow, Stage::Inspect, None, None),
        "json.result errno-overflow"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/required-size-overflow.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result required-size-overflow");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Overflow, Stage::Inspect, None, None),
        "json.result required-size-overflow"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/noncanonical-decimal.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result noncanonical-decimal");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Malformed, Stage::Inspect, None, None),
        "json.result noncanonical-decimal"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/escaped-profile-alias.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result escaped-profile-alias");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Malformed, Stage::Inspect, None, None),
        "json.result escaped-profile-alias"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/invalid-utf8.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result invalid-utf8");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Malformed, Stage::Inspect, None, None),
        "json.result invalid-utf8"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/trailing-value.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result trailing-value");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Malformed, Stage::Inspect, None, None),
        "json.result trailing-value"
    );
    assert!(error.source().is_none());
    let result = CapabilityObservation::from_json(
        include_bytes!("../fixtures/capability-v1/codec/too-many-evidence-ids.bytes"),
        &limits(),
    );
    let error = result.expect_err("json.result too-many-evidence-ids");
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::LimitExceeded, Stage::Inspect, None, None),
        "json.result too-many-evidence-ids"
    );
    assert!(error.source().is_none());
}
#[test]
fn canonical_literal_and_codec_budgets() {
    let raw = include_bytes!("../fixtures/capability-v1/codec/valid-base.bytes");
    assert_eq!(raw.len(), 1026);
    let value = CapabilityObservation::from_json(raw, &limits()).unwrap();
    let encoded = value.to_json(&limits()).unwrap();
    assert_eq!(&encoded[..], raw);
    let mut l = limits();
    l.input_bytes = 1025;
    l.work_steps = 0;
    let e = value.to_json(&l).unwrap_err();
    assert_eq!(
        (e.kind(), e.stage(), e.required_size()),
        (ErrorKind::LimitExceeded, Stage::Inspect, Some(1026))
    );
    l.input_bytes = 1026;
    let e = value.to_json(&l).unwrap_err();
    assert_eq!(
        (e.kind(), e.required_size()),
        (ErrorKind::LimitExceeded, None)
    );
    l.work_steps = 33856;
    let m = value.retained_bytes() + std::mem::size_of::<Vec<u8>>() + 1026;
    l.retained_bytes = m - 1;
    let e = value.to_json(&l).unwrap_err();
    assert_eq!(
        (e.kind(), e.required_size()),
        (ErrorKind::LimitExceeded, Some(m))
    );
    l.retained_bytes = m;
    assert_eq!(value.to_json(&l).unwrap(), raw);
    let e = CapabilityObservation::from_json(
        raw,
        &Limits {
            work_steps: 33855,
            ..limits()
        },
    )
    .unwrap_err();
    assert_eq!(
        (e.kind(), e.stage(), e.required_size()),
        (ErrorKind::LimitExceeded, Stage::Inspect, None)
    );
}
#[test]
fn repeated_import_keeps_local_imported() {
    let raw = include_bytes!("../fixtures/capability-v1/codec/valid-base.bytes");
    let v = CapabilityObservation::from_json(raw, &limits()).unwrap();
    let again =
        CapabilityObservation::from_json(&v.to_json(&limits()).unwrap(), &limits()).unwrap();
    assert_eq!(again.origin(), ObservationOrigin::Imported);
    assert_eq!(again.claimed_origin(), ObservationOrigin::CallerDescribed);
    assert_eq!(again, v);
}
fn assert_literal_getters(
    v: &CapabilityObservation,
    state: CapabilityState,
    cause: DescribedCause,
    errno: i32,
    bp_stage: Stage,
) {
    assert_eq!(
        v.object(),
        &ArtifactId([1; 32]),
        "description.fields object"
    );
    assert_eq!(v.profile().as_str(), "bpf-host-v1");
    assert_eq!(v.context().kernel_build, [0x11; 32]);
    assert_eq!(v.context().btf, Some(ArtifactId([0x22; 32])));
    assert_eq!(v.context().architecture, "x86_64");
    assert_eq!(v.context().namespace_context, [0x33; 32]);
    assert_eq!(v.context().security_context, [0x44; 32]);
    assert_eq!(v.context().topology, [0x55; 32]);
    assert_eq!(v.state(), state, "description.fields state");
    assert_eq!(
        v.stage(),
        EvidenceStage::Load,
        "description.fields evidence stage"
    );
    assert_eq!(v.hazard(), Some(HazardState::Clean));
    assert_eq!(v.operation(), "BPF_PROG_LOAD");
    assert_eq!(v.step_id(), Some("load"));
    assert_eq!(v.outcome(), ObservationOutcome::Refused);
    let error = v.operation_error().unwrap();
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (ErrorKind::Denied, bp_stage, Some(errno), Some(128)),
        "description.fields original error"
    );
    assert_eq!(v.reason(), &[0, 10, 127, 255], "description.fields reason");
    assert_eq!(
        v.diagnostic(),
        &[0, 101, 97, 99, 99, 101, 115, 255],
        "description.fields diagnostic"
    );
    assert_eq!(v.cause(), cause, "description.fields cause");
    assert_eq!(v.cause_method(), "caller-description");
    assert_eq!(
        v.cause_evidence_ids(),
        &["model-evidence-a", "model-evidence-b"]
    );
}
#[test]
fn imported_getters_are_independent_of_roundtrip() {
    let raw = include_bytes!("../fixtures/capability-v1/codec/valid-base.bytes");
    for bytes in [
        &raw[..],
        include_bytes!("../fixtures/capability-v1/codec/valid-reordered.bytes"),
        include_bytes!("../fixtures/capability-v1/codec/valid-whitespace.bytes"),
    ] {
        let v = CapabilityObservation::from_json(bytes, &limits()).unwrap();
        assert_literal_getters(
            &v,
            CapabilityState::Denied,
            DescribedCause::Permission,
            13,
            Stage::Execute,
        );
    }
}
#[test]
fn origin_is_local_and_claim_is_preserved() {
    let object = ArtifactId([1; 32]);
    let profile = ProfileId::new("bpf-host-v1").unwrap();
    let context = ProbeContext {
        kernel_build: [0x11; 32],
        btf: Some(ArtifactId([0x22; 32])),
        architecture: "x86_64".into(),
        namespace_context: [0x33; 32],
        security_context: [0x44; 32],
        topology: [0x55; 32],
    };
    let local = CapabilityObservation::new(
        CapabilityObservationInput {
            object: &object,
            profile: &profile,
            context: &context,
            state: CapabilityState::Denied,
            stage: EvidenceStage::Load,
            hazard: Some(HazardState::Clean),
            operation: "BPF_PROG_LOAD",
            step_id: Some("load"),
            outcome: ObservationOutcome::Refused,
            error: Some(OperationErrorSnapshot::from_error(
                &OperationError::new(ErrorKind::Denied, Stage::Execute, Some(13), None)
                    .with_required_size(128),
            )),
            reason: &[0, 10, 127, 255],
            diagnostic: &[0, 101, 97, 99, 99, 101, 115, 255],
            cause: CauseDescriptionInput {
                cause: DescribedCause::Permission,
                method: "caller-description",
                evidence_ids: &["model-evidence-a", "model-evidence-b"],
            },
        },
        &limits(),
    )
    .unwrap();
    assert_eq!(
        (local.origin(), local.claimed_origin()),
        (
            ObservationOrigin::CallerDescribed,
            ObservationOrigin::CallerDescribed
        )
    );
    let literal = std::str::from_utf8(include_bytes!(
        "../fixtures/capability-v1/codec/valid-base.bytes"
    ))
    .unwrap();
    for (claim, origin) in [
        ("caller_described", ObservationOrigin::CallerDescribed),
        ("imported", ObservationOrigin::Imported),
    ] {
        let bytes = literal.replace(
            "\"claimed_origin\":\"caller_described\"",
            &format!("\"claimed_origin\":\"{claim}\""),
        );
        let imported = CapabilityObservation::from_json(bytes.as_bytes(), &limits()).unwrap();
        assert_literal_getters(
            &imported,
            CapabilityState::Denied,
            DescribedCause::Permission,
            13,
            Stage::Execute,
        );
        assert_eq!(
            imported.origin(),
            ObservationOrigin::Imported,
            "origin.imported"
        );
        assert_eq!(imported.claimed_origin(), origin, "origin.claim-preserved");
        assert_ne!(imported, local, "origin.local-equality");
        assert!(imported.applies_to(&object, &profile, &context));
        let again =
            CapabilityObservation::from_json(&imported.to_json(&limits()).unwrap(), &limits())
                .unwrap();
        assert_eq!(again, imported);
        assert_eq!(again.claimed_origin(), origin);
    }
}
#[test]
fn imported_stages_remain_separate() {
    let literal = std::str::from_utf8(include_bytes!(
        "../fixtures/capability-v1/codec/valid-base.bytes"
    ))
    .unwrap();
    for (name, stage) in [
        ("execute", Stage::Execute),
        ("allocate", Stage::Allocate),
        ("inspect", Stage::Inspect),
    ] {
        let bytes = literal.replace("\"stage\":\"execute\"", &format!("\"stage\":\"{name}\""));
        let v = CapabilityObservation::from_json(bytes.as_bytes(), &limits()).unwrap();
        assert_literal_getters(
            &v,
            CapabilityState::Denied,
            DescribedCause::Permission,
            13,
            stage,
        );
    }
}
#[test]
fn same_errno_descriptions_are_not_classified() {
    let v=CapabilityObservation::from_json(br#"{"schema_version":1,"kind":"scopebase-bpf-capability-observation","schema_revision":1,"claimed_origin":"caller_described","object":"0101010101010101010101010101010101010101010101010101010101010101","profile":"bpf-host-v1","context":{"kernel_build":"1111111111111111111111111111111111111111111111111111111111111111","btf":"2222222222222222222222222222222222222222222222222222222222222222","architecture":"x86_64","namespace_context":"3333333333333333333333333333333333333333333333333333333333333333","security_context":"4444444444444444444444444444444444444444444444444444444444444444","topology":"5555555555555555555555555555555555555555555555555555555555555555"},"state":"denied","stage":"load","hazard":"clean","operation":"BPF_PROG_LOAD","step_id":"load","outcome":"refused","error":{"kind":"denied","stage":"execute","raw_errno":1,"required_size":"128"},"reason":"000a7fff","diagnostic":"00656163636573ff","cause":{"kind":"permission","method":"caller-description","evidence_ids":["model-evidence-a","model-evidence-b"]}}"#,&limits()).unwrap();
    assert_literal_getters(
        &v,
        CapabilityState::Denied,
        DescribedCause::Permission,
        1,
        Stage::Execute,
    );
    let v=CapabilityObservation::from_json(br#"{"schema_version":1,"kind":"scopebase-bpf-capability-observation","schema_revision":1,"claimed_origin":"caller_described","object":"0101010101010101010101010101010101010101010101010101010101010101","profile":"bpf-host-v1","context":{"kernel_build":"1111111111111111111111111111111111111111111111111111111111111111","btf":"2222222222222222222222222222222222222222222222222222222222222222","architecture":"x86_64","namespace_context":"3333333333333333333333333333333333333333333333333333333333333333","security_context":"4444444444444444444444444444444444444444444444444444444444444444","topology":"5555555555555555555555555555555555555555555555555555555555555555"},"state":"incompatible","stage":"load","hazard":"clean","operation":"BPF_PROG_LOAD","step_id":"load","outcome":"refused","error":{"kind":"denied","stage":"execute","raw_errno":1,"required_size":"128"},"reason":"000a7fff","diagnostic":"00656163636573ff","cause":{"kind":"verifier","method":"caller-description","evidence_ids":["model-evidence-a","model-evidence-b"]}}"#,&limits()).unwrap();
    assert_literal_getters(
        &v,
        CapabilityState::Incompatible,
        DescribedCause::Verifier,
        1,
        Stage::Execute,
    );
    let v=CapabilityObservation::from_json(br#"{"schema_version":1,"kind":"scopebase-bpf-capability-observation","schema_revision":1,"claimed_origin":"caller_described","object":"0101010101010101010101010101010101010101010101010101010101010101","profile":"bpf-host-v1","context":{"kernel_build":"1111111111111111111111111111111111111111111111111111111111111111","btf":"2222222222222222222222222222222222222222222222222222222222222222","architecture":"x86_64","namespace_context":"3333333333333333333333333333333333333333333333333333333333333333","security_context":"4444444444444444444444444444444444444444444444444444444444444444","topology":"5555555555555555555555555555555555555555555555555555555555555555"},"state":"incompatible","stage":"load","hazard":"clean","operation":"BPF_PROG_LOAD","step_id":"load","outcome":"refused","error":{"kind":"denied","stage":"execute","raw_errno":1,"required_size":"128"},"reason":"000a7fff","diagnostic":"00656163636573ff","cause":{"kind":"license","method":"caller-description","evidence_ids":["model-evidence-a","model-evidence-b"]}}"#,&limits()).unwrap();
    assert_literal_getters(
        &v,
        CapabilityState::Incompatible,
        DescribedCause::License,
        1,
        Stage::Execute,
    );
    let v=CapabilityObservation::from_json(br#"{"schema_version":1,"kind":"scopebase-bpf-capability-observation","schema_revision":1,"claimed_origin":"caller_described","object":"0101010101010101010101010101010101010101010101010101010101010101","profile":"bpf-host-v1","context":{"kernel_build":"1111111111111111111111111111111111111111111111111111111111111111","btf":"2222222222222222222222222222222222222222222222222222222222222222","architecture":"x86_64","namespace_context":"3333333333333333333333333333333333333333333333333333333333333333","security_context":"4444444444444444444444444444444444444444444444444444444444444444","topology":"5555555555555555555555555555555555555555555555555555555555555555"},"state":"unsupported","stage":"load","hazard":"clean","operation":"BPF_PROG_LOAD","step_id":"load","outcome":"refused","error":{"kind":"denied","stage":"execute","raw_errno":1,"required_size":"128"},"reason":"000a7fff","diagnostic":"00656163636573ff","cause":{"kind":"unsupported_operation","method":"caller-description","evidence_ids":["model-evidence-a","model-evidence-b"]}}"#,&limits()).unwrap();
    assert_literal_getters(
        &v,
        CapabilityState::Unsupported,
        DescribedCause::UnsupportedOperation,
        1,
        Stage::Execute,
    );
    let v=CapabilityObservation::from_json(br#"{"schema_version":1,"kind":"scopebase-bpf-capability-observation","schema_revision":1,"claimed_origin":"caller_described","object":"0101010101010101010101010101010101010101010101010101010101010101","profile":"bpf-host-v1","context":{"kernel_build":"1111111111111111111111111111111111111111111111111111111111111111","btf":"2222222222222222222222222222222222222222222222222222222222222222","architecture":"x86_64","namespace_context":"3333333333333333333333333333333333333333333333333333333333333333","security_context":"4444444444444444444444444444444444444444444444444444444444444444","topology":"5555555555555555555555555555555555555555555555555555555555555555"},"state":"unknown","stage":"load","hazard":"clean","operation":"BPF_PROG_LOAD","step_id":"load","outcome":"refused","error":{"kind":"denied","stage":"execute","raw_errno":1,"required_size":"128"},"reason":"000a7fff","diagnostic":"00656163636573ff","cause":{"kind":"unknown","method":"caller-description","evidence_ids":["model-evidence-a","model-evidence-b"]}}"#,&limits()).unwrap();
    assert_literal_getters(
        &v,
        CapabilityState::Unknown,
        DescribedCause::Unknown,
        1,
        Stage::Execute,
    );
    let v=CapabilityObservation::from_json(br#"{"schema_version":1,"kind":"scopebase-bpf-capability-observation","schema_revision":1,"claimed_origin":"caller_described","object":"0101010101010101010101010101010101010101010101010101010101010101","profile":"bpf-host-v1","context":{"kernel_build":"1111111111111111111111111111111111111111111111111111111111111111","btf":"2222222222222222222222222222222222222222222222222222222222222222","architecture":"x86_64","namespace_context":"3333333333333333333333333333333333333333333333333333333333333333","security_context":"4444444444444444444444444444444444444444444444444444444444444444","topology":"5555555555555555555555555555555555555555555555555555555555555555"},"state":"denied","stage":"load","hazard":"clean","operation":"BPF_PROG_LOAD","step_id":"load","outcome":"refused","error":{"kind":"denied","stage":"execute","raw_errno":13,"required_size":"128"},"reason":"000a7fff","diagnostic":"00656163636573ff","cause":{"kind":"permission","method":"caller-description","evidence_ids":["model-evidence-a","model-evidence-b"]}}"#,&limits()).unwrap();
    assert_literal_getters(
        &v,
        CapabilityState::Denied,
        DescribedCause::Permission,
        13,
        Stage::Execute,
    );
    let v=CapabilityObservation::from_json(br#"{"schema_version":1,"kind":"scopebase-bpf-capability-observation","schema_revision":1,"claimed_origin":"caller_described","object":"0101010101010101010101010101010101010101010101010101010101010101","profile":"bpf-host-v1","context":{"kernel_build":"1111111111111111111111111111111111111111111111111111111111111111","btf":"2222222222222222222222222222222222222222222222222222222222222222","architecture":"x86_64","namespace_context":"3333333333333333333333333333333333333333333333333333333333333333","security_context":"4444444444444444444444444444444444444444444444444444444444444444","topology":"5555555555555555555555555555555555555555555555555555555555555555"},"state":"incompatible","stage":"load","hazard":"clean","operation":"BPF_PROG_LOAD","step_id":"load","outcome":"refused","error":{"kind":"denied","stage":"execute","raw_errno":13,"required_size":"128"},"reason":"000a7fff","diagnostic":"00656163636573ff","cause":{"kind":"verifier","method":"caller-description","evidence_ids":["model-evidence-a","model-evidence-b"]}}"#,&limits()).unwrap();
    assert_literal_getters(
        &v,
        CapabilityState::Incompatible,
        DescribedCause::Verifier,
        13,
        Stage::Execute,
    );
    let v=CapabilityObservation::from_json(br#"{"schema_version":1,"kind":"scopebase-bpf-capability-observation","schema_revision":1,"claimed_origin":"caller_described","object":"0101010101010101010101010101010101010101010101010101010101010101","profile":"bpf-host-v1","context":{"kernel_build":"1111111111111111111111111111111111111111111111111111111111111111","btf":"2222222222222222222222222222222222222222222222222222222222222222","architecture":"x86_64","namespace_context":"3333333333333333333333333333333333333333333333333333333333333333","security_context":"4444444444444444444444444444444444444444444444444444444444444444","topology":"5555555555555555555555555555555555555555555555555555555555555555"},"state":"incompatible","stage":"load","hazard":"clean","operation":"BPF_PROG_LOAD","step_id":"load","outcome":"refused","error":{"kind":"denied","stage":"execute","raw_errno":13,"required_size":"128"},"reason":"000a7fff","diagnostic":"00656163636573ff","cause":{"kind":"license","method":"caller-description","evidence_ids":["model-evidence-a","model-evidence-b"]}}"#,&limits()).unwrap();
    assert_literal_getters(
        &v,
        CapabilityState::Incompatible,
        DescribedCause::License,
        13,
        Stage::Execute,
    );
    let v=CapabilityObservation::from_json(br#"{"schema_version":1,"kind":"scopebase-bpf-capability-observation","schema_revision":1,"claimed_origin":"caller_described","object":"0101010101010101010101010101010101010101010101010101010101010101","profile":"bpf-host-v1","context":{"kernel_build":"1111111111111111111111111111111111111111111111111111111111111111","btf":"2222222222222222222222222222222222222222222222222222222222222222","architecture":"x86_64","namespace_context":"3333333333333333333333333333333333333333333333333333333333333333","security_context":"4444444444444444444444444444444444444444444444444444444444444444","topology":"5555555555555555555555555555555555555555555555555555555555555555"},"state":"unsupported","stage":"load","hazard":"clean","operation":"BPF_PROG_LOAD","step_id":"load","outcome":"refused","error":{"kind":"denied","stage":"execute","raw_errno":13,"required_size":"128"},"reason":"000a7fff","diagnostic":"00656163636573ff","cause":{"kind":"unsupported_operation","method":"caller-description","evidence_ids":["model-evidence-a","model-evidence-b"]}}"#,&limits()).unwrap();
    assert_literal_getters(
        &v,
        CapabilityState::Unsupported,
        DescribedCause::UnsupportedOperation,
        13,
        Stage::Execute,
    );
    let v=CapabilityObservation::from_json(br#"{"schema_version":1,"kind":"scopebase-bpf-capability-observation","schema_revision":1,"claimed_origin":"caller_described","object":"0101010101010101010101010101010101010101010101010101010101010101","profile":"bpf-host-v1","context":{"kernel_build":"1111111111111111111111111111111111111111111111111111111111111111","btf":"2222222222222222222222222222222222222222222222222222222222222222","architecture":"x86_64","namespace_context":"3333333333333333333333333333333333333333333333333333333333333333","security_context":"4444444444444444444444444444444444444444444444444444444444444444","topology":"5555555555555555555555555555555555555555555555555555555555555555"},"state":"unknown","stage":"load","hazard":"clean","operation":"BPF_PROG_LOAD","step_id":"load","outcome":"refused","error":{"kind":"denied","stage":"execute","raw_errno":13,"required_size":"128"},"reason":"000a7fff","diagnostic":"00656163636573ff","cause":{"kind":"unknown","method":"caller-description","evidence_ids":["model-evidence-a","model-evidence-b"]}}"#,&limits()).unwrap();
    assert_literal_getters(
        &v,
        CapabilityState::Unknown,
        DescribedCause::Unknown,
        13,
        Stage::Execute,
    );
}
#[test]
fn nested_shape_null_scalar_depth_and_required_members() {
    let literal = std::str::from_utf8(include_bytes!(
        "../fixtures/capability-v1/codec/valid-base.bytes"
    ))
    .unwrap();
    for (old, new) in [
        (
            "\"architecture\":\"x86_64\"",
            "\"architecture\":\"x86_64\",\"architecture\":\"x86_64\"",
        ),
        (
            "\"architecture\":\"x86_64\"",
            "\"architecture\":\"x86_64\",\"unknown\":null",
        ),
        ("\"raw_errno\":13", "\"raw_errno\":13,\"raw_errno\":13"),
        ("\"raw_errno\":13", "\"raw_errno\":13,\"unknown\":null"),
        (
            "\"method\":\"caller-description\"",
            "\"method\":\"caller-description\",\"method\":\"caller-description\"",
        ),
        (
            "\"method\":\"caller-description\"",
            "\"method\":\"caller-description\",\"unknown\":null",
        ),
        (
            "\"object\":\"0101010101010101010101010101010101010101010101010101010101010101\"",
            "\"object\":null",
        ),
        ("\"raw_errno\":13", "\"raw_errno\":13.0"),
        ("\"raw_errno\":13", "\"raw_errno\":[[[[13]]]]"),
        (
            "\"evidence_ids\":[\"model-evidence-a\",\"model-evidence-b\"]",
            "\"evidence_ids\":null",
        ),
        (
            "\"evidence_ids\":[\"model-evidence-a\",\"model-evidence-b\"]",
            "\"evidence_ids\":[1]",
        ),
    ] {
        for schema in [1, 2] {
            let bad = literal.replace(old, new).replace(
                "\"schema_revision\":1",
                &format!("\"schema_revision\":{schema}"),
            );
            let e = CapabilityObservation::from_json(bad.as_bytes(), &limits()).unwrap_err();
            assert_eq!(
                (e.kind(), e.stage(), e.raw_os_error(), e.required_size()),
                (ErrorKind::Malformed, Stage::Inspect, None, None),
                "json.result nested shape {old}"
            );
        }
    }
    let base: serde_json::Value = serde_json::from_str(literal).unwrap();
    for path in [vec![], vec!["context"], vec!["error"], vec!["cause"]] {
        let mut keys = base.clone();
        for key in &path {
            keys = keys[*key].clone();
        }
        for key in keys.as_object().unwrap().keys() {
            let mut bad = base.clone();
            let mut object = &mut bad;
            for part in &path {
                object = &mut object[*part];
            }
            object.as_object_mut().unwrap().remove(key);
            let e = CapabilityObservation::from_json(&serde_json::to_vec(&bad).unwrap(), &limits())
                .unwrap_err();
            assert_eq!(
                (e.kind(), e.stage(), e.required_size()),
                (ErrorKind::Malformed, Stage::Inspect, None),
                "json.result missing required {path:?}/{key}"
            );
        }
    }
}
#[test]
fn decoded_field_hard_maxima_and_exact_twins() {
    let base: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../fixtures/capability-v1/codec/valid-base.bytes"
    ))
    .unwrap();
    for (path, maximum, binary) in [
        (vec!["profile"], 128, false),
        (vec!["context", "architecture"], 64, false),
        (vec!["operation"], 96, false),
        (vec!["step_id"], 96, false),
        (vec!["cause", "method"], 96, false),
        (vec!["reason"], 4096, true),
        (vec!["diagnostic"], 16384, true),
    ] {
        for extra in [0, 1] {
            let mut value = base.clone();
            let mut field = &mut value;
            for key in &path {
                field = &mut field[*key];
            }
            *field = serde_json::Value::String(if binary {
                "00".repeat(maximum + extra)
            } else {
                "a".repeat(maximum + extra)
            });
            let result =
                CapabilityObservation::from_json(&serde_json::to_vec(&value).unwrap(), &limits());
            if extra == 0 {
                assert!(result.is_ok(), "exact maximum {path:?}: {:?}", result.err());
            } else {
                let e = result.unwrap_err();
                assert_eq!(
                    (e.kind(), e.stage(), e.raw_os_error(), e.required_size()),
                    (
                        ErrorKind::LimitExceeded,
                        Stage::Inspect,
                        None,
                        Some(maximum + 1)
                    ),
                    "decoded maximum {path:?}"
                );
            }
        }
    }
    let mut value = base;
    value["cause"]["evidence_ids"] = serde_json::json!(["a".repeat(97)]);
    let e = CapabilityObservation::from_json(&serde_json::to_vec(&value).unwrap(), &limits())
        .unwrap_err();
    assert_eq!(
        (e.kind(), e.stage(), e.required_size()),
        (ErrorKind::LimitExceeded, Stage::Inspect, Some(97))
    );
}
