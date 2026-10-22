// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::*;
#[test]
fn filter_literals() {
    let [e, o, x, h] = [0, 0, 0, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Unknown,
        "filter.state all-zero"
    );
    let [e, o, x, h] = [0, 0, 1, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Unknown,
        "filter.state zero-own-with-excluded-population"
    );
    let [e, o, x, h] = [0, 1, 0, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state unexpected-own-no-excluded"
    );
    let [e, o, x, h] = [0, 1, 1, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state unexpected-own-active-excluded"
    );
    let [e, o, x, h] = [1, 0, 0, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Unknown,
        "filter.state disabled-own-trigger-no-excluded"
    );
    let [e, o, x, h] = [1, 0, 1, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Unknown,
        "filter.state disabled-own-trigger-active-excluded"
    );
    let [e, o, x, h] = [2, 0, 1, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Unknown,
        "filter.state original-quiet-owned"
    );
    let [e, o, x, h] = [2, 1, 0, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state short-own-no-excluded"
    );
    let [e, o, x, h] = [2, 1, 1, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state original-thread-exact"
    );
    let [e, o, x, h] = [1, 2, 0, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state extra-own-no-excluded"
    );
    let [e, o, x, h] = [1, 2, 1, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state extra-own-active-excluded"
    );
    let [e, o, x, h] = [1, 1, 0, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Unknown,
        "filter.state matched-own-missing-excluded"
    );
    let [e, o, x, h] = [1, 1, 1, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Supported,
        "filter.state small-supported-model"
    );
    let [e, o, x, h] = [2, 2, 1, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Supported,
        "filter.state original-positive-model"
    );
    let [e, o, x, h] = [2, 2, 2, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Supported,
        "filter.state more-excluded-executions"
    );
    let [e, o, x, h] = [0, 0, 0, 1];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state excluded-hit-with-all-other-zero"
    );
    let [e, o, x, h] = [1, 0, 0, 1];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state excluded-hit-with-disabled-trigger"
    );
    let [e, o, x, h] = [1, 0, 1, 1];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state excluded-hit-with-disabled-owned-active-excluded"
    );
    let [e, o, x, h] = [0, 1, 0, 1];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state excluded-hit-with-unexpected-own"
    );
    let [e, o, x, h] = [2, 1, 0, 1];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state excluded-hit-with-short-own"
    );
    let [e, o, x, h] = [2, 2, 0, 1];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state excluded-hit-with-missing-excluded-ledger"
    );
    let [e, o, x, h] = [2, 2, 1, 1];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state original-widened-filter"
    );
    let [e, o, x, h] = [2, 2, 1, 2];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state excluded-hits-exceed-ledger"
    );
    let [e, o, x, h] = [
        18446744073709551615,
        18446744073709551615,
        18446744073709551615,
        0,
    ];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Supported,
        "filter.state all-max-except-zero-excluded-hits"
    );
    let [e, o, x, h] = [18446744073709551615, 18446744073709551615, 0, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Unknown,
        "filter.state max-own-missing-excluded"
    );
    let [e, o, x, h] = [18446744073709551615, 0, 18446744073709551615, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Unknown,
        "filter.state max-expected-disabled-trigger"
    );
    let [e, o, x, h] = [
        18446744073709551615,
        18446744073709551614,
        18446744073709551615,
        0,
    ];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state max-short-own"
    );
    let [e, o, x, h] = [
        18446744073709551614,
        18446744073709551615,
        18446744073709551615,
        0,
    ];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state max-extra-own"
    );
    let [e, o, x, h] = [0, 18446744073709551615, 18446744073709551615, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state max-own-unexpected"
    );
    let [e, o, x, h] = [0, 0, 0, 18446744073709551615];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state max-excluded-hits-other-zero"
    );
    let [e, o, x, h] = [
        18446744073709551615,
        18446744073709551615,
        18446744073709551615,
        18446744073709551615,
    ];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state all-max"
    );
    let [e, o, x, h] = [1, 1, 18446744073709551615, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Supported,
        "filter.state max-excluded-population-no-hits"
    );
    let [e, o, x, h] = [18446744073709551615, 1, 1, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state max-vs-one-short"
    );
    let [e, o, x, h] = [1, 18446744073709551615, 1, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state one-vs-max-extra"
    );
    let [e, o, x, h] = [18446744073709551615, 0, 0, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Unknown,
        "filter.state max-expected-zero-observations"
    );
    let [e, o, x, h] = [0, 0, 18446744073709551615, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Unknown,
        "filter.state max-excluded-population-zero-own"
    );
    let [e, o, x, h] = [0, 0, 18446744073709551615, 18446744073709551615];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Incompatible,
        "filter.state max-excluded-with-hit-zero-own"
    );
    let [e, o, x, h] = [2, 0, 18446744073709551615, 0];
    assert_eq!(
        assess_filter_probe(&ProbePopulation {
            expected_owned_hits: e,
            observed_owned_hits: o,
            independently_executed_excluded: x,
            observed_excluded_hits: h
        })
        .unwrap(),
        CapabilityState::Unknown,
        "filter.state disabled-own-trigger-max-excluded"
    );
}
#[test]
fn finite_relation_partitions() {
    // Independent relation classes: E,O; expected X=0 and X>0 with H=0.
    let classes = [
        (0, 0, CapabilityState::Unknown, CapabilityState::Unknown),
        (
            0,
            1,
            CapabilityState::Incompatible,
            CapabilityState::Incompatible,
        ),
        (1, 0, CapabilityState::Unknown, CapabilityState::Unknown),
        (1, 1, CapabilityState::Unknown, CapabilityState::Supported),
        (
            1,
            2,
            CapabilityState::Incompatible,
            CapabilityState::Incompatible,
        ),
        (
            2,
            1,
            CapabilityState::Incompatible,
            CapabilityState::Incompatible,
        ),
        (
            u64::MAX,
            u64::MAX,
            CapabilityState::Unknown,
            CapabilityState::Supported,
        ),
        (
            u64::MAX,
            1,
            CapabilityState::Incompatible,
            CapabilityState::Incompatible,
        ),
        (
            1,
            u64::MAX,
            CapabilityState::Incompatible,
            CapabilityState::Incompatible,
        ),
    ];
    for (e, o, a, b) in classes {
        for (x, s) in [(0, a), (1, b), (u64::MAX, b)] {
            for (h, want) in [
                (0, s),
                (1, CapabilityState::Incompatible),
                (u64::MAX, CapabilityState::Incompatible),
            ] {
                assert_eq!(
                    assess_filter_probe(&ProbePopulation {
                        expected_owned_hits: e,
                        observed_owned_hits: o,
                        independently_executed_excluded: x,
                        observed_excluded_hits: h
                    })
                    .unwrap(),
                    want,
                    "filter.state relation"
                );
            }
        }
    }
}

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
fn context() -> ProbeContext {
    ProbeContext {
        kernel_build: [0x11; 32],
        btf: Some(ArtifactId([0x22; 32])),
        architecture: "x86_64".into(),
        namespace_context: [0x33; 32],
        security_context: [0x44; 32],
        topology: [0x55; 32],
    }
}
fn input<'a>(
    object: &'a ArtifactId,
    profile: &'a ProfileId,
    context: &'a ProbeContext,
) -> CapabilityObservationInput<'a> {
    CapabilityObservationInput {
        object,
        profile,
        context,
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
    }
}
fn assert_error(e: OperationError, k: ErrorKind, s: Stage, n: Option<usize>) {
    use std::error::Error;
    assert_eq!(
        (e.kind(), e.stage(), e.raw_os_error(), e.required_size()),
        (k, s, None, n)
    );
    assert!(e.source().is_none());
}
#[test]
fn profile_grammar_and_boundaries() {
    for s in ["a", "0", "a/._-09", &"a".repeat(128)] {
        assert_eq!(ProfileId::new(s).unwrap().as_str(), s);
    }
    for s in ["", "A", ".a", "aA", "a\n", "á", &"a".repeat(129)] {
        assert_error(
            ProfileId::new(s).unwrap_err(),
            ErrorKind::InvalidInput,
            Stage::Admission,
            None,
        );
    }
    let p = ProfileId::new("secret-profile").unwrap();
    let text = format!("{p:?}");
    assert!(!text.contains("secret-profile"));
}
#[test]
fn observation_fields_are_lossless() {
    let o = ArtifactId([1; 32]);
    let p = ProfileId::new("bpf-host-v1").unwrap();
    let c = context();
    let v = CapabilityObservation::new(input(&o, &p, &c), &limits()).unwrap();
    assert_eq!(v.object(), &o);
    assert_eq!(v.profile(), &p);
    assert_eq!(v.context(), &c);
    assert_eq!(v.state(), CapabilityState::Denied);
    assert_eq!(v.stage(), EvidenceStage::Load);
    assert_eq!(v.hazard(), Some(HazardState::Clean));
    assert_eq!(v.operation(), "BPF_PROG_LOAD");
    assert_eq!(v.step_id(), Some("load"));
    assert_eq!(v.outcome(), ObservationOutcome::Refused);
    assert_eq!(v.reason(), &[0, 10, 127, 255], "description.fields reason");
    assert_eq!(
        v.diagnostic(),
        &[0, 101, 97, 99, 99, 101, 115, 255],
        "description.fields diagnostic"
    );
    assert_eq!(v.cause(), DescribedCause::Permission);
    assert_eq!(v.cause_method(), "caller-description");
    assert_eq!(
        v.cause_evidence_ids(),
        &["model-evidence-a", "model-evidence-b"]
    );
    assert_eq!(v.origin(), ObservationOrigin::CallerDescribed);
    assert_eq!(v.claimed_origin(), ObservationOrigin::CallerDescribed);
    assert_eq!(
        (
            v.operation_error().unwrap().kind(),
            v.operation_error().unwrap().stage(),
            v.operation_error().unwrap().raw_os_error(),
            v.operation_error().unwrap().required_size()
        ),
        (ErrorKind::Denied, Stage::Execute, Some(13), Some(128)),
        "description.fields"
    );
    let debug = format!("{v:?}");
    assert!(debug.is_ascii() && debug.len() <= 256);
    for secret in [
        "BPF_PROG_LOAD",
        "bpf-host-v1",
        "x86_64",
        "caller-description",
        "model-evidence-a",
    ] {
        assert!(!debug.contains(secret));
    }
    let debug = format!("{c:?}");
    assert!(!debug.contains("x86_64"));
}
#[test]
fn context_matches_every_field() {
    let o = ArtifactId([1; 32]);
    let p = ProfileId::new("bpf-host-v1").unwrap();
    let c = context();
    let v = CapabilityObservation::new(input(&o, &p, &c), &limits()).unwrap();
    assert!(v.applies_to(&o, &p, &c));
    assert!(
        !v.applies_to(&ArtifactId([2; 32]), &p, &c),
        "context.applies object"
    );
    assert!(
        !v.applies_to(&o, &ProfileId::new("other").unwrap(), &c),
        "context.applies profile"
    );
    for field in 0..7 {
        let mut changed = c.clone();
        match field {
            0 => changed.kernel_build[0] ^= 1,
            1 => changed.btf = Some(ArtifactId([0; 32])),
            2 => changed.btf = None,
            3 => changed.architecture = "X86_64".into(),
            4 => changed.namespace_context[0] ^= 1,
            5 => changed.security_context[0] ^= 1,
            6 => changed.topology[0] ^= 1,
            _ => unreachable!(),
        };
        assert!(
            !v.applies_to(&o, &p, &changed),
            "context.applies field {field}"
        );
    }
    let mut c = c;
    c.btf = None;
    let v = CapabilityObservation::new(input(&o, &p, &c), &limits()).unwrap();
    assert!(v.applies_to(&o, &p, &c));
    c.btf = Some(ArtifactId([0; 32]));
    assert!(
        !v.applies_to(&o, &p, &c),
        "context.applies Some zero vs None"
    );
}
#[test]
fn hazard_and_capability_remain_separate() {
    let o = ArtifactId([1; 32]);
    let p = ProfileId::new("a").unwrap();
    let c = context();
    for (state, hazard) in [
        (CapabilityState::Denied, HazardState::Clean),
        (CapabilityState::Unknown, HazardState::Affected),
        (CapabilityState::Incompatible, HazardState::Unknown),
    ] {
        let mut i = input(&o, &p, &c);
        i.state = state;
        i.hazard = Some(hazard);
        let v = CapabilityObservation::new(i, &limits()).unwrap();
        assert_eq!((v.state(), v.hazard()), (state, Some(hazard)));
    }
}
#[test]
fn bp01_scalar_cross_product() {
    let kinds = [
        ErrorKind::InvalidInput,
        ErrorKind::Malformed,
        ErrorKind::Incompatible,
        ErrorKind::Unsupported,
        ErrorKind::Denied,
        ErrorKind::Disappeared,
        ErrorKind::Changed,
        ErrorKind::LimitExceeded,
        ErrorKind::Overflow,
        ErrorKind::Backend,
        ErrorKind::Poisoned,
    ];
    let stages = [
        Stage::Admission,
        Stage::Metadata,
        Stage::Allocate,
        Stage::Read,
        Stage::Attach,
        Stage::Drain,
        Stage::Retire,
        Stage::BtfQuery,
        Stage::Compile,
        Stage::Inspect,
        Stage::Execute,
    ];
    for kind in kinds {
        for stage in stages {
            for errno in [
                None,
                Some(0),
                Some(1),
                Some(13),
                Some(-1),
                Some(i32::MIN),
                Some(i32::MAX),
            ] {
                for required in [None, Some(0), Some(usize::MAX)] {
                    let mut e = OperationError::new(kind, stage, errno, None);
                    if let Some(n) = required {
                        e = e.with_required_size(n)
                    }
                    let snap = OperationErrorSnapshot::from_error(&e);
                    assert_eq!(
                        (
                            snap.kind(),
                            snap.stage(),
                            snap.raw_os_error(),
                            snap.required_size()
                        ),
                        (kind, stage, errno, required),
                        "description.fields scalar cross product"
                    );
                    let object = ArtifactId([7; 32]);
                    let profile = ProfileId::new("scalar-cross-product").unwrap();
                    let context = context();
                    let mut supplied = input(&object, &profile, &context);
                    supplied.error = Some(snap);
                    let described = CapabilityObservation::new(supplied, &limits()).unwrap();
                    let stored = described.operation_error().unwrap();
                    assert_eq!(
                        (
                            stored.kind(),
                            stored.stage(),
                            stored.raw_os_error(),
                            stored.required_size()
                        ),
                        (kind, stage, errno, required),
                        "description.fields stored scalar cross product"
                    );
                    assert_eq!(described.stage(), EvidenceStage::Load);
                    #[cfg(feature = "json")]
                    {
                        let encoded = described.to_json(&limits()).unwrap();
                        let imported =
                            CapabilityObservation::from_json(&encoded, &limits()).unwrap();
                        let stored = imported.operation_error().unwrap();
                        assert_eq!(
                            (
                                stored.kind(),
                                stored.stage(),
                                stored.raw_os_error(),
                                stored.required_size()
                            ),
                            (kind, stage, errno, required),
                            "description.fields imported scalar cross product"
                        );
                        assert_eq!(imported.stage(), EvidenceStage::Load);
                        assert_eq!(imported.origin(), ObservationOrigin::Imported);
                        assert_eq!(
                            imported.claimed_origin(),
                            ObservationOrigin::CallerDescribed
                        );
                        assert_ne!(imported, described);
                    }
                }
            }
        }
    }
}
#[test]
fn hostile_error_is_not_traversed() {
    struct Hostile;
    impl std::fmt::Debug for Hostile {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("source debug")
        }
    }
    impl std::fmt::Display for Hostile {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("source display")
        }
    }
    impl std::error::Error for Hostile {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            panic!("source traversal")
        }
    }
    let original = OperationError::new(
        ErrorKind::Backend,
        Stage::Execute,
        Some(-1),
        Some(Box::new(Hostile)),
    );
    let snap = OperationErrorSnapshot::from_error(&original);
    assert_eq!(snap.raw_os_error(), Some(-1));
    let o = ArtifactId([1; 32]);
    let p = ProfileId::new("a").unwrap();
    let c = context();
    let mut i = input(&o, &p, &c);
    i.error = Some(snap);
    let v = CapabilityObservation::new(i, &limits()).unwrap();
    let _ = format!("{v:?}");
}
#[test]
fn outcome_shape_and_label_order() {
    let o = ArtifactId([1; 32]);
    let p = ProfileId::new("a").unwrap();
    let c = context();
    for outcome in [
        ObservationOutcome::Completed,
        ObservationOutcome::Refused,
        ObservationOutcome::Incomplete,
    ] {
        for has_error in [false, true] {
            let mut i = input(&o, &p, &c);
            i.outcome = outcome;
            if !has_error {
                i.error = None
            }
            let ok = match outcome {
                ObservationOutcome::Completed => !has_error,
                ObservationOutcome::Refused => has_error,
                ObservationOutcome::Incomplete => true,
                _ => unreachable!(),
            };
            assert_eq!(CapabilityObservation::new(i, &limits()).is_ok(), ok);
        }
    }
    for ids in [&["same", "same"][..], &["z", "a"][..], &["bad/label"][..]] {
        let mut i = input(&o, &p, &c);
        i.cause.evidence_ids = ids;
        assert_error(
            CapabilityObservation::new(i, &limits()).unwrap_err(),
            ErrorKind::InvalidInput,
            Stage::Admission,
            None,
        );
    }
}
#[test]
fn hard_maxima_and_preflight_priority() {
    let o = ArtifactId([1; 32]);
    let p = ProfileId::new("a").unwrap();
    let c = context();
    let a = "a".repeat(97);
    let arch = "a".repeat(65);
    let reason = vec![0; 4097];
    let diag = vec![0; 16385];
    for field in 0..7 {
        let mut c = c.clone();
        if field == 0 {
            c.architecture = arch.clone()
        }
        let mut i = input(&o, &p, &c);
        match field{0=>{},1=>i.operation=&a,2=>i.step_id=Some(&a),3=>i.cause.method=&a,4=>i.reason=&reason,5=>i.diagnostic=&diag,6=>i.cause.evidence_ids=&["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],_=>unreachable!()};
        let expected = match field {
            0 => 65,
            1 | 2 | 3 | 6 => 97,
            4 => 4097,
            5 => 16385,
            _ => unreachable!(),
        };
        assert_error(
            CapabilityObservation::new(
                i,
                &Limits {
                    input_bytes: 0,
                    work_steps: 0,
                    ..limits()
                },
            )
            .unwrap_err(),
            ErrorKind::LimitExceeded,
            Stage::Admission,
            Some(expected),
        );
    }
    let ids = ["a"; 17];
    let mut i = input(&o, &p, &c);
    i.operation = &a;
    i.cause.evidence_ids = &ids;
    assert_error(
        CapabilityObservation::new(i, &limits()).unwrap_err(),
        ErrorKind::LimitExceeded,
        Stage::Admission,
        None,
    );
    let mut i = input(&o, &p, &c);
    i.operation = "bad/name";
    assert_error(
        CapabilityObservation::new(
            i,
            &Limits {
                input_bytes: 0,
                ..limits()
            },
        )
        .unwrap_err(),
        ErrorKind::LimitExceeded,
        Stage::Admission,
        Some(256 + 32 + 1 + 6 + 8 + 4 + 18 + 16 + 16 + 4 + 8),
    );
}
#[test]
fn input_work_retained_exact_boundaries() {
    let o = ArtifactId([1; 32]);
    let p = ProfileId::new("a").unwrap();
    let c = context();
    let i = input(&o, &p, &c);
    let pbytes = 256
        + 32
        + p.as_str().len()
        + c.architecture.len()
        + i.operation.len()
        + i.step_id.unwrap().len()
        + i.cause.method.len()
        + i.cause.evidence_ids.iter().map(|x| x.len()).sum::<usize>()
        + i.reason.len()
        + i.diagnostic.len();
    let work = 128 + 8 * pbytes as u64 + 8 * i.cause.evidence_ids.len() as u64;
    assert_error(
        CapabilityObservation::new(
            i,
            &Limits {
                input_bytes: pbytes - 1,
                work_steps: 0,
                ..limits()
            },
        )
        .unwrap_err(),
        ErrorKind::LimitExceeded,
        Stage::Admission,
        Some(pbytes),
    );
    assert_error(
        CapabilityObservation::new(
            i,
            &Limits {
                input_bytes: pbytes,
                work_steps: work - 1,
                ..limits()
            },
        )
        .unwrap_err(),
        ErrorKind::LimitExceeded,
        Stage::Admission,
        None,
    );
    let v = CapabilityObservation::new(
        i,
        &Limits {
            input_bytes: pbytes,
            work_steps: work,
            ..limits()
        },
    )
    .unwrap();
    let retained = v.retained_bytes();
    assert_error(
        CapabilityObservation::new(
            i,
            &Limits {
                retained_bytes: retained - 1,
                ..limits()
            },
        )
        .unwrap_err(),
        ErrorKind::LimitExceeded,
        Stage::Admission,
        Some(retained),
    );
    assert!(CapabilityObservation::new(
        i,
        &Limits {
            retained_bytes: retained,
            ..limits()
        }
    )
    .is_ok());
}
#[test]
fn borrowed_input_does_not_retain_capacity() {
    let o = ArtifactId([1; 32]);
    let p = ProfileId::new("a").unwrap();
    let mut c = context();
    c.architecture.reserve(50000);
    let mut reason = Vec::with_capacity(50000);
    reason.extend_from_slice(&[0, 255]);
    let mut operation = String::with_capacity(50000);
    operation.push_str("load");
    let mut i = input(&o, &p, &c);
    i.operation = &operation;
    i.reason = &reason;
    let v = CapabilityObservation::new(i, &limits()).unwrap();
    assert!(v.retained_bytes() < 4096);
    reason.fill(1);
    operation.clear();
    c.architecture.clear();
    assert_eq!(v.reason(), &[0, 255]);
    assert_eq!(v.operation(), "load");
    assert_eq!(v.context().architecture, "x86_64");
}
#[test]
fn positive_traits() {
    fn clone_eq_send<T: Clone + Eq + Send + Sync>() {}
    fn copy_eq_send<T: Copy + Eq + Send + Sync>() {}
    fn eq_send<T: Eq + Send + Sync>() {}
    clone_eq_send::<ProfileId>();
    clone_eq_send::<ProbeContext>();
    copy_eq_send::<ProbePopulation>();
    copy_eq_send::<CapabilityState>();
    copy_eq_send::<EvidenceStage>();
    copy_eq_send::<HazardState>();
    copy_eq_send::<ObservationOrigin>();
    copy_eq_send::<ObservationOutcome>();
    copy_eq_send::<DescribedCause>();
    copy_eq_send::<OperationErrorSnapshot>();
    eq_send::<CapabilityObservation>();
    fn inputs<'a>() {
        fn copy_send<T: Copy + Send + Sync>() {}
        copy_send::<CapabilityObservationInput<'a>>();
        copy_send::<CauseDescriptionInput<'a>>();
    }
    inputs();
}
