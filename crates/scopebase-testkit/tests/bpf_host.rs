// SPDX-License-Identifier: Apache-2.0
use scopebase_testkit::bpf::{profile_from_testkit, profile_to_testkit};
const PROFILE_CASES:&[(&str,&str,&str,&str)]=&[
("to-small","to-testkit-profile","a","ok:a"),
("from-small","from-testkit-profile","a","ok:a"),
("to-lower-punctuation","to-testkit-profile","abc-01._","ok:abc-01._"),
("from-lower-punctuation","from-testkit-profile","abc-01._","ok:abc-01._"),
("to-64","to-testkit-profile","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ok:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
("from-64","from-testkit-profile","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ok:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
("to-65","to-testkit-profile","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","receiving-id-error"),
("from-65","from-testkit-profile","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source-id-error"),
("to-128","to-testkit-profile","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","receiving-id-error"),
("from-128","from-testkit-profile","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source-id-error"),
("to-129","to-testkit-profile","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source-id-error"),
("to-slash","to-testkit-profile","a/b","receiving-id-error"),
("from-slash","from-testkit-profile","a/b","source-id-error"),
("to-uppercase","to-testkit-profile","Abc","source-id-error"),
("from-uppercase","from-testkit-profile","Abc","receiving-id-error"),
("to-empty","to-testkit-profile","","source-id-error"),
("from-empty","from-testkit-profile","","source-id-error"),
("to-first-dot","to-testkit-profile",".abc","source-id-error"),
("from-first-dot","from-testkit-profile",".abc","source-id-error"),
("to-nonascii","to-testkit-profile","å","source-id-error"),
("from-nonascii","from-testkit-profile","å","source-id-error"),
("to-space","to-testkit-profile","a b","source-id-error"),
("from-space","from-testkit-profile","a b","source-id-error"),
];
#[test]
fn profile_literal_receiving_domains() {
    for (id, op, input, expected) in PROFILE_CASES {
        let result = if *op == "to-testkit-profile" {
            scopebase_bpf::ProfileId::new(input)
                .map_err(|_| "source-id-error")
                .and_then(|p| {
                    profile_to_testkit(&p)
                        .map(|v| format!("ok:{}", v.as_str()))
                        .map_err(|_| "receiving-id-error")
                })
        } else {
            scopebase_testkit::ProfileId::parse(input)
                .map_err(|_| "source-id-error")
                .and_then(|p| {
                    profile_from_testkit(&p)
                        .map(|v| format!("ok:{}", v.as_str()))
                        .map_err(|_| "receiving-id-error")
                })
        };
        assert_eq!(
            result.unwrap_or_else(|e| e.into()),
            *expected,
            "profile.result {id}"
        );
    }
}
use scopebase_testkit::bpf::BpfHostAdapter;
use scopebase_testkit::*;
fn label(s: &str) -> Label {
    Label::parse(s).unwrap()
}
fn bpf_limits() -> scopebase_bpf::Limits {
    scopebase_bpf::Limits {
        input_bytes: 131072,
        retained_bytes: 262144,
        work_steps: 8388608,
        sites: 0,
        live_links: 0,
        pending_retirements: 0,
    }
}
fn subject(l: &RunLimits) -> SubjectBinding {
    let d = Digest256::of_bytes(b"BP03 unit model descriptive metadata");
    SubjectBinding::new(
        SubjectBindingValues {
            package_name: "scopebase-bpf".into(),
            package_version: "0.1.0".into(),
            source_sha256: d,
            build_inputs_sha256: d,
            features: vec![],
            backend: None,
            host: "x86_64-unknown-linux-gnu".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            consumer: ConsumerBinding::new(
                ConsumerBindingValues {
                    name: "bp03-unit".into(),
                    build_inputs_sha256: d,
                    executable_sha256: d,
                },
                l,
            )
            .unwrap(),
            objects: vec![],
            provenance: BindingProvenance::SelfReported {
                reason: "unit model fixture".into(),
            },
        },
        l,
    )
    .unwrap()
}
fn invocation(l: &RunLimits, schema: &str, op: &str, slots: &[&str]) -> CaseInvocation {
    let script = serde_json::json!({"schema_version":1,"kind":"steps-v1","schema_id":schema,"steps":[{"step_id":"only-step","operation":op,"inputs":slots,"parameters":[]}]});
    CaseInvocation::new(
        CaseInvocationValues {
            key: InvocationKey::new(
                InvocationKeyValues {
                    run_id: RunId::parse("0123456789abcdef0123456789abcdef").unwrap(),
                    case_key: CaseKey::new(
                        CaseKeyValues {
                            case_id: CaseId::parse("H22.model-filter").unwrap(),
                            case_version: 1,
                            cell_id: "model".into(),
                        },
                        l,
                    )
                    .unwrap(),
                    attempt: 1,
                    operation_id: 1,
                },
                l,
            )
            .unwrap(),
            observation_schema: SchemaBinding::new(
                SchemaBindingValues {
                    id: label("bp03-model-result"),
                    revision: 1,
                },
                l,
            )
            .unwrap(),
            fixture_schema: SchemaBinding::new(
                SchemaBindingValues {
                    id: label("bp03-fixed-input"),
                    revision: 1,
                },
                l,
            )
            .unwrap(),
            script: OperationScript::load(&serde_json::to_vec(&script).unwrap(), l).unwrap(),
            limits: l.clone(),
        },
        l,
    )
    .unwrap()
}
fn execute(
    b: scopebase_bpf::Limits,
    l: &RunLimits,
    schema: &str,
    op: &str,
    inputs: &[(&str, &[u8])],
) -> Result<Observation, CaseError> {
    use scopebase_testkit::{PreparedExecution, ResponsePreparedAdapter};
    let mut a = BpfHostAdapter::new(subject(l), b, l.clone()).unwrap();
    let slots = inputs.iter().map(|r| r.0).collect::<Vec<_>>();
    let i = invocation(l, schema, op, &slots);
    let refs = inputs
        .iter()
        .map(|(s, b)| FixtureInput::new(label(s), b))
        .collect::<Vec<_>>();
    let f = FixtureAccess::new(&refs, &[], EffectBatch::empty(l), l).unwrap();
    // Actual public prepared route: fallible admission first, then the
    // consuming whole-call execution. Scalar preparation failure is a test
    // defect in this helper; tests expecting scalar failure call
    // `prepare_response` directly.
    a.prepare_response(&i).unwrap().execute(&f)
}
#[test]
fn constructor_minima() {
    let original = RunLimits::default();
    for field in 0..5 {
        let mut values = original.values();
        match field {
            0 => values.name_bytes = 255,
            1 => values.label_bytes = 31,
            2 => values.diagnostic_bytes = 127,
            3 => values.observation_bytes = 127,
            4 => values.input_slots = 1,
            _ => unreachable!(),
        };
        let l = RunLimits::new(values).unwrap();
        let e = match BpfHostAdapter::new(subject(&original), bpf_limits(), l) {
            Err(e) => e,
            Ok(_) => panic!("constructor minima"),
        };
        assert_eq!(e.kind(), HarnessErrorKind::LimitExceeded);
        assert_eq!(e.diagnostic(), "bp03 adapter admission");
    }
}
#[test]
fn filter_actual_adapter_and_input_errors() {
    let l = RunLimits::default();
    for (input, want) in [
        (&b"2\n2\n1\n0\n"[..], &b"supported"[..]),
        (b"2\n1\n0\n0\n", b"incompatible"),
        (b"0\n0\n0\n0\n", b"unknown"),
        (b"0\n0\n0\n1\n", b"incompatible"),
    ] {
        let v = execute(
            bpf_limits(),
            &l,
            "bp03-host-v1",
            "assess-filter",
            &[("counts", input)],
        )
        .unwrap();
        assert_eq!(v.bytes(), want, "filter.state");
        assert_eq!(v.completed_steps(), &[label("only-step")]);
        assert!(v.effects().registrations().is_empty());
    }
    for input in [
        &b"02\n2\n1\n0\n"[..],
        b"2\r\n2\n1\n0\n",
        b"2\n2\n1\n0",
        b"2\n2\n1\n0\n0\n",
        b"18446744073709551616\n2\n1\n0\n",
    ] {
        let e = execute(
            bpf_limits(),
            &l,
            "bp03-host-v1",
            "assess-filter",
            &[("counts", input)],
        )
        .unwrap_err();
        assert_eq!(*e.category(), CaseErrorCategory::InvalidOutput);
        assert_eq!(e.stage().as_str(), "input");
        assert_eq!(e.diagnostic_bytes(), b"invalid-input");
        assert!(e.completed_steps().is_empty());
    }
}
#[test]
fn explicit_work_and_input_priority() {
    let l = RunLimits::default();
    let input = b"2\n2\n1\n0\n";
    let e = execute(
        scopebase_bpf::Limits {
            work_steps: 0,
            ..bpf_limits()
        },
        &l,
        "bp03-host-v1",
        "assess-filter",
        &[("counts", input)],
    )
    .unwrap_err();
    assert_eq!(*e.category(), CaseErrorCategory::Refused);
    assert_eq!(e.stage().as_str(), "admission");
    assert_eq!(e.diagnostic_bytes(), b"bpf:limit_exceeded/admission");
    let e = execute(
        scopebase_bpf::Limits {
            input_bytes: 7,
            work_steps: 0,
            ..bpf_limits()
        },
        &l,
        "bp03-host-v1",
        "assess-filter",
        &[("counts", input)],
    )
    .unwrap_err();
    assert_eq!(
        e.diagnostic_bytes(),
        b"bpf:limit_exceeded/admission;required=8"
    );
}
#[test]
fn invocation_limits_binding_precedes_dialect() {
    use scopebase_testkit::{PreparedExecution, ResponsePreparedAdapter};
    let l = RunLimits::default();
    let mut a = BpfHostAdapter::new(subject(&l), bpf_limits(), l.clone()).unwrap();
    let mut values = l.values();
    values.execution_ms -= 1;
    let changed = RunLimits::new(values).unwrap();
    let i = invocation(&changed, "unsupported", "not-an-operation", &[]);
    let f = FixtureAccess::new(&[], &[], EffectBatch::empty(&l), &l).unwrap();
    let e = a.prepare_response(&i).unwrap().execute(&f).unwrap_err();
    assert_eq!(*e.category(), CaseErrorCategory::InvalidOutput);
    assert_eq!(e.stage().as_str(), "binding");
    assert_eq!(e.diagnostic_bytes(), b"run-limits-mismatch");
    assert_eq!(*e.step_id(), None);
    assert!(e.completed_steps().is_empty());
}
#[test]
fn whole_dialect_preflight() {
    use scopebase_testkit::{PreparedExecution, ResponsePreparedAdapter};
    let l = RunLimits::default();
    for (schema, op, inputs) in [
        ("wrong", "assess-filter", vec!["counts"]),
        ("bp03-host-v1", "wrong", vec!["counts"]),
        ("bp03-host-v1", "assess-filter", vec![]),
        ("bp03-host-v1", "assess-filter", vec!["a", "b"]),
    ] {
        let mut a = BpfHostAdapter::new(subject(&l), bpf_limits(), l.clone()).unwrap();
        let i = invocation(&l, schema, op, &inputs);
        let f = FixtureAccess::new(&[], &[], EffectBatch::empty(&l), &l).unwrap();
        let e = a.prepare_response(&i).unwrap().execute(&f).unwrap_err();
        assert_eq!(*e.category(), CaseErrorCategory::UnsupportedSchema);
        assert_eq!(e.stage().as_str(), "preflight");
        assert_eq!(e.diagnostic_bytes(), b"unsupported-dialect");
        assert_eq!(*e.step_id(), None);
    }
}
#[cfg(feature = "bpf-host-json")]
#[test]
fn json_adapter_origin_and_context() {
    let l = RunLimits::default();
    let raw = controls::OBSERVATION_INPUT;
    let v = execute(
        bpf_limits(),
        &l,
        "bp03-host-json-v1",
        "import-observation",
        &[("record", raw)],
    )
    .unwrap();
    assert_eq!(&v.bytes()[..9], b"imported\n", "origin.imported");
    assert_eq!(&v.bytes()[9..], raw);
    let v = execute(
        bpf_limits(),
        &l,
        "bp03-host-json-v1",
        "context-applies",
        &[("base", raw), ("candidate", raw)],
    )
    .unwrap();
    assert_eq!(v.bytes(), b"true", "context.applies");
}

#[path = "fixtures/bp03/controls.rs"]
mod controls;

#[test]
fn exact_receiving_errors_and_adapter_profile_rows() {
    for value in ["a/b".to_owned(), "a".repeat(65)] {
        let source = scopebase_bpf::ProfileId::new(&value).unwrap();
        let error = profile_to_testkit(&source).unwrap_err();
        assert_eq!(
            error,
            if value.len() > 64 {
                IdError::TooLong
            } else {
                IdError::InvalidCharacter
            }
        );
    }
    let source = scopebase_testkit::ProfileId::parse("UpperCase").unwrap();
    let error = profile_from_testkit(&source).unwrap_err();
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (
            scopebase_bpf::ErrorKind::InvalidInput,
            scopebase_bpf::Stage::Admission,
            None,
            None
        )
    );
    let l = RunLimits::default();
    for (id, op, input, expected) in PROFILE_CASES {
        let bytes = format!("{input}\n");
        let result = execute(
            bpf_limits(),
            &l,
            "bp03-host-v1",
            op,
            &[("profile", bytes.as_bytes())],
        )
        .unwrap();
        assert_eq!(
            result.bytes(),
            expected.as_bytes(),
            "profile.result actual adapter {id}"
        );
        assert_eq!(result.completed_steps(), &[label("only-step")]);
    }
    for raw in [&b"a\n\n"[..], b"a\r\n", b"a", b"a\nb\n"] {
        let error = execute(
            bpf_limits(),
            &l,
            "bp03-host-v1",
            "to-testkit-profile",
            &[("profile", raw)],
        )
        .unwrap_err();
        assert_eq!(*error.category(), CaseErrorCategory::InvalidOutput);
        assert_eq!(error.stage().as_str(), "input");
        assert_eq!(error.diagnostic_bytes(), b"invalid-input");
    }
}
#[test]
fn prepared_call_is_consuming_and_bound() {
    use scopebase_testkit::{PreparedExecution, ResponsePreparedAdapter};
    let l = RunLimits::default();
    let mut a = BpfHostAdapter::new(subject(&l), bpf_limits(), l.clone()).unwrap();
    // Each prepared call is tied to its actual invocation: the finished
    // result carries that invocation's key, and a later call for a different
    // invocation carries its own.
    let first = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
    let refs = [FixtureInput::new(label("counts"), b"2\n2\n1\n0\n")];
    let f = FixtureAccess::new(&refs, &[], EffectBatch::empty(&l), &l).unwrap();
    let v = a.prepare_response(&first).unwrap().execute(&f).unwrap();
    assert_eq!(v.key(), first.key());
    assert_eq!(v.bytes(), b"supported");
    let second = invocation(&l, "bp03-host-v1", "to-testkit-profile", &["profile"]);
    let profile_refs = [FixtureInput::new(label("profile"), b"a\n")];
    let pf = FixtureAccess::new(&profile_refs, &[], EffectBatch::empty(&l), &l).unwrap();
    let v = a.prepare_response(&second).unwrap().execute(&pf).unwrap();
    assert_eq!(v.key(), second.key());
    assert_eq!(v.bytes(), b"ok:a");
}
/// S01: fields must fit the EMBEDDED limits, not just the constructor
/// ceiling. The counterexample (default ceiling, embedded name_bytes=1,
/// a normal 5-byte cell_id) must be rejected at construction instead of
/// panicking a downstream adapter's fitted echo.
#[test]
fn invocation_fields_must_fit_embedded_limits() {
    let ceiling = RunLimits::default();
    let mut narrow = ceiling.values();
    narrow.name_bytes = 1;
    let embedded = RunLimits::new(narrow).unwrap();
    let script = serde_json::json!({"schema_version":1,"kind":"steps-v1","schema_id":"bp03-host-v1","steps":[{"step_id":"only-step","operation":"assess-filter","inputs":["counts"],"parameters":[]}]});
    let err = CaseInvocation::new(
        CaseInvocationValues {
            key: InvocationKey::new(
                InvocationKeyValues {
                    run_id: RunId::parse("0123456789abcdef0123456789abcdef").unwrap(),
                    case_key: CaseKey::new(
                        CaseKeyValues {
                            case_id: CaseId::parse("H22.model-filter").unwrap(),
                            case_version: 1,
                            cell_id: "model".into(),
                        },
                        &ceiling,
                    )
                    .unwrap(),
                    attempt: 1,
                    operation_id: 1,
                },
                &ceiling,
            )
            .unwrap(),
            observation_schema: SchemaBinding::new(
                SchemaBindingValues {
                    id: label("bp03-model-result"),
                    revision: 1,
                },
                &ceiling,
            )
            .unwrap(),
            fixture_schema: SchemaBinding::new(
                SchemaBindingValues {
                    id: label("bp03-fixed-input"),
                    revision: 1,
                },
                &ceiling,
            )
            .unwrap(),
            script: OperationScript::load(&serde_json::to_vec(&script).unwrap(), &ceiling).unwrap(),
            limits: embedded,
        },
        &ceiling,
    )
    .unwrap_err();
    assert_eq!(err.kind(), HarnessErrorKind::LimitExceeded);
}
