// SPDX-License-Identifier: Apache-2.0
use scopebase_testkit::*;
#[test]
fn hash_known_vectors_and_bounds() {
    assert_eq!(
        Digest256::of_bytes(b"").as_str(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        Digest256::of_bytes(b"abc").as_str(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        Digest256::of_bytes(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").as_str(),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    assert!(Digest256::parse(&"A".repeat(64)).is_err());
}
#[test]
fn limits_construct_and_lower() {
    let mut v = RunLimits::default().values();
    v.execution_ms = 60_000;
    v.retirement_ms = 30_000;
    assert!(RunLimits::new(v.clone()).is_ok());
    assert_eq!(
        RunLimits::default().lowered(v).unwrap_err().kind(),
        LimitErrorKind::NotLower
    );
    let mut execution_only = RunLimits::default().values();
    execution_only.execution_ms = 60_000;
    let error = RunLimits::default().lowered(execution_only).unwrap_err();
    assert_eq!(error.field(), "execution_ms");
    assert_eq!(error.kind(), LimitErrorKind::NotLower);
    assert!(RunLimits::new(RunLimits::maxima()).is_ok());
    let mut v = RunLimits::default().values();
    v.input_bytes = 0;
    assert_eq!(RunLimits::new(v).unwrap_err().kind(), LimitErrorKind::Zero);
}
#[test]
fn all_limit_fields_reject_zero_and_maximum_plus_one() {
    let mutations: [(&str, fn(&mut RunLimitValues, u64)); 32] = [
        ("input_bytes", |v, x| v.input_bytes = x),
        ("observation_bytes", |v, x| v.observation_bytes = x),
        ("vector_bytes", |v, x| v.vector_bytes = x),
        ("receipt_bytes", |v, x| v.receipt_bytes = x),
        ("retained_bytes", |v, x| v.retained_bytes = x),
        ("diagnostic_bytes", |v, x| v.diagnostic_bytes = x),
        ("name_bytes", |v, x| v.name_bytes = x),
        ("label_bytes", |v, x| v.label_bytes = x),
        ("measure_file_bytes", |v, x| v.measure_file_bytes = x),
        ("measure_total_bytes", |v, x| v.measure_total_bytes = x),
        ("read_calls", |v, x| v.read_calls = x),
        ("measurement_attempts", |v, x| v.measurement_attempts = x),
        ("case_attempts", |v, x| v.case_attempts = x),
        ("steps_per_invocation", |v, x| v.steps_per_invocation = x),
        ("steps_total", |v, x| v.steps_total = x),
        ("attempts_per_case", |v, x| v.attempts_per_case = x),
        ("assertions_per_case", |v, x| v.assertions_per_case = x),
        ("coverage_per_case", |v, x| v.coverage_per_case = x),
        ("effects_per_case", |v, x| v.effects_per_case = x),
        ("assertion_records", |v, x| v.assertion_records = x),
        ("coverage_records", |v, x| v.coverage_records = x),
        ("effects_total", |v, x| v.effects_total = x),
        ("features", |v, x| v.features = x),
        ("artifacts", |v, x| v.artifacts = x),
        ("input_slots", |v, x| v.input_slots = x),
        ("script_parameters", |v, x| v.script_parameters = x),
        ("resource_views", |v, x| v.resource_views = x),
        ("scalar_bytes", |v, x| v.scalar_bytes = x),
        ("json_depth", |v, x| v.json_depth = x),
        ("json_edges", |v, x| v.json_edges = x),
        ("execution_ms", |v, x| v.execution_ms = x),
        ("retirement_ms", |v, x| v.retirement_ms = x),
    ];
    let maximum = serde_json::to_value(RunLimits::maxima()).unwrap();
    for (name, set) in mutations {
        for (value, kind) in [
            (0, LimitErrorKind::Zero),
            (
                maximum[name].as_str().unwrap().parse::<u64>().unwrap() + 1,
                LimitErrorKind::AboveMaximum,
            ),
        ] {
            let mut v = RunLimits::default().values();
            set(&mut v, value);
            let error = RunLimits::new(v).unwrap_err();
            assert_eq!(error.field(), name);
            assert_eq!(error.kind(), kind);
            assert_eq!(error.requested(), value);
        }
    }
    let mut lower = RunLimits::default().values();
    lower.execution_ms = 1000;
    lower.retirement_ms = 1000;
    assert!(RunLimits::default().lowered(lower).is_ok());
    let mut invalid = RunLimits::default().values();
    invalid.measure_total_bytes = invalid.measure_file_bytes;
    assert_eq!(
        RunLimits::new(invalid).unwrap_err().kind(),
        LimitErrorKind::CrossField
    );
    let mut invalid = RunLimits::default().values();
    invalid.steps_total = invalid.steps_per_invocation - 1;
    assert_eq!(
        RunLimits::new(invalid).unwrap_err().kind(),
        LimitErrorKind::CrossField
    );
}

fn binding(id: &str, role: ArtifactRole, b: &[u8]) -> ArtifactBinding {
    ArtifactBinding::new(
        ArtifactBindingValues {
            id: Label::parse(id).unwrap(),
            revision: 1,
            role,
            length: b.len() as u64,
            sha256: Digest256::of_bytes(b),
        },
        &RunLimits::default(),
    )
    .unwrap()
}
fn temp_file(bytes: &[u8]) -> (std::path::PathBuf, std::fs::File) {
    use std::io::Write;
    let p = std::env::temp_dir().join(format!(
        "tt02-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&p)
        .unwrap();
    f.write_all(bytes).unwrap();
    (p, f)
}
#[test]
fn positional_files_and_aliases() {
    use std::io::{Seek, SeekFrom};
    let bytes = b"0123456789abc";
    let (p, mut f) = temp_file(bytes);
    f.seek(SeekFrom::Start(7)).unwrap();
    let mut alias = f.try_clone().unwrap();
    let mut m = ArtifactMeasurer::new(
        RunId::parse("0123456789abcdef0123456789abcdef").unwrap(),
        RunLimits::default(),
    )
    .unwrap();
    m.measure(&binding("a", ArtifactRole::ConsumerExecutable, bytes), &f)
        .unwrap();
    m.measure(
        &binding("b", ArtifactRole::ConsumerExecutable, bytes),
        &alias,
    )
    .unwrap();
    assert_eq!(f.stream_position().unwrap(), 7);
    assert_eq!(alias.stream_position().unwrap(), 7);
    assert_eq!(m.usage().reserved_bytes, 28);
    std::fs::remove_file(p).unwrap();
}
#[test]
fn stream_budget_and_progress() {
    let (p, f) = temp_file(b"abc");
    let mut v = RunLimits::default().values();
    v.measure_file_bytes = 3;
    v.measure_total_bytes = 8;
    v.read_calls = 3;
    let l = RunLimits::new(v).unwrap();
    let mut m = ArtifactMeasurer::new(RunId::parse("0123456789abcdef0123456789abcdef").unwrap(), l)
        .unwrap();
    let mut bad = binding("a", ArtifactRole::ConsumerExecutable, b"abc");
    let v = ArtifactBindingValues {
        id: bad.id().clone(),
        revision: 1,
        role: ArtifactRole::ConsumerExecutable,
        length: 3,
        sha256: Digest256::of_bytes(b"abd"),
    };
    bad = ArtifactBinding::new(v, &RunLimits::default()).unwrap();
    assert_eq!(
        m.measure(&bad, &f).unwrap_err().kind(),
        BindingErrorKind::DigestMismatch
    );
    assert_eq!(m.usage().reserved_bytes, 4);
    assert_eq!(m.usage().read_calls, 2);
    assert_eq!(
        m.measure(&bad, &f).unwrap_err().kind(),
        BindingErrorKind::LimitExceeded
    );
    assert_eq!(m.usage().reserved_bytes, 8);
    assert_eq!(m.usage().bytes_returned, 6);
    assert_eq!(m.usage().bytes_hashed, 6);
    assert_eq!(
        m.measure(&bad, &f).unwrap_err().kind(),
        BindingErrorKind::LimitExceeded
    );
    assert_eq!(m.usage().attempts, 3);
    assert_eq!(m.usage().reserved_bytes, 8);
    std::fs::remove_file(p).unwrap();
}
#[test]
fn large_artifacts_do_not_raise_vector_cap() {
    exact_vector_ceiling();
    for (i, (n, expected)) in [
        (
            13_836_048usize,
            "94e15fd2487213a233ea75011cfb720f28345c70a1e4441f76c84af9e33a0ffc",
        ),
        (
            15_647_872,
            "1f433c8357ab721bdad368bd6251ac3afb80de12ef59a70d2b251bfa63ffeb4e",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = vec![b'x'; n];
        let (p, f) = temp_file(&bytes);
        let mut m = ArtifactMeasurer::new(
            RunId::parse("0123456789abcdef0123456789abcdef").unwrap(),
            RunLimits::default(),
        )
        .unwrap();
        let binding = ArtifactBinding::new(
            ArtifactBindingValues {
                id: Label::parse(&format!("binary{i}")).unwrap(),
                revision: 1,
                role: ArtifactRole::ConsumerExecutable,
                length: n as u64,
                sha256: Digest256::parse(expected).unwrap(),
            },
            &RunLimits::default(),
        )
        .unwrap();
        m.measure(&binding, &f).unwrap();
        assert_eq!(m.usage().bytes_hashed, n as u64);
        assert!(m.usage().read_calls <= n as u64 / 65536 + 2);
        assert_eq!(RunLimits::default().vector_bytes(), 8_388_608);
        std::fs::remove_file(p).unwrap();
    }
}
#[path = "fixtures/harness/support.rs"]
mod support;
#[test]
fn self_reported_is_not_generated() {
    let mut v = support::contract_value();
    v["expected_subject"]["provenance"] =
        serde_json::json!({"kind":"self_reported","reason":"custom declaration"});
    let c = support::changed_contract(&v);
    let (_, p, _) = support::load();
    let mut session = support::session_custom(c.clone());
    let mut a = support::adapter::ArithmeticAdapter {
        subject: c.expected_subject().clone(),
        wrong: false,
        calls: 0,
    };
    let o = support::oracle::ArithmeticOracle {
        binding: c.expected_oracle().clone(),
    };
    let report = run_profile(&p, &mut a, &mut session, &o).unwrap();
    assert_eq!(report.qualification(), Qualification::Incomplete);
}
#[test]
fn catalog_and_contract_are_external() {
    let (c, p, _) = support::load();
    let mut bytes = std::fs::read(support::root().join("catalog.json")).unwrap();
    let original = c.source_sha256();
    bytes.push(b' ');
    let different = CaseCatalog::load(&bytes, CatalogLimits::default()).unwrap();
    assert_ne!(different.source_sha256(), original);
    assert_eq!(
        RunContract::load(
            &different,
            &p,
            &std::fs::read(support::root().join("contract.json")).unwrap(),
            RunLimits::default()
        )
        .unwrap_err()
        .kind(),
        HarnessErrorKind::InvalidBinding
    );
}
#[test]
fn wrong_subject_rejected() {
    let (_, p, c) = support::load();
    let v = serde_json::to_value(c.expected_subject()).unwrap();
    for field in [
        "package_version",
        "source_sha256",
        "target",
        "features",
        "backend",
        "consumer",
        "objects",
    ] {
        let mut changed = v.clone();
        changed[field] = match field {
            "source_sha256" => "0".repeat(64).into(),
            "features" => serde_json::json!(["json"]),
            "backend" => {
                serde_json::json!({"name":"other","version":"1","source_sha256":"0".repeat(64)})
            }
            "consumer" => {
                let mut x = changed[field].clone();
                x["executable_sha256"] = "0".repeat(64).into();
                x
            }
            "objects" => {
                serde_json::json!([{"id":"changed-object","revision":1,"role":"final_object","length":"1","sha256":"0".repeat(64)}])
            }
            _ => "other".into(),
        };
        let mut cv = support::contract_value();
        cv["expected_subject"] = changed;
        if field == "objects" {
            let object = cv["expected_subject"]["objects"][0].clone();
            let artifacts = cv["artifacts"].as_array_mut().unwrap();
            artifacts.push(object);
            artifacts.sort_by_key(|a| a["id"].as_str().unwrap().to_owned());
        }
        let bad = support::changed_contract(&cv).expected_subject().clone();
        let mut a = support::adapter::ArithmeticAdapter {
            subject: bad,
            wrong: false,
            calls: 0,
        };
        let o = support::oracle::ArithmeticOracle {
            binding: c.expected_oracle().clone(),
        };
        assert_eq!(
            run_profile(&p, &mut a, &mut support::session(c.clone()), &o)
                .unwrap_err()
                .kind(),
            HarnessErrorKind::InvalidBinding
        );
        assert_eq!(a.calls, 0);
    }
}
#[test]
fn verified_vector_bytes_are_retained() {
    use std::os::unix::fs::FileExt;
    let (_, _, c) = support::load();
    let (p, f) = temp_file(b"2\n3\n");
    let m = VectorManifest::load(
        &c,
        &std::fs::read(support::root().join("bundle.json")).unwrap(),
        c.limits().clone(),
    )
    .unwrap();
    let expected = std::fs::File::open(support::root().join("expected.json")).unwrap();
    let ledger = std::fs::File::open(support::root().join("ledger.json")).unwrap();
    let files = [
        OpenedVector {
            file_id: Label::parse("expected").unwrap(),
            file: &expected,
        },
        OpenedVector {
            file_id: Label::parse("ledger").unwrap(),
            file: &ledger,
        },
        OpenedVector {
            file_id: Label::parse("operands").unwrap(),
            file: &f,
        },
    ];
    let mut meter = ArtifactMeasurer::new(c.run_id().clone(), c.limits().clone()).unwrap();
    let bundle = VectorBundle::read(&m, &files, &mut meter).unwrap();
    f.write_at(b"9\n9\n", 0).unwrap();
    let mut session = VectorFixtureSession::new(c.clone(), bundle).unwrap();
    let r = &c.case_rules()[0];
    let i = CaseInvocation::new(
        CaseInvocationValues {
            key: c.schedule()[0].clone(),
            observation_schema: r.observation_schema().clone(),
            fixture_schema: r.fixture_schema().clone(),
            script: r.script().clone(),
            limits: c.limits().clone(),
        },
        c.limits(),
    )
    .unwrap();
    let access = session.prepare(&i).unwrap();
    assert_eq!(
        access.input(&Label::parse("operands").unwrap()),
        Some(b"2\n3\n".as_slice())
    );
    drop(access);
    assert_eq!(std::fs::read(&p).unwrap(), b"9\n9\n");
    std::fs::remove_file(p).unwrap();
}
#[test]
fn exact_vector_ceiling() {
    let data = vec![b'x'; 8_388_608];
    let (p, file) = temp_file(&data);
    let mut cv = support::contract_value();
    for a in cv["artifacts"].as_array_mut().unwrap() {
        if a["id"] == "operands" {
            a["length"] = "8388608".into();
            a["sha256"] = Digest256::of_bytes(&data).as_str().into();
        }
    }
    let c = support::changed_contract(&cv);
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(support::root().join("bundle.json")).unwrap())
            .unwrap();
    manifest["run_contract_sha256"] = c.sha256().as_str().into();
    for f in manifest["files"].as_array_mut().unwrap() {
        if f["file_id"] == "operands" {
            f["length"] = "8388608".into();
            f["sha256"] = Digest256::of_bytes(&data).as_str().into();
        }
    }
    let expected = std::fs::File::open(support::root().join("expected.json")).unwrap();
    let ledger = std::fs::File::open(support::root().join("ledger.json")).unwrap();
    let opened = [
        OpenedVector {
            file_id: Label::parse("expected").unwrap(),
            file: &expected,
        },
        OpenedVector {
            file_id: Label::parse("ledger").unwrap(),
            file: &ledger,
        },
        OpenedVector {
            file_id: Label::parse("operands").unwrap(),
            file: &file,
        },
    ];
    let admitted = VectorManifest::load(
        &c,
        &serde_json::to_vec(&manifest).unwrap(),
        c.limits().clone(),
    )
    .unwrap();
    let mut meter = ArtifactMeasurer::new(c.run_id().clone(), c.limits().clone()).unwrap();
    VectorBundle::read(&admitted, &opened, &mut meter).unwrap();
    manifest["files"][2]["length"] = "8388609".into();
    assert!(VectorManifest::load(
        &c,
        &serde_json::to_vec(&manifest).unwrap(),
        c.limits().clone()
    )
    .is_err());
    std::fs::remove_file(p).unwrap();
}

#[test]
fn lowered_names_reserve_mandatory_runner_evidence() {
    let (catalog, plan, _) = support::load();
    let mut cv = support::contract_value();
    cv["limits"]["label_bytes"] = "15".into();
    assert_eq!(
        RunContract::load(
            &catalog,
            &plan,
            &serde_json::to_vec(&cv).unwrap(),
            RunLimits::default()
        )
        .unwrap_err()
        .kind(),
        HarnessErrorKind::LimitExceeded
    );
    cv["limits"]["label_bytes"] = "29".into();
    let c = RunContract::load(
        &catalog,
        &plan,
        &serde_json::to_vec(&cv).unwrap(),
        RunLimits::default(),
    )
    .unwrap();
    let mut a = support::adapter::ArithmeticAdapter {
        subject: c.expected_subject().clone(),
        wrong: false,
        calls: 0,
    };
    let o = support::oracle::ArithmeticOracle {
        binding: c.expected_oracle().clone(),
    };
    let r = run_profile(&plan, &mut a, &mut support::session_custom(c.clone()), &o).unwrap();
    assert_eq!(r.qualification(), Qualification::Qualified);
    assert!(RunReport::from_json(
        &c,
        &r.to_json(c.limits().clone()).unwrap(),
        c.limits().clone()
    )
    .is_ok());
    let mut v = RunLimits::default().values();
    v.name_bytes = 5;
    let l = RunLimits::new(v).unwrap();
    assert!(CaseKey::new(
        CaseKeyValues {
            case_id: CaseId::parse("H01.sum").unwrap(),
            case_version: 1,
            cell_id: "model".into()
        },
        &l
    )
    .is_ok());
    assert_eq!(
        CaseKey::new(
            CaseKeyValues {
                case_id: CaseId::parse("H01.sum").unwrap(),
                case_version: 1,
                cell_id: "longer".into()
            },
            &l
        )
        .unwrap_err()
        .kind(),
        HarnessErrorKind::LimitExceeded
    );
    let mut receipt = support::literal();
    receipt["case_results"][0]["reason"] = "x".repeat(65537).into();
    assert_eq!(
        support::imported(&receipt).unwrap_err().kind(),
        HarnessErrorKind::LimitExceeded
    );
}
