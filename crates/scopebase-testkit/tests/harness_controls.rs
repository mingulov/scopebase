// SPDX-License-Identifier: Apache-2.0
use scopebase_testkit::*;
#[path = "fixtures/harness/review_r1.rs"]
mod review_r1;
#[path = "fixtures/harness/support.rs"]
mod support;
#[test]
fn oracle_wrong_value() {
    assert_eq!(support::run(true).qualification(), Qualification::Failed);
    assert_eq!(
        support::run(false).qualification(),
        Qualification::Qualified
    );
}
#[test]
fn script_and_bundle_contract() {
    let (_, _, c) = support::load();
    let mut v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(support::root().join("bundle.json")).unwrap())
            .unwrap();
    v["run_id"] = "00000000000000000000000000000000".into();
    assert!(
        VectorManifest::load(&c, &serde_json::to_vec(&v).unwrap(), RunLimits::default()).is_err()
    );
    assert!(OperationScript::load(
        br#"{"schema_version":1,"kind":"shell","schema_id":"x","steps":[]}"#,
        &RunLimits::default()
    )
    .is_err());
}
#[test]
fn duplicate_terminal() {
    let (_, _, c) = support::load();
    let b = std::fs::read(support::root().join("receipt-qualified.json")).unwrap();
    let text = String::from_utf8(b).unwrap();
    let dup = text.replacen("\"terminal\":{", "\"terminal\":null,\"terminal\":{", 1);
    assert_eq!(
        RunReport::from_json(&c, dup.as_bytes(), RunLimits::default())
            .unwrap_err()
            .kind(),
        HarnessErrorKind::InvalidInput
    );
    let mut v = support::literal();
    v["run_terminal"]["after_cleanup_call_id"] = "2".into();
    assert!(support::imported(&v).is_err());
    let mut v = support::literal();
    v["case_results"][0]["terminal"] = serde_json::Value::Null;
    assert_eq!(support::partial_q(&mut v), Qualification::Incomplete);
    assert_eq!(
        support::imported(&support::literal())
            .unwrap()
            .qualification(),
        Qualification::Qualified
    );
}
#[test]
fn silent_filtering() {
    let mut v = support::literal();
    v["selection"]["required"][0]["case_version"] = 2.into();
    assert_eq!(
        support::imported(&v).unwrap_err().kind(),
        HarnessErrorKind::InvalidBinding
    );
    let mut v = support::literal();
    v["selection"]["extensions"] = serde_json::json!(["unselected-v1"]);
    assert!(support::imported(&v).is_err());
    assert_eq!(
        support::imported(&support::literal())
            .unwrap()
            .qualification(),
        Qualification::Qualified
    );
}
#[test]
fn missing_trigger() {
    for id in ["setup", "trigger", "positive", "excluded"] {
        let (c, v) = support::change_coverage(id, "0");
        let r = RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), RunLimits::default())
            .unwrap();
        assert_eq!(r.qualification(), Qualification::Incomplete);
        assert_eq!(
            *r.case_results()[0].effective_checks()[0].status(),
            CheckStatus::NotJudged
        );
    }
    assert_eq!(
        support::imported(&support::literal())
            .unwrap()
            .qualification(),
        Qualification::Qualified
    );
}
#[test]
fn inactive_excluded_target() {
    let mut v = support::literal();
    v["case_results"][0]["outcome"]["observation"]["completed_steps"] = serde_json::json!([]);
    assert!(support::imported(&v).is_err());
    let mut v = support::literal();
    v["case_results"][0]["expected_evidence"]["coverage"][0]["achieved"] = "0".into();
    assert!(support::imported(&v).is_err());
    assert_eq!(
        support::imported(&support::literal())
            .unwrap()
            .qualification(),
        Qualification::Qualified
    );
}
use support::instrumented as ins;
fn run_session(s: &mut ins::Session<'_>, a: &mut ins::Adapter) -> Result<RunReport, HarnessError> {
    let (_, p, _) = support::load();
    let o = support::oracle::ArithmeticOracle {
        binding: s.c.expected_oracle().clone(),
    };
    run_profile(&p, a, s, &o)
}
#[test]
fn cleanup_survives_zero_exit() {
    let c = support::effect_contract();
    let mut s = ins::Session::new(c.clone());
    s.effect = true;
    s.mode = ins::Retirement::Pending;
    let mut a = ins::adapter(&s);
    let r = run_session(&mut s, &mut a).unwrap();
    assert_eq!(r.qualification(), Qualification::Incomplete);
    assert_eq!(
        *r.cleanup_records()[1].state_at_run_end(),
        CleanupState::Unresolved
    );
    let mut s = ins::Session::new(c.clone());
    s.effect = true;
    s.mode = ins::Retirement::Now;
    let mut a = ins::adapter(&s);
    assert_eq!(
        run_session(&mut s, &mut a).unwrap().qualification(),
        Qualification::Qualified
    );
    let mut s = ins::Session::new(c);
    s.effect = true;
    s.mode = ins::Retirement::Omit;
    let mut a = ins::adapter(&s);
    let err = run_session(&mut s, &mut a).unwrap_err();
    assert_eq!(err.kind(), HarnessErrorKind::InvalidProtocol);
    assert!(err.partial_report().is_some());
}
#[test]
fn case_to_run_ledger_reconciliation() {
    let c = support::effect_contract();
    let mut s = ins::Session::new(c);
    s.effect = true;
    s.mode = ins::Retirement::AtRun;
    let mut a = ins::adapter(&s);
    let r = run_session(&mut s, &mut a).unwrap();
    assert_eq!(r.qualification(), Qualification::Qualified);
    assert_eq!(
        *r.cleanup_records()[1].state_at_case_end(),
        Some(CleanupState::Unresolved)
    );
    assert_eq!(
        *r.cleanup_records()[1].state_at_run_end(),
        CleanupState::Complete
    );
    assert_eq!(r.cleanup_records()[3].transition_ids().len(), 1);
}
#[test]
fn participation_and_empty_effects() {
    let (_, _, c) = support::load();
    let mut s = ins::Session::new(c.clone());
    let mut a = ins::adapter(&s);
    let r = run_session(&mut s, &mut a).unwrap();
    assert_eq!(r.cleanup_records().len(), 4);
    assert!(r
        .cleanup_records()
        .iter()
        .all(|r| *r.status() == CleanupCallStatus::Called
            && *r.state_at_run_end() == CleanupState::NotRequired));
    let mut s = ins::Session::new(c);
    s.prepare_error = Some(FixtureErrorCategory::Denied);
    let mut a = ins::adapter(&s);
    let r = run_session(&mut s, &mut a).unwrap();
    assert_eq!(
        *r.cleanup_records()[0].status(),
        CleanupCallStatus::UncalledNoParticipation
    );
    assert_eq!(*r.cleanup_records()[1].status(), CleanupCallStatus::Called);
    assert_eq!(r.qualification(), Qualification::Incomplete);
}
#[test]
fn owned_probe_during_fixture_borrow() {
    let (_, _, c) = support::load();
    let owner = ins::NonClone(123);
    let mut s = ins::Session::new(c);
    s.resources
        .push(FixtureResource::new(ins::label("actual-owner"), &owner));
    let mut a = ins::adapter(&s);
    a.require_resource = true;
    let r = run_session(&mut s, &mut a).unwrap();
    assert_eq!(r.qualification(), Qualification::Qualified);
    assert!(s.polls.load(std::sync::atomic::Ordering::Acquire) >= 11);
}
#[test]
fn shared_probe_cancellation_and_sealing() {
    let (_, _, c) = support::load();
    for prepare in [true, false] {
        let mut s = ins::Session::new(c.clone());
        s.cancel_prepare = prepare;
        let mut a = ins::adapter(&s);
        a.cancel_execute = !prepare;
        let r = run_session(&mut s, &mut a).unwrap();
        assert_eq!(r.qualification(), Qualification::Incomplete);
        assert_eq!(r.case_results()[0].outcome().is_some(), !prepare);
        assert!(!s.events.borrow().iter().any(|e| e == "collect"));
        assert!(r
            .cleanup_records()
            .iter()
            .any(|r| *r.status() == CleanupCallStatus::Called));
    }
    let mut s = support::session(c);
    let p = s.cancellation_probe();
    assert!(!p.cancellation_requested());
    assert_eq!(
        *s.set_cancellation(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
            false
        )))
        .unwrap_err()
        .category(),
        FixtureErrorCategory::InvalidProtocol
    );
}
#[test]
fn probe_acquired_once_before_effects() {
    let (_, _, c) = support::load();
    let mut s = ins::Session::new(c);
    let mut a = ins::adapter(&s);
    run_session(&mut s, &mut a).unwrap();
    assert_eq!(s.acquisitions, 1);
    let e = s.events.borrow();
    assert_eq!(&e[..3], ["contract", "probe", "subject"]);
    assert!(e.iter().position(|x| x == "prepare").unwrap() > 2);
}
#[test]
fn cancellation_after_each_barrier() {
    let (_, _, c) = support::load();
    for poll in 1..=16 {
        let mut s = ins::Session::new(c.clone());
        s.cancel_at = poll;
        let mut a = ins::adapter(&s);
        let r = run_session(&mut s, &mut a).unwrap();
        assert_eq!(r.qualification(), Qualification::Incomplete, "poll {poll}");
        assert_eq!(r.cleanup_records().len(), 4);
        assert!(r.reasons().iter().any(|l| l.as_str() == "runner.cancelled"));
    }
    assert_eq!(
        support::run(false).qualification(),
        Qualification::Qualified
    );
}
#[test]
fn setup_is_not_negative() {
    let (_, _, c) = support::load();
    let mut s = ins::Session::new(c);
    s.prepare_error = Some(FixtureErrorCategory::Denied);
    let mut a = ins::adapter(&s);
    let r = run_session(&mut s, &mut a).unwrap();
    assert!(r.case_results()[0].outcome().is_none());
    assert!(r.case_results()[0].oracle_verdict().is_none());
    assert_eq!(r.qualification(), Qualification::Incomplete);
}
#[test]
fn prelude_and_unimplemented_paths() {
    let (p, c) = support::unimplemented();
    let mut s = ins::Session::new(c.clone());
    let mut a = ins::adapter(&s);
    let o = support::oracle::ArithmeticOracle {
        binding: c.expected_oracle().clone(),
    };
    let r = run_profile(&p, &mut a, &mut s, &o).unwrap();
    assert_eq!(r.qualification(), Qualification::Incomplete);
    assert_eq!(r.case_results()[0].entered_stages().len(), 0);
    assert_eq!(s.events.borrow().as_slice(), ["contract", "probe"]);
    assert_eq!(s.polls.load(std::sync::atomic::Ordering::Acquire), 2);
    assert!(r
        .cleanup_records()
        .iter()
        .all(|r| *r.status() == CleanupCallStatus::UncalledNoParticipation));
    let bytes = r.to_json(c.limits().clone()).unwrap();
    assert_eq!(
        RunReport::from_json(&c, &bytes, c.limits().clone())
            .unwrap()
            .qualification(),
        Qualification::Incomplete
    );
    let mut catalog: serde_json::Value =
        serde_json::from_slice(&std::fs::read(support::root().join("catalog.json")).unwrap())
            .unwrap();
    catalog["profiles"][0]["required_cases"] = serde_json::json!([]);
    catalog["profiles"][0]["definition_state"] = "DRAFT".into();
    catalog["profiles"][0]["open_owners"] = serde_json::json!(["TT02"]);
    let b = serde_json::to_vec(&catalog).unwrap();
    let cat = CaseCatalog::load(&b, CatalogLimits::default()).unwrap();
    let p = ProfilePlan::select(&cat, &ProfileId::parse("tt02-harness-v1").unwrap()).unwrap();
    let mut cv = support::contract_value();
    cv["catalog_sha256"] = cat.source_sha256().as_str().into();
    assert_eq!(
        RunContract::load(
            &cat,
            &p,
            &serde_json::to_vec(&cv).unwrap(),
            RunLimits::default()
        )
        .unwrap_err()
        .kind(),
        HarnessErrorKind::InvalidSelection
    );
}
#[test]
fn probe_no_effect_prelude_paths() {
    prelude_and_unimplemented_paths();
    let (_, p, c) = support::load();
    let mut s = ins::Session::new(c.clone());
    let mut a = ins::adapter(&s);
    let mut cv = support::contract_value();
    cv["expected_subject"]["package_version"] = "0.2.0".into();
    a.inner.subject = support::changed_contract(&cv).expected_subject().clone();
    let o = support::oracle::ArithmeticOracle {
        binding: c.expected_oracle().clone(),
    };
    let err = run_profile(&p, &mut a, &mut s, &o).unwrap_err();
    assert_eq!(err.kind(), HarnessErrorKind::InvalidBinding);
    assert!(err.partial_report().is_none());
    assert!(!s
        .events
        .borrow()
        .iter()
        .any(|e| e == "prepare" || e.starts_with("retire")));
}
fn model_run(
    actual: &'static [u8],
    cause: &str,
    blocked_twin: bool,
    wrong_bytes: bool,
) -> RunReport {
    let (p, c) = support::refusal_contract_inputs(
        cause,
        actual,
        support::LICENSE_EXPECTED,
        if wrong_bytes {
            b"incompatible model source grant"
        } else {
            include_bytes!("fixtures/harness/source-terms.bytes")
        },
        include_bytes!("fixtures/harness/elf-license.bin"),
        include_bytes!("fixtures/harness/loader-license.bin"),
    );
    let mut s = ins::Session::new(c.clone());
    s.model_input = Some(actual);
    s.expected_override = Some(support::LICENSE_EXPECTED);
    s.prepare_error = if blocked_twin {
        Some(FixtureErrorCategory::Denied)
    } else {
        None
    };
    s.error_twin_only = blocked_twin;
    let mut a = support::model_adapter::ModelAdapter {
        arithmetic: support::adapter::ArithmeticAdapter {
            subject: c.expected_subject().clone(),
            wrong: false,
            calls: 0,
        },
    };
    let o = support::model_oracle::ModelOracle {
        arithmetic: support::oracle::ArithmeticOracle {
            binding: c.expected_oracle().clone(),
        },
        rules: c.case_rules().to_vec(),
        source_terms: if wrong_bytes {
            b"incompatible model source grant".to_vec()
        } else {
            include_bytes!("fixtures/harness/source-terms.bytes").to_vec()
        },
        elf_license: include_bytes!("fixtures/harness/elf-license.bin").to_vec(),
        loader_license: include_bytes!("fixtures/harness/loader-license.bin").to_vec(),
        context: include_bytes!("fixtures/harness/model-context.json").to_vec(),
        objects: c.artifacts().to_vec(),
    };
    run_profile(&p, &mut a, &mut s, &o).unwrap()
}
#[test]
fn h33_cause_discriminators() {
    complete_model_refusal_matrix();
    let r = model_run(support::LICENSE_INPUT, "license", false, false);
    assert_eq!(r.qualification(), Qualification::Qualified);
    let ambiguous=br#"{"schema_version":1,"kind":"tt02-model-outcome","outcome":{"kind":"error","stage":"load","category":"refused","errno":13,"cause":"unknown","diagnostic_hex":"47504c2d6f6e6c792068656c706572"}}"#;
    assert_eq!(
        model_run(ambiguous, "license", false, false).qualification(),
        Qualification::Incomplete
    );
    let wrong=br#"{"schema_version":1,"kind":"tt02-model-outcome","outcome":{"kind":"error","stage":"load","category":"refused","errno":13,"cause":"verifier","diagnostic_hex":"756e696e697469616c697a656420737461636b"}}"#;
    assert_eq!(
        model_run(wrong, "license", false, false).qualification(),
        Qualification::Failed
    );
    assert_eq!(
        model_run(support::LICENSE_INPUT, "license", false, false).qualification(),
        Qualification::Qualified
    );
}
#[test]
fn h33_license_domains() {
    each_model_license_domain_has_a_negative();
    assert_eq!(
        model_run(support::LICENSE_INPUT, "license", false, true).qualification(),
        Qualification::Failed
    );
    assert_eq!(
        model_run(support::LICENSE_INPUT, "license", false, false).qualification(),
        Qualification::Qualified
    );
}
#[test]
fn partial_steps_do_not_invent_activity() {
    let (_, _, c) = support::load();
    let mut a = support::adapter::ArithmeticAdapter {
        subject: c.expected_subject().clone(),
        wrong: false,
        calls: 0,
    };
    let script=OperationScript::load(br#"{"schema_version":1,"kind":"steps-v1","schema_id":"tt02-u64-v1","steps":[{"step_id":"first","operation":"checked-add","inputs":["good"],"parameters":[]},{"step_id":"overflow","operation":"checked-add","inputs":["bad"],"parameters":[]},{"step_id":"third","operation":"decimal-length","inputs":["good"],"parameters":[]}]}"#,c.limits()).unwrap();
    let inputs = [
        FixtureInput::new(ins::label("good"), b"2\n3\n"),
        FixtureInput::new(ins::label("bad"), b"18446744073709551615\n1\n"),
    ];
    let access =
        FixtureAccess::new(&inputs, &[], EffectBatch::empty(c.limits()), c.limits()).unwrap();
    let i = CaseInvocation::new(
        CaseInvocationValues {
            key: c.schedule()[0].clone(),
            observation_schema: c.case_rules()[0].observation_schema().clone(),
            fixture_schema: c.case_rules()[0].fixture_schema().clone(),
            script,
            limits: c.limits().clone(),
        },
        c.limits(),
    )
    .unwrap();
    let err = a.execute(&i, &access).unwrap_err();
    assert_eq!(err.completed_steps(), &[ins::label("first")]);
    assert_eq!(err.step_id().as_ref(), Some(&ins::label("overflow")));
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(*err.cause().cause(), RefusalCause::Unknown);
    let prefix: serde_json::Value =
        serde_json::from_slice(err.partial_observation().as_ref().unwrap().bytes()).unwrap();
    assert_eq!(
        prefix["steps"],
        serde_json::json!([{"step_id":"first","value":"5"}])
    );
    assert!(!err.completed_steps().contains(&ins::label("third")));
    partial_steps_runner_gates_authored_third_step();
}
#[test]
fn complete_model_refusal_matrix() {
    let domains = [
        include_bytes!("fixtures/harness/source-terms.bytes").as_slice(),
        include_bytes!("fixtures/harness/elf-license.bin").as_slice(),
        include_bytes!("fixtures/harness/loader-license.bin").as_slice(),
    ];
    for (input, expected, cause, cap) in [
        (
            include_bytes!("fixtures/harness/permission-input.json").as_slice(),
            include_bytes!("fixtures/harness/permission-expected.json").as_slice(),
            "permission",
            CapabilityState::Denied,
        ),
        (
            include_bytes!("fixtures/harness/verifier-input.json").as_slice(),
            include_bytes!("fixtures/harness/verifier-expected.json").as_slice(),
            "verifier",
            CapabilityState::Incompatible,
        ),
        (
            support::LICENSE_INPUT,
            support::LICENSE_EXPECTED,
            "license",
            CapabilityState::Incompatible,
        ),
        (
            include_bytes!("fixtures/harness/unsupported-input.json").as_slice(),
            include_bytes!("fixtures/harness/unsupported-expected.json").as_slice(),
            "unsupported_operation",
            CapabilityState::Unsupported,
        ),
    ] {
        let (c, r) = support::model_case(input, expected, cause, domains);
        assert_eq!(r.qualification(), Qualification::Qualified);
        assert_eq!(*r.case_results()[1].capability().state(), cap);
        let b = r.to_json(c.limits().clone()).unwrap();
        assert_eq!(
            RunReport::from_json(&c, &b, c.limits().clone())
                .unwrap()
                .qualification(),
            Qualification::Qualified
        );
        for state in ["supported", "unknown", "not_applicable"] {
            let mut v: serde_json::Value = serde_json::from_slice(&b).unwrap();
            v["case_results"][1]["capability"]["state"] = state.into();
            v["case_results"][1]["oracle_verdict"]["capability"]["state"] = state.into();
            v["run_terminal"]["qualification"] = "incomplete".into();
            v["run_terminal"]["reasons"] = serde_json::json!(["case.intent"]);
            assert_eq!(
                RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), c.limits().clone())
                    .unwrap()
                    .qualification(),
                Qualification::Incomplete
            );
        }
    }
}
#[test]
fn each_model_license_domain_has_a_negative() {
    let valid = [
        include_bytes!("fixtures/harness/source-terms.bytes").as_slice(),
        include_bytes!("fixtures/harness/elf-license.bin").as_slice(),
        include_bytes!("fixtures/harness/loader-license.bin").as_slice(),
    ];
    for index in 0..3 {
        let mut wrong = valid;
        wrong[index] = b"wrong domain bytes";
        let (_, r) = support::model_case(
            support::LICENSE_INPUT,
            support::LICENSE_EXPECTED,
            "license",
            wrong,
        );
        assert_eq!(r.qualification(), Qualification::Failed);
        assert_eq!(
            *r.case_results()[1]
                .effective_checks()
                .iter()
                .find(|a| a.id().as_str() == "input.license-bytes")
                .unwrap()
                .status(),
            CheckStatus::Fail
        );
    }
    assert_eq!(
        support::model_case(
            support::LICENSE_INPUT,
            support::LICENSE_EXPECTED,
            "license",
            valid
        )
        .1
        .qualification(),
        Qualification::Qualified
    );
}

#[test]
fn partial_steps_runner_gates_authored_third_step() {
    struct Session {
        inner: ins::Session<'static>,
        inputs: Vec<FixtureInput<'static>>,
        evidence: ExpectedEvidence,
    }
    impl FixtureSession for Session {
        fn contract(&self) -> &RunContract {
            self.inner.contract()
        }
        fn cancellation_probe(&mut self) -> Box<dyn CancellationProbe + 'static> {
            self.inner.cancellation_probe()
        }
        fn prepare(&mut self, i: &CaseInvocation) -> Result<FixtureAccess<'_>, FixtureError> {
            let access = self.inner.prepare(i)?;
            let effects = access.effects().clone();
            drop(access);
            FixtureAccess::new(&self.inputs, &[], effects, self.inner.c.limits())
        }
        fn collect(&mut self, _: &CaseInvocation) -> Result<ExpectedEvidence, FixtureError> {
            Ok(self.evidence.clone())
        }
        fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
            self.inner.retire(r)
        }
    }
    let (_, plan, _) = support::load();
    for overflow in [true, false] {
        let mut cv = support::contract_value();
        cv["case_rules"][0]["script"]["steps"] = serde_json::json!([
            {"step_id":"first","operation":"checked-add","inputs":["good"],"parameters":[]},
            {"step_id":"overflow","operation":"checked-add","inputs":["second"],"parameters":[]},
            {"step_id":"third","operation":"decimal-length","inputs":["last"],"parameters":[]}
        ]);
        cv["case_rules"][0]["intent"] = serde_json::json!({"kind":if overflow { "assertion_only" } else { "positive_support" }});
        for need in cv["case_rules"][0]["coverage"].as_array_mut().unwrap() {
            need["step_ids"] = serde_json::json!(["third"]);
        }
        let expected = br#"{"schema_version":1,"kind":"tt02-u64-expected","steps":[{"step_id":"first","value":"5"},{"step_id":"overflow","value":"3"},{"step_id":"third","value":"1"}]}"#;
        let mut ledger: serde_json::Value =
            serde_json::from_slice(include_bytes!("fixtures/harness/ledger.json")).unwrap();
        for need in ledger["coverage"].as_array_mut().unwrap() {
            need["step_ids"] = serde_json::json!(["third"]);
        }
        let ledger_bytes = serde_json::to_vec(&ledger).unwrap();
        for (id, bytes) in [
            ("expected", expected.as_slice()),
            ("ledger", ledger_bytes.as_slice()),
        ] {
            let artifact = cv["artifacts"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|a| a["id"] == id)
                .unwrap();
            artifact["sha256"] = Digest256::of_bytes(bytes).as_str().into();
            artifact["length"] = bytes.len().to_string().into();
        }
        let second: &'static [u8] = if overflow {
            b"18446744073709551615\n1\n"
        } else {
            b"1\n2\n"
        };
        for (id, bytes) in [
            ("good", b"2\n3\n".as_slice()),
            ("second", second),
            ("last", b"9\n".as_slice()),
        ] {
            cv["artifacts"].as_array_mut().unwrap().push(serde_json::json!({"id":id,"revision":1,"role":"fixture_input","length":bytes.len().to_string(),"sha256":Digest256::of_bytes(bytes).as_str()}));
        }
        cv["artifacts"]
            .as_array_mut()
            .unwrap()
            .sort_by_key(|a| a["id"].as_str().unwrap().to_owned());
        let c = support::changed_contract(&cv);
        let coverage = c.case_rules()[0]
            .coverage()
            .iter()
            .map(|r| {
                CoverageEvidence::new(
                    CoverageEvidenceValues {
                        id: r.id().clone(),
                        step_ids: r.step_ids().clone(),
                        achieved: 1,
                    },
                    c.limits(),
                )
                .unwrap()
            })
            .collect();
        let evidence = ExpectedEvidence::new(
            ExpectedEvidenceValues {
                key: c.schedule()[0].clone(),
                oracle: c.expected_oracle().clone(),
                fixture_schema: c.case_rules()[0].fixture_schema().clone(),
                truth_kind: TruthKind::IndependentLedger,
                expected_bytes: expected.to_vec(),
                ledger_bytes,
                coverage,
                effects: EffectBatch::empty(c.limits()),
            },
            c.limits(),
        )
        .unwrap();
        let inner = ins::Session::new(c.clone());
        let mut adapter = ins::adapter(&inner);
        let mut session = Session {
            inner,
            inputs: vec![
                FixtureInput::new(ins::label("good"), b"2\n3\n"),
                FixtureInput::new(ins::label("second"), second),
                FixtureInput::new(ins::label("last"), b"9\n"),
            ],
            evidence,
        };
        let oracle = support::oracle::ArithmeticOracle {
            binding: c.expected_oracle().clone(),
        };
        let report = run_profile(&plan, &mut adapter, &mut session, &oracle).unwrap();
        assert_eq!(
            report.qualification(),
            if overflow {
                Qualification::Incomplete
            } else {
                Qualification::Qualified
            },
            "qualification reasons {:?}; outcome {:?}",
            report.reasons(),
            report.case_results()[0].outcome()
        );
        let row = &report.case_results()[0];
        if overflow {
            let CaseOutcome::OperationError(error) = row.outcome().as_ref().unwrap() else {
                panic!("required checked overflow");
            };
            assert_eq!(error.completed_steps(), &[ins::label("first")]);
            assert_eq!(error.partial_observation().as_ref().unwrap().bytes(), br#"{"kind":"tt02-u64-observation","schema_version":1,"steps":[{"step_id":"first","value":"5"}]}"#);
            assert_eq!(*row.effective_checks()[0].status(), CheckStatus::NotJudged);
            for coverage in row.coverage().iter().filter(|x| x.id().as_str() != "setup") {
                assert_eq!(*coverage.raw_achieved(), 1);
                assert_eq!(*coverage.effective_achieved(), 0, "third step never ran");
            }
        }
        let imported = RunReport::from_json(
            &c,
            &report.to_json(c.limits().clone()).unwrap(),
            c.limits().clone(),
        )
        .unwrap();
        assert_eq!(imported.qualification(), report.qualification());
    }
}

#[path = "fixtures/harness/dialect_tests.rs"]
mod dialect_tests;
