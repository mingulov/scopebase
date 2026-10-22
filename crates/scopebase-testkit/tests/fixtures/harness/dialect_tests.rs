// SPDX-License-Identifier: Apache-2.0
use super::support;
use scopebase_testkit::*;
fn label(s: &str) -> Label {
    Label::parse(s).unwrap()
}
fn invocation(script: serde_json::Value) -> CaseInvocation {
    let (_, _, c) = support::load();
    CaseInvocation::new(
        CaseInvocationValues {
            key: c.schedule()[0].clone(),
            observation_schema: c.case_rules()[0].observation_schema().clone(),
            fixture_schema: c.case_rules()[0].fixture_schema().clone(),
            script: OperationScript::load(&serde_json::to_vec(&script).unwrap(), c.limits())
                .unwrap(),
            limits: c.limits().clone(),
        },
        c.limits(),
    )
    .unwrap()
}
fn script(model: bool) -> serde_json::Value {
    serde_json::json!({"schema_version":1,"kind":"steps-v1","schema_id":if model{"tt02-refusal-v1"}else{"tt02-u64-v1"},"steps":[{"step_id":"sum","operation":if model{"emit-model-outcome"}else{"checked-add"},"inputs":["operands"],"parameters":[]}]})
}
fn arithmetic() -> support::adapter::ArithmeticAdapter {
    support::adapter::ArithmeticAdapter {
        subject: support::load().2.expected_subject().clone(),
        wrong: false,
        calls: 0,
    }
}
fn rejection(error: &CaseError) {
    assert_eq!(*error.category(), CaseErrorCategory::UnsupportedSchema);
    assert!(
        error.step_id().is_none()
            && error.completed_steps().is_empty()
            && error.partial_observation().is_none()
            && error.errno().is_none()
    );
    assert_eq!(*error.cause().cause(), RefusalCause::Unknown);
    assert_eq!(error.stage().as_str(), "adapter-schema");
    assert_eq!(error.cause().method().as_str(), "adapter-dialect");
    assert!(error.cause().evidence_ids().is_empty());
    assert!(*error.effects().complete() && error.effects().registrations().is_empty());
}
#[test]
fn s1_all_shipped_dialect_rejections_are_typed() {
    for model in [false, true] {
        for n in 0..if model { 6 } else { 5 } {
            let mut v = script(model);
            match n {
                0 => v["schema_id"] = "unknown-dialect".into(),
                1 => v["steps"][0]["operation"] = "unknown-op".into(),
                2 => v["steps"][0]["inputs"] = serde_json::json!([]),
                3 => v["steps"][0]["inputs"] = serde_json::json!(["operands", "second"]),
                4 => {
                    v["steps"][0]["parameters"] = serde_json::json!([{"kind":"bool","value":true}])
                }
                _ => {
                    let mut next = v["steps"][0].clone();
                    next["step_id"] = "next".into();
                    v["steps"].as_array_mut().unwrap().push(next);
                }
            }
            let i = invocation(v);
            let mut reads = 0;
            let error = if model {
                support::model_adapter::ModelAdapter {
                    arithmetic: arithmetic(),
                }
                .execute_with(&i, |_| {
                    reads += 1;
                    Some(b"2\n3\n".as_slice())
                })
                .unwrap_err()
            } else {
                arithmetic()
                    .execute_with(&i, |_| {
                        reads += 1;
                        Some(b"2\n3\n".as_slice())
                    })
                    .unwrap_err()
            };
            rejection(&error);
            assert_eq!(reads, 0, "dialect must be checked before input access");
        }
    }
}
#[test]
fn s2_whole_script_preflight_precedes_first_read() {
    for field in ["operation", "inputs"] {
        let mut v = script(false);
        let mut next = v["steps"][0].clone();
        next["step_id"] = "next".into();
        next[field] = if field == "operation" {
            "unknown-op".into()
        } else {
            serde_json::json!([])
        };
        v["steps"].as_array_mut().unwrap().push(next);
        let mut reads = 0;
        let error = arithmetic()
            .execute_with(&invocation(v), |_| {
                reads += 1;
                Some(b"2\n3\n".as_slice())
            })
            .unwrap_err();
        rejection(&error);
        assert_eq!(
            reads, 0,
            "second-step syntax must not allow first-step data consumption"
        );
    }
}
#[test]
fn s3_bad_data_is_attempted_invalid_output() {
    for data in [b"02\n3\n".as_slice(), b"bad", b"2\n3\ntrailing"] {
        let i = invocation(script(false));
        let mut reads = 0;
        let error = arithmetic()
            .execute_with(&i, |_| {
                reads += 1;
                Some(data)
            })
            .unwrap_err();
        assert_eq!(*error.category(), CaseErrorCategory::InvalidOutput);
        assert_eq!(error.step_id().as_ref(), Some(&label("sum")));
        assert_eq!(reads, 1);
        assert_eq!(*error.cause().cause(), RefusalCause::Unknown);
    }
    let i = invocation(script(false));
    let err = arithmetic()
        .execute_with(&i, |_| Some(b"18446744073709551615\n1\n"))
        .unwrap_err();
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert!(arithmetic().execute_with(&i, |_| Some(b"2\n3\n")).is_ok());
    let good = include_bytes!("license-input.json");
    let mut bad = vec![b"bad JSON".to_vec()];
    for change in ["category", "cause", "version", "extra", "diagnostic"] {
        let mut v: serde_json::Value = serde_json::from_slice(good).unwrap();
        match change {
            "category" => v["outcome"]["category"] = "unsupported_schema".into(),
            "cause" => v["outcome"]["cause"] = "invented".into(),
            "version" => v["schema_version"] = 2.into(),
            "extra" => v["outcome"]["authority"] = true.into(),
            _ => v["outcome"]["diagnostic_hex"] = "f".into(),
        };
        bad.push(serde_json::to_vec(&v).unwrap());
    }
    let i = invocation(script(true));
    for data in bad {
        let mut reads = 0;
        let error = support::model_adapter::ModelAdapter {
            arithmetic: arithmetic(),
        }
        .execute_with(&i, |_| {
            reads += 1;
            Some(&data)
        })
        .unwrap_err();
        assert_eq!(*error.category(), CaseErrorCategory::InvalidOutput);
        assert_eq!(error.step_id().as_ref(), Some(&label("sum")));
        assert_eq!(reads, 1);
    }
    let error = support::model_adapter::ModelAdapter {
        arithmetic: arithmetic(),
    }
    .execute_with(&i, |_| Some(good))
    .unwrap_err();
    assert_eq!(*error.category(), CaseErrorCategory::Refused);
    assert_eq!(*error.cause().cause(), RefusalCause::License);
    assert!(support::model_adapter::ModelAdapter {
        arithmetic: arithmetic()
    }
    .execute_with(&i, |_| Some(include_bytes!("positive-input.json")))
    .is_ok());
    let mut expected: serde_json::Value =
        serde_json::from_slice(include_bytes!("license-expected.json")).unwrap();
    expected["expected_outcome"]["category"] = "unsupported_schema".into();
    assert!(
        support::model_adapter::expected_value(&serde_json::to_vec(&expected).unwrap()).is_none()
    );
}
fn unsupported_run() -> (RunContract, RunReport) {
    let (_, p, _) = support::load();
    let mut cv = support::contract_value();
    cv["case_rules"][0]["script"]["steps"][0]["operation"] = "unknown-op".into();
    let c = support::changed_contract(&cv);
    let mut a = arithmetic();
    a.subject = c.expected_subject().clone();
    let o = support::oracle::ArithmeticOracle {
        binding: c.expected_oracle().clone(),
    };
    let r = run_profile(&p, &mut a, &mut support::session_custom(c.clone()), &o).unwrap();
    (c, r)
}
#[test]
fn s4_preflight_cannot_synthesize_activity() {
    let (c, r) = unsupported_run();
    assert_eq!(r.qualification(), Qualification::Incomplete);
    let row = &r.case_results()[0];
    for cv in row.coverage() {
        assert_eq!(*cv.raw_achieved(), 1);
        assert_eq!(
            *cv.effective_achieved(),
            if cv.id().as_str() == "setup" { 1 } else { 0 }
        );
    }
    assert_eq!(
        *row.oracle_verdict().unwrap().checks()[0].status(),
        CheckStatus::NotJudged
    );
    assert_eq!(*row.capability().state(), CapabilityState::Unknown);
    assert_eq!(
        RunReport::from_json(
            &c,
            &r.to_json(c.limits().clone()).unwrap(),
            c.limits().clone()
        )
        .unwrap()
        .qualification(),
        Qualification::Incomplete
    );
    assert_eq!(
        support::run(false).qualification(),
        Qualification::Qualified
    );
}
#[test]
fn s5_model_oracle_compares_actual_category_and_independent_checks() {
    let mut data: serde_json::Value =
        serde_json::from_slice(include_bytes!("license-input.json")).unwrap();
    data["outcome"]["category"] = "other".into();
    let bytes = serde_json::to_vec(&data).unwrap();
    let actual: &'static [u8] = Box::leak(bytes.into_boxed_slice());
    let domains = [
        include_bytes!("source-terms.bytes").as_slice(),
        include_bytes!("elf-license.bin").as_slice(),
        include_bytes!("loader-license.bin").as_slice(),
    ];
    assert_eq!(
        support::model_case(actual, support::LICENSE_EXPECTED, "license", domains)
            .1
            .qualification(),
        Qualification::Failed
    );
    struct Preflight(support::model_adapter::ModelAdapter);
    impl ConformanceAdapter for Preflight {
        fn subject(&self) -> SubjectBinding {
            self.0.subject()
        }
        fn execute(
            &mut self,
            i: &CaseInvocation,
            f: &FixtureAccess<'_>,
        ) -> Result<Observation, CaseError> {
            if i.key().case_key().case_id().as_str() == "H01.refusal" {
                Err(support::adapter::preflight_error(i))
            } else {
                self.0.execute(i, f)
            }
        }
        fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
            self.0.retire(r)
        }
    }
    let (p, c) = support::refusal_contract("license");
    let mut s = support::instrumented::Session::new(c.clone());
    s.model_input = Some(support::LICENSE_INPUT);
    s.expected_override = Some(support::LICENSE_EXPECTED);
    let mut a = Preflight(support::model_adapter::ModelAdapter {
        arithmetic: support::adapter::ArithmeticAdapter {
            subject: c.expected_subject().clone(),
            wrong: false,
            calls: 0,
        },
    });
    let o = support::model_oracle::ModelOracle {
        arithmetic: support::oracle::ArithmeticOracle {
            binding: c.expected_oracle().clone(),
        },
        rules: c.case_rules().to_vec(),
        source_terms: b"independent wrong source terms".to_vec(),
        elf_license: domains[1].to_vec(),
        loader_license: domains[2].to_vec(),
        context: include_bytes!("model-context.json").to_vec(),
        objects: c.artifacts().to_vec(),
    };
    let report = run_profile(&p, &mut a, &mut s, &o).unwrap();
    assert_eq!(report.qualification(), Qualification::Failed);
    let row = &report.case_results()[1];
    assert_eq!(*row.capability().state(), CapabilityState::Unknown);
    assert_eq!(
        *row.oracle_verdict()
            .unwrap()
            .checks()
            .iter()
            .find(|x| x.id().as_str() == "input.license-bytes")
            .unwrap()
            .status(),
        CheckStatus::Fail
    );
    assert_eq!(
        *row.effective_checks()
            .iter()
            .find(|x| x.id().as_str() == "refusal.intended-cause")
            .unwrap()
            .status(),
        CheckStatus::NotJudged
    );
}
#[test]
fn s6_literal_receipt_and_intrinsic_controls() {
    let (_, _, c) = support::load();
    let sample = support::adapter::preflight_error(&invocation(script(false)));
    for n in 0..5 {
        let mut values = CaseErrorValues {
            key: sample.key().clone(),
            step_id: None,
            stage: sample.stage().clone(),
            category: CaseErrorCategory::UnsupportedSchema,
            errno: None,
            diagnostic_bytes: vec![],
            cause: sample.cause().clone(),
            completed_steps: vec![],
            partial_observation: None,
            effects: sample.effects().clone(),
        };
        match n {
            0 => values.step_id = Some(label("sum")),
            1 => values.completed_steps = vec![label("sum")],
            2 => values.errno = Some(13),
            3 => {
                values.partial_observation = Some(
                    PartialObservation::new(
                        PartialObservationValues {
                            schema_id: label("tt02-u64-v1"),
                            schema_revision: 1,
                            bytes: vec![],
                        },
                        c.limits(),
                    )
                    .unwrap(),
                )
            }
            _ => {
                values.cause = RefusalEvidence::new(
                    RefusalEvidenceValues {
                        cause: RefusalCause::Permission,
                        method: label("claimed"),
                        evidence_ids: vec![],
                        tier: EvidenceTier::T0,
                    },
                    c.limits(),
                )
                .unwrap()
            }
        };
        assert_eq!(
            CaseError::new(values, c.limits()).unwrap_err().kind(),
            HarnessErrorKind::InvalidInput
        );
    }
    let row: serde_json::Value =
        serde_json::from_slice(include_bytes!("unsupported-row.json")).unwrap();
    let mut receipt = support::literal();
    receipt["case_results"][0] = row;
    receipt["run_terminal"]["qualification"] = "incomplete".into();
    receipt["run_terminal"]["reasons"] =
        serde_json::json!(["case.coverage", "case.intent", "case.not_judged"]);
    let imported = |v: &serde_json::Value| {
        RunReport::from_json(&c, &serde_json::to_vec(v).unwrap(), c.limits().clone())
    };
    let report = imported(&receipt).unwrap();
    assert_eq!(report.origin(), ReportOrigin::Imported);
    assert_eq!(report.qualification(), Qualification::Incomplete);
    let error = match report.case_results()[0].outcome().as_ref().unwrap() {
        CaseOutcome::OperationError(e) => e,
        _ => panic!("literal error"),
    };
    assert_eq!(*error.category(), CaseErrorCategory::UnsupportedSchema);
    for n in 0..10 {
        let mut v = receipt.clone();
        let e = &mut v["case_results"][0]["outcome"]["error"];
        match n {
            0 => e["category"] = "UnsupportedSchema".into(),
            1 => {
                e.as_object_mut().unwrap().remove("step_id");
            }
            2 => e["step_id"] = "sum".into(),
            3 => e["completed_steps"] = serde_json::json!(["sum"]),
            4 => e["errno"] = 13.into(),
            5 => {
                e["partial_observation"] =
                    serde_json::json!({"schema_id":"tt02-u64-v1","schema_revision":1,"bytes":""})
            }
            6 => e["cause"]["cause"] = "permission".into(),
            7 => v["case_results"][0]["coverage"][0]["effective_achieved"] = "1".into(),
            8 => v["run_terminal"]["qualification"] = "qualified".into(),
            _ => {
                e.as_object_mut().unwrap().remove("errno");
            }
        };
        assert!(imported(&v).is_err(), "literal control {n}");
    }
    let mut changed = receipt.clone();
    changed["case_results"][0]["outcome"]["error"]["stage"] = "operation".into();
    changed["case_results"][0]["outcome"]["error"]["diagnostic_bytes"] = "00".into();
    assert_eq!(
        imported(&changed).unwrap().qualification(),
        Qualification::Incomplete
    );
    changed["case_results"][0]["outcome"]["error"]["category"] = "invalid_output".into();
    changed["case_results"][0]["outcome"]["error"]["stage"] = "unsupported-schema".into();
    let report = imported(&changed).unwrap();
    assert!(
        matches!(report.case_results()[0].outcome(),Some(CaseOutcome::OperationError(e))if *e.category()==CaseErrorCategory::InvalidOutput)
    );
    assert_eq!(
        RunReport::from_json(
            &c,
            &report.to_json(c.limits().clone()).unwrap(),
            c.limits().clone()
        )
        .unwrap()
        .origin(),
        ReportOrigin::Imported
    );
}
struct Reject {
    inner: support::adapter::ArithmeticAdapter,
    first_only: bool,
    flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    unknown_batch: bool,
}
impl ConformanceAdapter for Reject {
    fn subject(&self) -> SubjectBinding {
        self.inner.subject()
    }
    fn execute(
        &mut self,
        i: &CaseInvocation,
        f: &FixtureAccess<'_>,
    ) -> Result<Observation, CaseError> {
        if self.first_only && *i.key().operation_id() > 1 {
            return self.inner.execute(i, f);
        }
        if let Some(flag) = &self.flag {
            flag.store(true, std::sync::atomic::Ordering::Release);
        }
        let e = support::adapter::preflight_error(i);
        if !self.unknown_batch {
            return Err(e);
        }
        let l = i.limits();
        let registration = EffectRegistration::new(
            EffectRegistrationValues {
                resource_id: label("preflight-owner"),
                owner: Owner::Adapter,
                origin: i.key().clone(),
                kind: label("owned-state"),
                identity_sha256: Digest256::of_bytes(b"owned state before rejection"),
                recovery_evidence_id: None,
            },
            l,
        )
        .unwrap();
        Err(CaseError::new(
            CaseErrorValues {
                key: i.key().clone(),
                step_id: None,
                stage: e.stage().clone(),
                category: *e.category(),
                errno: None,
                diagnostic_bytes: e.diagnostic_bytes().clone(),
                cause: e.cause().clone(),
                completed_steps: vec![],
                partial_observation: None,
                effects: EffectBatch::new(
                    EffectBatchValues {
                        registrations: vec![registration],
                        complete: false,
                    },
                    l,
                )
                .unwrap(),
            },
            l,
        )
        .unwrap())
    }
    fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
        support::instrumented::retire(
            r,
            support::instrumented::Retirement::Now,
            &RunLimits::default(),
        )
    }
}
fn reject(c: &RunContract) -> Reject {
    Reject {
        inner: support::adapter::ArithmeticAdapter {
            subject: c.expected_subject().clone(),
            wrong: false,
            calls: 0,
        },
        first_only: false,
        flag: None,
        unknown_batch: false,
    }
}
#[test]
fn s7_nonstopping_lifecycle_and_retained_returns() {
    let (_, p, _) = support::load();
    let mut cv = support::contract_value();
    cv["case_rules"][0]["attempts"] = 2.into();
    cv["case_rules"][0]["operation_ids"] = serde_json::json!(["1", "2"]);
    let c = support::with_model_ledgers(cv);
    let mut a = reject(&c);
    a.first_only = true;
    let mut s = support::instrumented::Session::new(c.clone());
    let o = support::oracle::ArithmeticOracle {
        binding: c.expected_oracle().clone(),
    };
    let r = run_profile(&p, &mut a, &mut s, &o).unwrap();
    assert_eq!(r.qualification(), Qualification::Incomplete);
    assert_eq!(
        r.case_results()[0].entered_stages(),
        &vec![
            EnteredStage::Prepare,
            EnteredStage::Execute,
            EnteredStage::Collect,
            EnteredStage::Judge
        ]
    );
    assert_eq!(
        *r.case_results()[1].effective_checks()[0].status(),
        CheckStatus::Pass
    );
    assert!(r
        .cleanup_records()
        .iter()
        .all(|r| *r.status() == CleanupCallStatus::Called));
    for cancelled in [false, true] {
        let (_, p, c) = support::load();
        let mut s = support::instrumented::Session::new(c.clone());
        let mut a = reject(&c);
        if cancelled {
            a.flag = Some(s.flag.clone());
        } else {
            s.collect_error = Some(FixtureErrorCategory::Denied);
        }
        let o = support::oracle::ArithmeticOracle {
            binding: c.expected_oracle().clone(),
        };
        let r = run_profile(&p, &mut a, &mut s, &o).unwrap();
        assert!(
            matches!(r.case_results()[0].outcome(),Some(CaseOutcome::OperationError(e))if *e.category()==CaseErrorCategory::UnsupportedSchema)
        );
        assert!(r.case_results()[0].oracle_verdict().is_none());
        assert_eq!(*r.cleanup_records()[0].status(), CleanupCallStatus::Called);
        assert_eq!(
            RunReport::from_json(
                &c,
                &r.to_json(c.limits().clone()).unwrap(),
                c.limits().clone()
            )
            .unwrap()
            .qualification(),
            Qualification::Incomplete
        );
    }
    let (_, p, _) = support::load();
    let c = support::effect_contract();
    let mut a = reject(&c);
    a.unknown_batch = true;
    let mut s = support::instrumented::Session::new(c.clone());
    let o = support::oracle::ArithmeticOracle {
        binding: c.expected_oracle().clone(),
    };
    let r = run_profile(&p, &mut a, &mut s, &o).unwrap();
    assert_eq!(
        *r.cleanup_records()[0].state_at_run_end(),
        CleanupState::Unresolved
    );
    assert!(!r.cleanup_records()[0].uncertainty_ids().is_empty());
    assert_eq!(r.cleanup_records()[0].transition_ids().len(), 1);
    assert_eq!(r.case_results()[0].effect_batches().len(), 3);
}
#[test]
fn s8_assertion_only_and_real_refusal_boundaries() {
    struct Oracle(OracleBinding);
    impl CaseOracle for Oracle {
        fn identity(&self) -> OracleBinding {
            self.0.clone()
        }
        fn evaluate(
            &self,
            _: &CaseSpec,
            _: &ExpectedEvidence,
            o: &CaseOutcome,
        ) -> AssertionVerdict {
            let l = RunLimits::default();
            AssertionVerdict::new(AssertionVerdictValues{harness:HarnessValidity::Valid,checks:vec![AssertionCheck::new(AssertionCheckValues{id:label("value.equal"),status:if matches!(o,CaseOutcome::OperationError(e)if *e.category()==CaseErrorCategory::UnsupportedSchema){CheckStatus::Pass}else{CheckStatus::Fail},reason:None},&l).unwrap()],capability:CapabilityEvidence::new(CapabilityEvidenceValues{state:CapabilityState::Unknown,method:label("preflight-assertion"),context:"asserts local adapter preflight only".into(),evidence_ids:vec![]},&l).unwrap()},&l).unwrap()
        }
    }
    let (_, p, _) = support::load();
    let mut cv = support::contract_value();
    cv["case_rules"][0]["intent"] = serde_json::json!({"kind":"assertion_only"});
    cv["case_rules"][0]["coverage"] =
        serde_json::json!([{"id":"setup","kind":"setup","minimum":"1","step_ids":["sum"]}]);
    cv["case_rules"][0]["assertions"][0]["requires_coverage"] = serde_json::json!(["setup"]);
    let c = support::changed_contract(&cv);
    let mut s = support::instrumented::Session::new(c.clone());
    let report = run_profile(
        &p,
        &mut reject(&c),
        &mut s,
        &Oracle(c.expected_oracle().clone()),
    )
    .unwrap();
    assert_eq!(report.qualification(), Qualification::Qualified);
    assert_eq!(
        *report.case_results()[0].capability().state(),
        CapabilityState::Unknown
    );
    let (_, p, c) = support::load();
    let mut s = support::instrumented::Session::new(c.clone());
    let r = run_profile(
        &p,
        &mut reject(&c),
        &mut s,
        &support::oracle::ArithmeticOracle {
            binding: c.expected_oracle().clone(),
        },
    )
    .unwrap();
    assert_eq!(
        r.qualification(),
        Qualification::Incomplete,
        "always rejecting a valid positive cannot qualify"
    );
    assert_eq!(
        support::run(false).qualification(),
        Qualification::Qualified
    );
    let domains = [
        include_bytes!("source-terms.bytes").as_slice(),
        include_bytes!("elf-license.bin").as_slice(),
        include_bytes!("loader-license.bin").as_slice(),
    ];
    let (_, r) = support::model_case(
        include_bytes!("unsupported-input.json"),
        include_bytes!("unsupported-expected.json"),
        "unsupported_operation",
        domains,
    );
    assert_eq!(r.qualification(), Qualification::Qualified);
    assert!(
        matches!(r.case_results()[1].outcome(),Some(CaseOutcome::OperationError(e))if *e.category()==CaseErrorCategory::Refused&&*e.cause().cause()==RefusalCause::UnsupportedOperation&&e.step_id().is_some())
    );
}
