// SPDX-License-Identifier: Apache-2.0
use scopebase_testkit::*;
#[path = "fixtures/harness/support.rs"]
mod support;
#[test]
fn precedence_truth_table() {
    independent_cartesian_truth_table();
    assert_eq!(
        support::run(false).qualification(),
        Qualification::Qualified
    );
    assert_eq!(support::run(true).qualification(), Qualification::Failed);
}
#[test]
fn receipt_cannot_mint_authority() {
    let (_, _, c) = support::load();
    let report = support::run(false);
    let bytes = report.to_json(RunLimits::default()).unwrap();
    let imported = RunReport::from_json(&c, &bytes, RunLimits::default()).unwrap();
    assert_eq!(imported.origin(), ReportOrigin::Imported);
    assert_eq!(imported.qualification(), Qualification::Qualified);
}
#[test]
fn receipt_strictness_and_recomputation() {
    strict_receipt_populations();
    let (_, _, c) = support::load();
    let report = support::run(false);
    let bytes = report.to_json(RunLimits::default()).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["run_terminal"]["qualification"] = "failed".into();
    assert_eq!(
        RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), RunLimits::default())
            .unwrap_err()
            .kind(),
        HarnessErrorKind::InvalidProtocol
    );
}
#[test]
fn externally_authored_receipts() {
    let (_, _, c) = support::load();
    for (name, q) in [
        ("receipt-qualified.json", Qualification::Qualified),
        ("receipt-failed.json", Qualification::Failed),
    ] {
        let b = std::fs::read(support::root().join(name)).unwrap();
        let r = RunReport::from_json(&c, &b, RunLimits::default()).unwrap();
        assert_eq!(r.qualification(), q);
        assert_eq!(r.origin(), ReportOrigin::Imported)
    }
}
#[test]
fn final_subject_drift_is_serialized() {
    for field in ["source_sha256", "build_inputs_sha256"] {
        let mut v = support::literal();
        v["runner_observations"]["final_subject"]["value"][field] = "0".repeat(64).into();
        omit_meta(&mut v, "final_oracle", "prior_stop");
        assert_eq!(support::partial_q(&mut v), Qualification::Invalid);
        v["run_terminal"] = support::literal()["run_terminal"].clone();
        assert_eq!(
            support::imported(&v).unwrap_err().kind(),
            HarnessErrorKind::InvalidProtocol
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
fn final_oracle_drift_is_serialized() {
    for field in ["revision", "source_sha256", "schema_id", "artifact_id"] {
        let mut v = support::literal();
        v["runner_observations"]["final_oracle"]["value"][field] = match field {
            "revision" => 2.into(),
            "source_sha256" => "0".repeat(64).into(),
            _ => "changed".into(),
        };
        assert_eq!(support::partial_q(&mut v), Qualification::Invalid);
    }
    assert_eq!(
        support::imported(&support::literal())
            .unwrap()
            .qualification(),
        Qualification::Qualified
    );
}
fn omit_meta(v: &mut serde_json::Value, name: &str, cause: &str) {
    v["runner_observations"][name] = serde_json::json!({"checkpoints":{"before":{"kind":"omitted","cause":cause},"after":{"kind":"omitted","cause":"not_entered"}},"value":null,"returned_elapsed_ns":null});
}
#[test]
fn final_check_unavailable_is_not_entry_reuse() {
    let mut v = support::literal();
    v["runner_observations"]["final_subject"]["checkpoints"]["before"]["sample"]["cancelled"] =
        true.into();
    v["runner_observations"]["final_subject"]["checkpoints"]["after"] =
        serde_json::json!({"kind":"omitted","cause":"not_entered"});
    v["runner_observations"]["final_subject"]["value"] = serde_json::Value::Null;
    v["runner_observations"]["final_subject"]["returned_elapsed_ns"] = serde_json::Value::Null;
    omit_meta(&mut v, "final_oracle", "prior_stop");
    assert_eq!(support::partial_q(&mut v), Qualification::Incomplete);
    let copied = support::literal()["runner_observations"]["entry_subject"]["value"].clone();
    v["runner_observations"]["final_subject"]["value"] = copied;
    v["runner_observations"]["final_subject"]["returned_elapsed_ns"] = "48".into();
    assert_eq!(
        support::imported(&v).unwrap_err().kind(),
        HarnessErrorKind::InvalidProtocol
    );
}
#[test]
fn late_runner_stops_survive_successful_cases() {
    for (cancel, time) in [(true, "57"), (false, "30000000000")] {
        let mut v = support::literal();
        v["runner_observations"]["completion"]["sample"]["cancelled"] = cancel.into();
        v["runner_observations"]["completion"]["sample"]["poll_finished_elapsed_ns"] = time.into();
        assert_eq!(support::partial_q(&mut v), Qualification::Incomplete);
        v["case_results"][0]["oracle_verdict"]["checks"][0]["status"] = "fail".into();
        v["case_results"][0]["effective_checks"][0]["status"] = "fail".into();
        assert_eq!(support::partial_q(&mut v), Qualification::Failed);
    }
    assert_eq!(
        support::imported(&support::literal())
            .unwrap()
            .qualification(),
        Qualification::Qualified
    );
}
#[test]
fn runner_observations_are_not_terminal_reasons() {
    let base = support::literal();
    for n in 0..6 {
        let mut v = base.clone();
        match n {
            0 => v["run_terminal"]["reasons"] = serde_json::json!(["runner.cancelled"]),
            1 => v["runner_observations"]["completion"]["sample"]["cancelled"] = true.into(),
            2 => {
                v["runner_observations"]["entry_subject"]["checkpoints"]["after"]["sample"]
                    ["poll_started_elapsed_ns"] = "0".into()
            }
            3 => {
                v["case_results"][0]["execution_checkpoints"]["execute"]["after"] =
                    serde_json::json!({"kind":"omitted","cause":"not_entered"})
            }
            4 => {
                v["case_results"][0]["execution_checkpoints"]["prepare"]["before"]["sample"]
                    ["cancelled"] = true.into()
            }
            _ => {
                v["runner_observations"]["completion"]["sample"]["cancelled"] =
                    serde_json::Value::Null
            }
        };
        assert!(support::imported(&v).is_err(), "control {n}");
    }
    assert!(support::imported(&base).is_ok());
}
#[test]
fn import_matches_actual_rules() {
    for n in 0..6 {
        let mut v = support::literal();
        match n {
            0 => v["case_results"][0]["key"]["operation_id"] = "2".into(),
            1 => v["case_results"][0]["script_sha256"] = "0".repeat(64).into(),
            2 => v["case_results"][0]["tier"] = "T1".into(),
            3 => v["case_results"][0]["expected_evidence"]["oracle"]["revision"] = 2.into(),
            4 => v["case_results"][0]["expected_evidence"]["fixture_schema"]["revision"] = 2.into(),
            _ => v["case_results"][0]["intent"] = serde_json::json!({"kind":"assertion_only"}),
        };
        assert!(support::imported(&v).is_err(), "control {n}");
    }
    let mut v = support::literal();
    v["case_results"] = serde_json::json!([]);
    v["cleanup_records"] = serde_json::json!([]);
    v["run_terminal"] = serde_json::Value::Null;
    for name in [
        "entry_subject",
        "entry_oracle",
        "final_subject",
        "final_oracle",
    ] {
        v["runner_observations"][name]["checkpoints"]["before"] =
            serde_json::json!({"kind":"not_recorded"});
        v["runner_observations"][name]["checkpoints"]["after"] =
            serde_json::json!({"kind":"not_recorded"});
        v["runner_observations"][name]["value"] = serde_json::Value::Null;
        v["runner_observations"][name]["returned_elapsed_ns"] = serde_json::Value::Null;
    }
    v["runner_observations"]["completion"] = serde_json::json!({"kind":"not_recorded"});
    assert_eq!(
        support::imported(&v).unwrap().qualification(),
        Qualification::Incomplete
    );
}
#[test]
fn probe_keeps_checkpoint_receipts() {
    let r = support::run(false);
    let case = &r.case_results()[0];
    for pair in [
        case.execution_checkpoints().prepare(),
        case.execution_checkpoints().execute(),
        case.execution_checkpoints().collect(),
        case.execution_checkpoints().judge(),
    ] {
        assert!(matches!(pair.before(), CheckpointSlot::Sampled { .. }));
        assert!(matches!(pair.after(), CheckpointSlot::Sampled { .. }));
    }
    runner_observations_are_not_terminal_reasons();
    late_runner_stops_survive_successful_cases();
}
#[test]
fn refusal_is_not_support() {
    let mut v = support::literal();
    for state in [
        "denied",
        "unknown",
        "unsupported",
        "incompatible",
        "not_applicable",
    ] {
        v["case_results"][0]["capability"]["state"] = state.into();
        v["case_results"][0]["oracle_verdict"]["capability"]["state"] = state.into();
        v["run_terminal"]["qualification"] = "incomplete".into();
        v["run_terminal"]["reasons"] = serde_json::json!(["case.intent"]);
        assert_eq!(
            support::imported(&v).unwrap().qualification(),
            Qualification::Incomplete
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
fn closed_intent_matrix() {
    refusal_is_not_support();
    for state in ["unknown", "not_applicable"] {
        let mut cv = support::contract_value();
        cv["case_rules"][0]["intent"] = serde_json::json!({"kind":"assertion_only"});
        let mut v = support::literal();
        let c = support::rebase(&mut v, &cv);
        v["case_results"][0]["capability"]["state"] = state.into();
        v["case_results"][0]["oracle_verdict"]["capability"]["state"] = state.into();
        assert_eq!(
            RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), RunLimits::default())
                .unwrap()
                .qualification(),
            Qualification::Qualified
        );
    }
    let mut cv = support::contract_value();
    cv["case_rules"][0]["intent"] =
        serde_json::json!({"kind":"expected_refusal","cause":"unknown"});
    let (c, p, _) = support::load();
    assert!(RunContract::load(
        &c,
        &p,
        &serde_json::to_vec(&cv).unwrap(),
        RunLimits::default()
    )
    .is_err());
}
#[test]
fn blocked_twin_preserves_independent_fail() {
    let (p, c) = support::refusal_contract("license");
    for fail in [true, false] {
        let mut s = support::instrumented::Session::new(c.clone());
        s.model_input = Some(support::LICENSE_INPUT);
        s.expected_override = Some(support::LICENSE_EXPECTED);
        s.prepare_error = Some(FixtureErrorCategory::Denied);
        s.error_twin_only = true;
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
            source_terms: if fail {
                b"incompatible model source grant".to_vec()
            } else {
                include_bytes!("fixtures/harness/source-terms.bytes").to_vec()
            },
            elf_license: include_bytes!("fixtures/harness/elf-license.bin").to_vec(),
            loader_license: include_bytes!("fixtures/harness/loader-license.bin").to_vec(),
            context: include_bytes!("fixtures/harness/model-context.json").to_vec(),
            objects: c.artifacts().to_vec(),
        };
        let r = run_profile(&p, &mut a, &mut s, &o).unwrap();
        assert_eq!(
            r.qualification(),
            if fail {
                Qualification::Failed
            } else {
                Qualification::Incomplete
            }
        );
        let refusal = &r.case_results()[1];
        assert_eq!(
            *refusal
                .effective_checks()
                .iter()
                .find(|a| a.id().as_str() == "refusal.intended-cause")
                .unwrap()
                .status(),
            CheckStatus::NotJudged
        );
        assert_eq!(
            *refusal
                .effective_checks()
                .iter()
                .find(|a| a.id().as_str() == "input.license-bytes")
                .unwrap()
                .status(),
            if fail {
                CheckStatus::Fail
            } else {
                CheckStatus::Pass
            }
        );
    }
}
struct Alternating {
    inner: support::adapter::ArithmeticAdapter,
}
impl ConformanceAdapter for Alternating {
    fn subject(&self) -> SubjectBinding {
        self.inner.subject()
    }
    fn execute(
        &mut self,
        i: &CaseInvocation,
        f: &FixtureAccess<'_>,
    ) -> Result<Observation, CaseError> {
        self.inner.wrong = self.inner.calls == 0;
        self.inner.execute(i, f)
    }
    fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
        self.inner.retire(r)
    }
}
#[test]
fn all_attempts_are_sticky() {
    let (_, p, _) = support::load();
    let mut cv = support::contract_value();
    cv["case_rules"][0]["attempts"] = 2.into();
    cv["case_rules"][0]["operation_ids"] = serde_json::json!(["1", "2"]);
    let c = support::with_model_ledgers(cv);
    let mut s = support::instrumented::Session::new(c.clone());
    let mut a = Alternating {
        inner: support::adapter::ArithmeticAdapter {
            subject: c.expected_subject().clone(),
            wrong: false,
            calls: 0,
        },
    };
    let o = support::oracle::ArithmeticOracle {
        binding: c.expected_oracle().clone(),
    };
    let r = run_profile(&p, &mut a, &mut s, &o).unwrap();
    assert_eq!(r.case_results().len(), 2);
    assert_eq!(
        *r.case_results()[0].effective_checks()[0].status(),
        CheckStatus::Fail
    );
    assert_eq!(
        *r.case_results()[1].effective_checks()[0].status(),
        CheckStatus::Pass
    );
    assert_eq!(r.qualification(), Qualification::Failed);
    let mut cv = support::contract_value();
    cv["case_rules"][0]["attempts"] = 2.into();
    cv["case_rules"][0]["operation_ids"] = serde_json::json!(["1", "1"]);
    let (c, p, _) = support::load();
    assert!(RunContract::load(
        &c,
        &p,
        &serde_json::to_vec(&cv).unwrap(),
        RunLimits::default()
    )
    .is_err());
}
fn failed_fixture(category: FixtureErrorCategory, collect: bool) -> (RunContract, RunReport) {
    let (_, p, c) = support::load();
    let mut s = support::instrumented::Session::new(c.clone());
    if collect {
        s.collect_error = Some(category)
    } else {
        s.prepare_error = Some(category)
    }
    let mut a = support::instrumented::adapter(&s);
    let o = support::oracle::ArithmeticOracle {
        binding: c.expected_oracle().clone(),
    };
    (c, run_profile(&p, &mut a, &mut s, &o).unwrap())
}
#[test]
fn fixture_prepare_stop_roundtrip() {
    for (category, reason) in [
        (FixtureErrorCategory::Cancelled, "runner.cancelled"),
        (FixtureErrorCategory::TimedOut, "runner.deadline"),
    ] {
        let (c, r) = failed_fixture(category, false);
        assert_eq!(r.qualification(), Qualification::Incomplete);
        let x = &r.case_results()[0];
        assert_eq!(x.entered_stages(), &[EnteredStage::Prepare]);
        assert!(x.outcome().is_none());
        assert!(x.oracle_verdict().is_none());
        assert_eq!(*x.fixture_failure().unwrap().category(), category);
        let b = r.to_json(c.limits().clone()).unwrap();
        let imported = RunReport::from_json(&c, &b, c.limits().clone()).unwrap();
        assert_eq!(imported.qualification(), Qualification::Incomplete);
        assert!(imported.reasons().iter().any(|l| l.as_str() == reason));
        assert!(imported.case_results()[0]
            .effective_checks()
            .iter()
            .all(|a| *a.status() == CheckStatus::NotJudged));
    }
    assert_eq!(
        support::run(false).qualification(),
        Qualification::Qualified
    );
}
#[test]
fn fixture_collect_stop_preserves_outcome() {
    collect_failure_keeps_operation_error_and_prior_fail();
    for category in [
        FixtureErrorCategory::Cancelled,
        FixtureErrorCategory::TimedOut,
    ] {
        let (c, r) = failed_fixture(category, true);
        let x = &r.case_results()[0];
        assert!(matches!(x.outcome(), Some(CaseOutcome::Observed(_))));
        assert_eq!(
            x.entered_stages(),
            &[
                EnteredStage::Prepare,
                EnteredStage::Execute,
                EnteredStage::Collect
            ]
        );
        assert_eq!(x.effect_batches().len(), 3);
        assert!(x.oracle_verdict().is_none());
        let b = r.to_json(c.limits().clone()).unwrap();
        let imported = RunReport::from_json(&c, &b, c.limits().clone()).unwrap();
        assert_eq!(imported.case_results()[0].outcome(), x.outcome());
        assert_eq!(imported.qualification(), Qualification::Incomplete);
    }
}
#[test]
fn fixture_denial_is_not_refusal() {
    let (_, p, _) = support::load();
    let mut cv = support::contract_value();
    cv["case_rules"][0]["attempts"] = 2.into();
    cv["case_rules"][0]["operation_ids"] = serde_json::json!(["1", "2"]);
    let c = support::with_model_ledgers(cv);
    for cat in [
        FixtureErrorCategory::Unavailable,
        FixtureErrorCategory::Denied,
        FixtureErrorCategory::Io,
        FixtureErrorCategory::Other,
    ] {
        let mut s = support::instrumented::Session::new(c.clone());
        s.prepare_error = Some(cat);
        s.error_first_only = true;
        let mut a = support::instrumented::adapter(&s);
        let o = support::oracle::ArithmeticOracle {
            binding: c.expected_oracle().clone(),
        };
        let r = run_profile(&p, &mut a, &mut s, &o).unwrap();
        assert_eq!(r.qualification(), Qualification::Incomplete);
        assert!(r.case_results()[0].outcome().is_none());
        assert_eq!(*r.case_results()[1].execution(), ExecutionState::Completed);
        let b = r.to_json(c.limits().clone()).unwrap();
        assert_eq!(
            RunReport::from_json(&c, &b, c.limits().clone())
                .unwrap()
                .qualification(),
            Qualification::Incomplete
        );
    }
}
#[test]
fn wrong_artifact_progress_stops_before_second_prepare_and_retires() {
    struct WrongProgressSession {
        inner: support::instrumented::Session<'static>,
        progress: InputReadProgress,
        prepares: Vec<u64>,
        retires: Vec<u64>,
    }
    impl FixtureSession for WrongProgressSession {
        fn contract(&self) -> &RunContract {
            self.inner.contract()
        }
        fn cancellation_probe(&mut self) -> Box<dyn CancellationProbe + 'static> {
            self.inner.cancellation_probe()
        }
        fn prepare(&mut self, i: &CaseInvocation) -> Result<FixtureAccess<'_>, FixtureError> {
            self.prepares.push(*i.key().operation_id());
            if *i.key().operation_id() == 1 {
                let l = i.limits();
                let effect = EffectRegistration::new(
                    EffectRegistrationValues {
                        resource_id: support::instrumented::label("fixture.first"),
                        owner: Owner::Fixture,
                        origin: i.key().clone(),
                        kind: support::instrumented::label("owned-state"),
                        identity_sha256: Digest256::of_bytes(b"first fixture resource"),
                        recovery_evidence_id: None,
                    },
                    l,
                )
                .unwrap();
                return Err(FixtureError::new(
                    FixtureErrorValues {
                        key: Some(i.key().clone()),
                        stage: FixtureStage::Prepare,
                        category: FixtureErrorCategory::Io,
                        errno: Some(5),
                        diagnostic_bytes: b"first input read failed".to_vec(),
                        effects: EffectBatch::new(
                            EffectBatchValues {
                                registrations: vec![effect],
                                complete: true,
                            },
                            l,
                        )
                        .unwrap(),
                        read_progress: Some(self.progress.clone()),
                    },
                    l,
                )
                .unwrap());
            }
            self.inner.prepare(i)
        }
        fn collect(&mut self, i: &CaseInvocation) -> Result<ExpectedEvidence, FixtureError> {
            self.inner.collect(i)
        }
        fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
            self.retires.push(r.call_id());
            self.inner.retire(r)
        }
    }

    let (_, p, _) = support::load();
    let mut cv = support::contract_value();
    cv["case_rules"][0]["attempts"] = 2.into();
    cv["case_rules"][0]["operation_ids"] = serde_json::json!(["1", "2"]);
    cv["case_rules"][0]["max_effects"] = 1.into();
    let c = support::with_model_ledgers(cv);
    let foreign = ArtifactBinding::new(
        ArtifactBindingValues {
            id: Label::parse("foreign-input").unwrap(),
            revision: 1,
            role: ArtifactRole::FixtureInput,
            length: 4,
            sha256: Digest256::of_bytes(b"not the input"),
        },
        c.limits(),
    )
    .unwrap();
    assert!(c.artifacts().iter().all(|a| a.id() != foreign.id()));
    let file = std::fs::File::open(support::root().join("operands.bytes")).unwrap();
    let mut meter = ArtifactMeasurer::new(c.run_id().clone(), c.limits().clone()).unwrap();
    let measurement = meter.measure(&foreign, &file).unwrap_err();
    assert_eq!(measurement.kind(), BindingErrorKind::DigestMismatch);
    let progress = measurement.progress().unwrap().clone();
    assert_eq!(progress.file_id(), foreign.id());
    assert_eq!(progress.expected_length(), 4);
    assert_eq!(progress.bytes_returned(), 4);
    assert_eq!(progress.read_calls(), 2);

    let mut inner = support::instrumented::Session::new(c.clone());
    inner.mode = support::instrumented::Retirement::Now;
    let mut a = support::instrumented::adapter(&inner);
    let mut s = WrongProgressSession {
        inner,
        progress: progress.clone(),
        prepares: vec![],
        retires: vec![],
    };
    let o = support::oracle::ArithmeticOracle {
        binding: c.expected_oracle().clone(),
    };
    let result = run_profile(&p, &mut a, &mut s, &o);
    assert_eq!(
        s.prepares,
        [1],
        "invalid first progress admitted a second prepare"
    );
    let error = result.unwrap_err();
    assert_eq!(error.kind(), HarnessErrorKind::InvalidProtocol);
    let partial = error
        .partial_report()
        .expect("entered prepare retains evidence");
    assert_eq!(partial.case_results().len(), 2);
    let first = &partial.case_results()[0];
    assert_eq!(
        first.fixture_failure().unwrap().read_progress().as_ref(),
        Some(&progress)
    );
    assert_eq!(
        first.effect_batches()[0].registrations()[0]
            .resource_id()
            .as_str(),
        "fixture.first"
    );
    assert_eq!(
        *partial.case_results()[1].execution(),
        ExecutionState::NotRun
    );
    assert!(partial.case_results()[1].entered_stages().is_empty());
    assert_eq!(s.retires, [2, 6]);
    let cleanup = partial
        .cleanup_records()
        .iter()
        .find(|r| *r.call_id() == 2 && *r.owner() == Owner::Fixture)
        .unwrap();
    assert_eq!(*cleanup.status(), CleanupCallStatus::Called);
    assert_eq!(cleanup.response().as_ref().unwrap().transitions().len(), 1);
}
#[test]
fn fixture_failure_closed_wire() {
    let (c, r) = failed_fixture(FixtureErrorCategory::Cancelled, false);
    let base: serde_json::Value =
        serde_json::from_slice(&r.to_json(c.limits().clone()).unwrap()).unwrap();
    for n in 0..8 {
        let mut v = base.clone();
        match n {
            0 => {
                v["case_results"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("fixture_failure");
            }
            1 => v["case_results"][0]["fixture_failure"]["category"] = "refused".into(),
            2 => v["case_results"][0]["fixture_failure"]["stage"] = "admission".into(),
            3 => v["case_results"][0]["fixture_failure"]["key"]["operation_id"] = "2".into(),
            4 => v["case_results"][0]["execution"] = "completed".into(),
            5 => v["case_results"][0]["fixture_failure"]["diagnostic_bytes"] = "GG".into(),
            6 => {
                v["case_results"][0]["fixture_failure"]["read_progress"] = serde_json::json!({"file_id":"operands","expected_length":"999","bytes_returned":"0","read_calls":"0"})
            }
            _ => {
                v["case_results"][0]["oracle_verdict"] =
                    support::literal()["case_results"][0]["oracle_verdict"].clone()
            }
        };
        assert!(
            RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), c.limits().clone()).is_err(),
            "control {n}"
        );
    }
    assert_eq!(
        RunReport::from_json(&c, &serde_json::to_vec(&base).unwrap(), c.limits().clone())
            .unwrap()
            .qualification(),
        Qualification::Incomplete
    );
}
#[test]
fn fixture_failure_is_stop_evidence() {
    let (c, r) = failed_fixture(FixtureErrorCategory::Cancelled, false);
    let mut v: serde_json::Value =
        serde_json::from_slice(&r.to_json(c.limits().clone()).unwrap()).unwrap();
    v["case_results"][0]["reason"] = "Everything passed".into();
    assert_eq!(
        RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), c.limits().clone())
            .unwrap()
            .qualification(),
        Qualification::Incomplete
    );
    v["case_results"][0]["fixture_failure"] = serde_json::Value::Null;
    assert!(
        RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), c.limits().clone()).is_err()
    );
    let (c, r) = failed_fixture(FixtureErrorCategory::InvalidProtocol, false);
    assert_eq!(r.qualification(), Qualification::Invalid);
    let b = r.to_json(c.limits().clone()).unwrap();
    assert_eq!(
        RunReport::from_json(&c, &b, c.limits().clone())
            .unwrap()
            .qualification(),
        Qualification::Invalid
    );
}
#[test]
fn fixture_error_after_gate_and_partial_tail() {
    let (c, r) = failed_fixture(FixtureErrorCategory::Cancelled, false);
    let mut v: serde_json::Value =
        serde_json::from_slice(&r.to_json(c.limits().clone()).unwrap()).unwrap();
    v["run_terminal"] = serde_json::Value::Null;
    v["case_results"][0]["execution_checkpoints"]["prepare"]["after"] =
        serde_json::json!({"kind":"not_recorded"});
    v["runner_observations"]["completion"] = serde_json::json!({"kind":"not_recorded"});
    let p = RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), c.limits().clone()).unwrap();
    assert_eq!(p.qualification(), Qualification::Incomplete);
    assert_eq!(
        *p.case_results()[0].fixture_failure().unwrap().category(),
        FixtureErrorCategory::Cancelled
    );
}
#[test]
fn fixture_error_effect_mirror_once() {
    let (_, p, _) = support::load();
    let c = support::effect_contract();
    let mut s = support::instrumented::Session::new(c.clone());
    s.effect = true;
    s.prepare_error = Some(FixtureErrorCategory::Denied);
    s.mode = support::instrumented::Retirement::Now;
    let mut a = support::instrumented::adapter(&s);
    let o = support::oracle::ArithmeticOracle {
        binding: c.expected_oracle().clone(),
    };
    let r = run_profile(&p, &mut a, &mut s, &o).unwrap();
    assert_eq!(
        r.case_results()[0].effect_batches()[0],
        *r.case_results()[0].fixture_failure().unwrap().effects()
    );
    assert_eq!(
        *r.cleanup_records()[1].state_at_run_end(),
        CleanupState::Complete
    );
    let b = r.to_json(c.limits().clone()).unwrap();
    assert!(RunReport::from_json(&c, &b, c.limits().clone()).is_ok());
    let mut v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    v["case_results"][0]["effect_batches"][0]["registrations"] = serde_json::json!([]);
    assert!(
        RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), c.limits().clone()).is_err()
    );
}
struct InvalidOracle {
    inner: support::oracle::ArithmeticOracle,
}
impl CaseOracle for InvalidOracle {
    fn identity(&self) -> OracleBinding {
        self.inner.identity()
    }
    fn evaluate(&self, c: &CaseSpec, e: &ExpectedEvidence, o: &CaseOutcome) -> AssertionVerdict {
        let v = self.inner.evaluate(c, e, o);
        AssertionVerdict::new(
            AssertionVerdictValues {
                harness: HarnessValidity::Invalid {
                    reason: "independently detected harness fault".into(),
                },
                checks: v.checks().to_vec(),
                capability: v.capability().clone(),
            },
            &RunLimits::default(),
        )
        .unwrap()
    }
}
#[test]
fn oracle_harness_invalid_is_retained() {
    let (_, p, c) = support::load();
    let mut a = support::adapter::ArithmeticAdapter {
        subject: c.expected_subject().clone(),
        wrong: false,
        calls: 0,
    };
    let o = InvalidOracle {
        inner: support::oracle::ArithmeticOracle {
            binding: c.expected_oracle().clone(),
        },
    };
    let r = run_profile(&p, &mut a, &mut support::session(c.clone()), &o).unwrap();
    assert_eq!(r.qualification(), Qualification::Invalid);
    let x = &r.case_results()[0];
    assert!(matches!(
        x.oracle_verdict().unwrap().harness(),
        HarnessValidity::Invalid { .. }
    ));
    assert_eq!(
        *x.oracle_verdict().unwrap().checks()[0].status(),
        CheckStatus::Pass
    );
    assert_eq!(*x.effective_checks()[0].status(), CheckStatus::NotJudged);
    assert_eq!(x.capability().method().as_str(), "runner.unjudged");
    let b = r.to_json(c.limits().clone()).unwrap();
    assert_eq!(
        RunReport::from_json(&c, &b, c.limits().clone())
            .unwrap()
            .qualification(),
        Qualification::Invalid
    );
    let mut v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    v["case_results"][0]["capability"] =
        v["case_results"][0]["oracle_verdict"]["capability"].clone();
    assert!(
        RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), c.limits().clone()).is_err()
    );
}
#[test]
fn oracle_nonentry_is_distinct_from_return() {
    let (_, r) = failed_fixture(FixtureErrorCategory::Denied, false);
    let x = &r.case_results()[0];
    assert!(x.oracle_verdict().is_none());
    assert_eq!(*x.capability().state(), CapabilityState::Unknown);
    assert_eq!(x.capability().method().as_str(), "runner.unjudged");
    let mut v = support::literal();
    v["case_results"][0]["oracle_verdict"] = serde_json::Value::Null;
    assert!(support::imported(&v).is_err());
    let mut v = support::literal();
    v["case_results"][0]["entered_stages"] = serde_json::json!([]);
    assert!(support::imported(&v).is_err());
}
#[test]
fn oracle_partial_return_is_preserved() {
    for invalid in [false, true] {
        let mut v = support::literal();
        v["run_terminal"] = serde_json::Value::Null;
        v["case_results"][0]["execution_checkpoints"]["judge"]["after"] =
            serde_json::json!({"kind":"not_recorded"});
        for key in ["final_subject", "final_oracle"] {
            v["runner_observations"][key] = serde_json::json!({"checkpoints":{"before":{"kind":"not_recorded"},"after":{"kind":"not_recorded"}},"value":null,"returned_elapsed_ns":null});
        }
        v["runner_observations"]["completion"] = serde_json::json!({"kind":"not_recorded"});
        if invalid {
            v["case_results"][0]["oracle_verdict"]["harness"] =
                serde_json::json!({"kind":"invalid","reason":"literal invalid witness"});
            v["case_results"][0]["effective_checks"][0]["status"] = "not_judged".into();
            v["case_results"][0]["effective_checks"][0]["reason"] = "oracle.harness_invalid".into();
            v["case_results"][0]["capability"] = serde_json::json!({"state":"unknown","method":"runner.unjudged","context":"","evidence_ids":[]});
            v["case_results"][0]["execution"] = "harness_error".into();
            v["case_results"][0]["terminal"] = serde_json::Value::Null;
        }
        let r = support::imported(&v).unwrap();
        assert!(r.case_results()[0].oracle_verdict().is_some());
        assert_eq!(
            r.qualification(),
            if invalid {
                Qualification::Invalid
            } else {
                Qualification::Incomplete
            }
        );
    }
}
#[test]
fn oracle_response_set_and_summary_controls() {
    let mut cv = support::contract_value();
    cv["case_rules"][0]["assertions"].as_array_mut().unwrap().push(serde_json::json!({"id":"second.equal","requires_coverage":["trigger"],"requires_positive_twin":false}));
    let mut v = support::literal();
    let c = support::rebase(&mut v, &cv);
    let check = serde_json::json!({"id":"second.equal","status":"pass","reason":null});
    v["case_results"][0]["oracle_verdict"]["checks"]
        .as_array_mut()
        .unwrap()
        .push(check.clone());
    v["case_results"][0]["effective_checks"]
        .as_array_mut()
        .unwrap()
        .push(check);
    assert_eq!(
        RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), c.limits().clone())
            .unwrap()
            .qualification(),
        Qualification::Qualified
    );
    for n in 0..5 {
        let mut bad = v.clone();
        match n {
            0 => {
                bad["case_results"][0]["oracle_verdict"]["checks"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
            1 => bad["case_results"][0]["oracle_verdict"]["checks"][1]["id"] = "value.equal".into(),
            2 => bad["case_results"][0]["oracle_verdict"]["checks"][1]["status"] = "maybe".into(),
            3 => bad["case_results"][0]["oracle_verdict"]["checks"][1]["id"] = "extra".into(),
            _ => bad["case_results"][0]["oracle_checks"] = serde_json::Value::Null,
        };
        assert!(
            RunReport::from_json(&c, &serde_json::to_vec(&bad).unwrap(), c.limits().clone())
                .is_err(),
            "control {n}"
        );
    }
}
#[test]
fn independent_cartesian_truth_table() {
    let rows: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/harness/verdict-truth.json")).unwrap();
    for row in rows.as_array().unwrap() {
        let valid = row["valid"].as_bool().unwrap();
        let covered = row["covered"].as_bool().unwrap();
        let settled = row["settled"].as_bool().unwrap();
        let frozen = row["frozen"].as_bool().unwrap();
        let assertion = row["assertion"].as_str().unwrap();
        let mut v = support::literal();
        let mut cv = support::contract_value();
        let mut cat: serde_json::Value =
            serde_json::from_slice(&std::fs::read(support::root().join("catalog.json")).unwrap())
                .unwrap();
        cv["case_rules"][0]["assertions"][0]["requires_coverage"] = serde_json::json!([]);
        cv["case_rules"][0]["assertions"].as_array_mut().unwrap().push(serde_json::json!({"id":"activity.equal","requires_coverage":["trigger"],"requires_positive_twin":false}));
        v["case_results"][0]["oracle_verdict"]["checks"][0]["status"] = assertion.into();
        let check = serde_json::json!({"id":"activity.equal","status":"pass","reason":null});
        v["case_results"][0]["oracle_verdict"]["checks"]
            .as_array_mut()
            .unwrap()
            .push(check);
        if !covered {
            let mut ledger: serde_json::Value = serde_json::from_slice(
                &std::fs::read(support::root().join("ledger.json")).unwrap(),
            )
            .unwrap();
            ledger["coverage"][3]["achieved"] = "0".into();
            let bytes = serde_json::to_vec(&ledger).unwrap();
            for a in cv["artifacts"].as_array_mut().unwrap() {
                if a["id"] == "ledger" {
                    a["length"] = bytes.len().to_string().into();
                    a["sha256"] = Digest256::of_bytes(&bytes).as_str().into();
                }
            }
            v["case_results"][0]["expected_evidence"]["ledger_bytes"] = bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                .into();
            v["case_results"][0]["expected_evidence"]["coverage"] = ledger["coverage"].clone();
            v["case_results"][0]["coverage"][3]["raw_achieved"] = "0".into();
            v["case_results"][0]["coverage"][3]["effective_achieved"] = "0".into();
        }
        if !frozen {
            cat["profiles"][0]["definition_state"] = "DRAFT".into();
            cat["profiles"][0]["open_owners"] = serde_json::json!(["TT02"]);
            cv["selection"]["definition_complete"] = false.into();
            cv["selection"]["open_owners"] = serde_json::json!(["TT02"]);
            v["selection"] = cv["selection"].clone();
        }
        if !settled {
            cv["case_rules"][0]["max_effects"] = 1.into();
            let key = v["case_results"][0]["key"].clone();
            let registration = serde_json::json!({"resource_id":"R","owner":"fixture","origin":key,"kind":"owned-state","identity_sha256":"11".repeat(32),"recovery_evidence_id":null});
            let pending = serde_json::json!({"resource_id":"R","owner":"fixture","origin":key,"identity_sha256":"11".repeat(32)});
            v["case_results"][0]["effect_batches"][0]["registrations"] =
                serde_json::json!([registration]);
            for i in [1, 3] {
                v["cleanup_records"][i]["response"]["pending_snapshot"] =
                    serde_json::json!([pending]);
                v["cleanup_records"][i]["pending_ids"] = serde_json::json!(["R"]);
                v["cleanup_records"][i]["state_at_run_end"] = "unresolved".into();
            }
            v["cleanup_records"][1]["state_at_case_end"] = "unresolved".into();
        }
        let mut reasons = std::collections::BTreeSet::new();
        if !valid {
            v["case_results"][0]["oracle_verdict"]["harness"] =
                serde_json::json!({"kind":"invalid","reason":"literal invalid population"});
            v["case_results"][0]["execution"] = "harness_error".into();
            v["case_results"][0]["terminal"]["execution"] = "harness_error".into();
            v["case_results"][0]["capability"] = serde_json::json!({"state":"unknown","method":"runner.unjudged","context":"","evidence_ids":[]});
            reasons.extend([
                "oracle.harness_invalid",
                "case.intent",
                "case.not_completed",
                "case.not_judged",
            ]);
        }
        let raw = v["case_results"][0]["oracle_verdict"]["checks"]
            .as_array()
            .unwrap()
            .clone();
        let effective = raw
            .into_iter()
            .enumerate()
            .map(|(i, mut a)| {
                if !valid {
                    a["status"] = "not_judged".into();
                    a["reason"] = "oracle.harness_invalid".into();
                } else if i == 1 && !covered {
                    a["status"] = "not_judged".into();
                    a["reason"] = "prerequisite missing".into();
                }
                a
            })
            .collect::<Vec<_>>();
        v["case_results"][0]["effective_checks"] = serde_json::json!(effective);
        if valid {
            if assertion == "fail" {
                reasons.insert("case.semantic_fail");
            }
            if assertion == "not_judged" {
                reasons.insert("case.not_judged");
            }
        }
        if !covered {
            reasons.extend(["case.coverage", "case.not_judged"]);
        }
        if !settled {
            reasons.insert("cleanup.unresolved");
        }
        if !frozen {
            reasons.extend(["selection.draft", "selection.open_owner"]);
        }
        if !valid || !settled {
            for name in ["final_subject", "final_oracle"] {
                omit_meta(
                    &mut v,
                    name,
                    if !valid {
                        "prior_stop"
                    } else {
                        "cleanup_unresolved"
                    },
                );
            }
            reasons.extend([
                "runner.final_subject_missing",
                "runner.final_oracle_missing",
            ]);
        }
        let bytes = serde_json::to_vec(&cat).unwrap();
        let catalog = CaseCatalog::load(&bytes, CatalogLimits::default()).unwrap();
        let plan =
            ProfilePlan::select(&catalog, &ProfileId::parse("tt02-harness-v1").unwrap()).unwrap();
        cv["catalog_sha256"] = catalog.source_sha256().as_str().into();
        let c = RunContract::load(
            &catalog,
            &plan,
            &serde_json::to_vec(&cv).unwrap(),
            RunLimits::default(),
        )
        .unwrap();
        v["run_contract_sha256"] = c.sha256().as_str().into();
        v["artifacts"] = serde_json::to_value(c.artifacts()).unwrap();
        v["case_results"][0]["script_sha256"] = c.case_rules()[0].script().sha256().as_str().into();
        v["run_terminal"]["qualification"] = row["expected"].clone();
        v["run_terminal"]["reasons"] = serde_json::json!(reasons);
        let report = RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), c.limits().clone())
            .expect("independent Cartesian row must reconstruct");
        let expected = match row["expected"].as_str().unwrap() {
            "qualified" => Qualification::Qualified,
            "invalid" => Qualification::Invalid,
            "failed" => Qualification::Failed,
            _ => Qualification::Incomplete,
        };
        assert_eq!(report.qualification(), expected, "{row}");
    }
}
#[test]
fn collect_failure_keeps_operation_error_and_prior_fail() {
    let (_, p, _) = support::load();
    for category in [
        FixtureErrorCategory::Cancelled,
        FixtureErrorCategory::TimedOut,
    ] {
        let mut cv = support::contract_value();
        let overflow = b"18446744073709551615\n1\n";
        for a in cv["artifacts"].as_array_mut().unwrap() {
            if a["id"] == "operands" {
                a["length"] = overflow.len().to_string().into();
                a["sha256"] = Digest256::of_bytes(overflow).as_str().into();
            }
        }
        let c = support::changed_contract(&cv);
        let mut s = support::instrumented::Session::new(c.clone());
        s.operation_input = Some(overflow);
        s.collect_error = Some(category);
        let mut a = support::instrumented::adapter(&s);
        let o = support::oracle::ArithmeticOracle {
            binding: c.expected_oracle().clone(),
        };
        let r = run_profile(&p, &mut a, &mut s, &o).unwrap();
        assert!(
            matches!(r.case_results()[0].outcome(),Some(CaseOutcome::OperationError(e))if *e.category()==CaseErrorCategory::Refused&&*e.cause().cause()==RefusalCause::Unknown&&e.completed_steps().is_empty()&&e.partial_observation().is_some())
        );
        let bytes = r.to_json(c.limits().clone()).unwrap();
        assert_eq!(
            RunReport::from_json(&c, &bytes, c.limits().clone())
                .unwrap()
                .case_results()[0]
                .outcome(),
            r.case_results()[0].outcome()
        );
        let mut cv = support::contract_value();
        cv["case_rules"][0]["attempts"] = 2.into();
        cv["case_rules"][0]["operation_ids"] = serde_json::json!(["1", "2"]);
        let c = support::changed_contract(&cv);
        let mut s = support::instrumented::Session::new(c.clone());
        s.collect_error = Some(category);
        s.collect_error_after_first = true;
        let mut a = Alternating {
            inner: support::adapter::ArithmeticAdapter {
                subject: c.expected_subject().clone(),
                wrong: false,
                calls: 0,
            },
        };
        let o = support::oracle::ArithmeticOracle {
            binding: c.expected_oracle().clone(),
        };
        let r = run_profile(&p, &mut a, &mut s, &o).unwrap();
        assert_eq!(r.qualification(), Qualification::Failed);
        let bytes = r.to_json(c.limits().clone()).unwrap();
        assert_eq!(
            RunReport::from_json(&c, &bytes, c.limits().clone())
                .unwrap()
                .qualification(),
            Qualification::Failed
        );
    }
}
#[test]
fn independently_authored_fixture_failure() {
    let (_, _, c) = support::load();
    let bytes = std::fs::read(support::root().join("receipt-fixture-cancelled.json")).unwrap();
    let r = RunReport::from_json(&c, &bytes, c.limits().clone()).unwrap();
    assert_eq!(r.qualification(), Qualification::Incomplete);
    assert_eq!(
        *r.case_results()[0].fixture_failure().unwrap().category(),
        FixtureErrorCategory::Cancelled
    );
    assert_eq!(
        r.case_results()[0]
            .fixture_failure()
            .unwrap()
            .read_progress()
            .as_ref()
            .unwrap()
            .read_calls(),
        0
    );
}
#[test]
fn strict_receipt_populations() {
    let (_, _, c) = support::load();
    let original = std::fs::read(support::root().join("receipt-qualified.json")).unwrap();
    for n in 0..11 {
        let mut v: serde_json::Value = serde_json::from_slice(&original).unwrap();
        match n {
            0 => v["schema_version"] = 2.into(),
            1 => v["schema_version"] = true.into(),
            2 => v["case_results"][0]["key"]["operation_id"] = true.into(),
            3 => v["case_results"][0]["key"]["operation_id"] = "01".into(),
            4 => v["case_results"][0]["key"]["operation_id"] = "18446744073709551616".into(),
            5 => v["case_results"][0]["script_sha256"] = "A".repeat(64).into(),
            6 => {
                v["case_results"][0]["outcome"]["observation"]["bytes"] = serde_json::json!([1, 2])
            }
            7 => {
                v["runner_observations"]["completion"]["sample"]
                    .as_object_mut()
                    .unwrap()
                    .remove("cancelled");
            }
            8 => v["extra"] = 0.into(),
            9 => v["case_results"][0]["capability"]["state"] = "maybe".into(),
            _ => v["case_results"][0]["key"]["attempt"] = 0.into(),
        };
        assert!(
            RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), c.limits().clone()).is_err(),
            "control {n}"
        );
    }
    let raw = String::from_utf8(original.clone()).unwrap();
    let duplicate = raw.replacen(
        "\"cancelled\":false",
        "\"cancelled\":false,\"cancelled\":false",
        1,
    );
    assert!(RunReport::from_json(&c, duplicate.as_bytes(), c.limits().clone()).is_err());
    let trailing = [original.as_slice(), b" true"].concat();
    assert!(RunReport::from_json(&c, &trailing, c.limits().clone()).is_err());
    let invalid = [original.as_slice(), &[0xff]].concat();
    assert!(RunReport::from_json(&c, &invalid, c.limits().clone()).is_err());
    assert!(RunReport::from_json(&c, &original, c.limits().clone()).is_ok());
}
