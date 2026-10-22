// SPDX-License-Identifier: Apache-2.0
//! Independently authored boundary populations from critical review R1.
use super::support;
use scopebase_testkit::*;
use support::instrumented as ins;
fn contract(v: &serde_json::Value) -> Result<RunContract, HarnessError> {
    let (catalog, plan, _) = support::load();
    RunContract::load(
        &catalog,
        &plan,
        &serde_json::to_vec(v).unwrap(),
        RunLimits::default(),
    )
}
#[test]
fn a1_selected_structure_is_admitted_again() {
    for field in ["json_depth", "json_edges"] {
        let mut v = support::contract_value();
        v["limits"][field] = "1".into();
        assert_eq!(
            contract(&v).unwrap_err().kind(),
            HarnessErrorKind::LimitExceeded,
            "selected {field}"
        );
        v["limits"][field] = serde_json::to_value(RunLimits::default()).unwrap()[field].clone();
        assert!(contract(&v).is_ok());
    }
}
#[test]
fn a1_mandatory_diagnostic_payload_is_reserved_before_effects() {
    let mut v = support::contract_value();
    v["limits"]["diagnostic_bytes"] = "1".into();
    assert_eq!(
        contract(&v).unwrap_err().kind(),
        HarnessErrorKind::LimitExceeded,
        "fixed runner diagnostics must fit selected limits"
    );
    assert!(contract(&support::contract_value()).is_ok());
}
#[test]
fn a1_reused_access_and_measurement_values_use_selected_limits() {
    let (_, _, c) = support::load();
    let mut v = c.limits().values();
    v.label_bytes = 4;
    let l = RunLimits::new(v).unwrap();
    let input = [FixtureInput::new(Label::parse("long-slot").unwrap(), b"x")];
    assert!(
        FixtureAccess::new(&input, &[], EffectBatch::empty(&l), &l).is_err(),
        "selected input label"
    );
    let resource = 7u64;
    let resources = [FixtureResource::new(
        Label::parse("long-resource").unwrap(),
        &resource,
    )];
    assert!(
        FixtureAccess::new(&[], &resources, EffectBatch::empty(&l), &l).is_err(),
        "selected resource label"
    );
    assert!(FixtureAccess::new(&input, &[], EffectBatch::empty(&l), c.limits()).is_ok());
    let file = std::fs::File::open(support::root().join("operands.bytes")).unwrap();
    let a = ArtifactBinding::new(
        ArtifactBindingValues {
            id: Label::parse("long-binding").unwrap(),
            revision: 1,
            role: ArtifactRole::ConsumerExecutable,
            length: 4,
            sha256: Digest256::of_bytes(b"2\n3\n"),
        },
        c.limits(),
    )
    .unwrap();
    let mut meter = ArtifactMeasurer::new(c.run_id().clone(), l).unwrap();
    assert!(meter.measure(&a, &file).is_err(), "selected artifact label");
    assert_eq!(
        meter.usage().attempts,
        0,
        "invalid descriptor is not an I/O attempt"
    );
    let mut meter = ArtifactMeasurer::new(c.run_id().clone(), c.limits().clone()).unwrap();
    assert!(meter.measure(&a, &file).is_ok());
}
#[test]
fn a1_access_rechecks_previously_admitted_effects() {
    let (_, _, c) = support::load();
    let key = &c.schedule()[0];
    let wide = c.limits();
    let batch = EffectBatch::new(
        EffectBatchValues {
            registrations: ["r1", "r2"]
                .iter()
                .map(|id| {
                    EffectRegistration::new(
                        EffectRegistrationValues {
                            resource_id: Label::parse(id).unwrap(),
                            owner: Owner::Fixture,
                            origin: key.clone(),
                            kind: Label::parse("state").unwrap(),
                            identity_sha256: Digest256::of_bytes(id.as_bytes()),
                            recovery_evidence_id: None,
                        },
                        wide,
                    )
                    .unwrap()
                })
                .collect(),
            complete: true,
        },
        wide,
    )
    .unwrap();
    let mut v = wide.values();
    v.effects_total = 1;
    v.effects_per_case = 1;
    let small = RunLimits::new(v).unwrap();
    assert!(
        FixtureAccess::new(&[], &[], batch.clone(), &small).is_err(),
        "selected effect batch bound"
    );
    assert!(FixtureAccess::new(&[], &[], batch, wide).is_ok());
}
struct LooseOutcome {
    subject: SubjectBinding,
    error: bool,
}
impl ConformanceAdapter for LooseOutcome {
    fn subject(&self) -> SubjectBinding {
        self.subject.clone()
    }
    fn execute(
        &mut self,
        i: &CaseInvocation,
        _: &FixtureAccess<'_>,
    ) -> Result<Observation, CaseError> {
        let l = RunLimits::default();
        if self.error {
            Err(CaseError::new(
                CaseErrorValues {
                    key: i.key().clone(),
                    step_id: Some(Label::parse("sum").unwrap()),
                    stage: Label::parse("execute").unwrap(),
                    category: CaseErrorCategory::InvalidOutput,
                    errno: None,
                    diagnostic_bytes: vec![b'x'; 64],
                    cause: RefusalEvidence::new(
                        RefusalEvidenceValues {
                            cause: RefusalCause::Unknown,
                            method: Label::parse("model").unwrap(),
                            evidence_ids: vec![],
                            tier: EvidenceTier::T0,
                        },
                        &l,
                    )
                    .unwrap(),
                    completed_steps: vec![],
                    partial_observation: None,
                    effects: EffectBatch::empty(&l),
                },
                &l,
            )
            .unwrap())
        } else {
            Ok(Observation::new(ObservationValues{key:i.key().clone(),schema_id:i.observation_schema().id().clone(),schema_revision:*i.observation_schema().revision(),completed_steps:vec![Label::parse("sum").unwrap()],bytes:br#"{"schema_version":1,"kind":"tt02-u64-observation","steps":[{"step_id":"sum","value":"5"}]}"#.to_vec(),effects:EffectBatch::empty(&l)},&l).unwrap())
        }
    }
    fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
        ins::retire(r, ins::Retirement::Empty, &RunLimits::default())
    }
}
#[test]
fn a1_returned_outcomes_recheck_selected_bounds_before_collect() {
    for error in [false, true] {
        let (_, p, _) = support::load();
        let mut v = support::contract_value();
        if error {
            v["limits"]["diagnostic_bytes"] = "48".into()
        } else {
            v["limits"]["observation_bytes"] = "1".into()
        }
        let c = contract(&v).unwrap();
        let mut s = ins::Session::new(c.clone());
        let mut a = LooseOutcome {
            subject: c.expected_subject().clone(),
            error,
        };
        let o = support::oracle::ArithmeticOracle {
            binding: c.expected_oracle().clone(),
        };
        let result = run_profile(&p, &mut a, &mut s, &o);
        assert!(
            result.is_err(),
            "selected returned outcome bounds: error={error}"
        );
        assert!(
            !s.events.borrow().iter().any(|e| e == "collect"),
            "invalid outcome stops normal work"
        );
        let c = support::load().2;
        let mut s = ins::Session::new(c.clone());
        let mut a = LooseOutcome {
            subject: c.expected_subject().clone(),
            error,
        };
        assert!(run_profile(&p, &mut a, &mut s, &o).is_ok());
    }
}
#[test]
fn a1_selected_receipt_cap_is_not_enlarged_by_the_ceiling() {
    let (_, p, _) = support::load();
    let mut v = support::contract_value();
    v["limits"]["receipt_bytes"] = "8192".into();
    let c = contract(&v).unwrap();
    let mut s = ins::Session::new(c.clone());
    let mut a = ins::adapter(&s);
    let o = support::oracle::ArithmeticOracle {
        binding: c.expected_oracle().clone(),
    };
    let result = run_profile(&p, &mut a, &mut s, &o);
    let report = match &result {
        Ok(r) => r,
        Err(e) => e.partial_report().expect("bounded partial"),
    };
    assert!(report.to_json(c.limits().clone()).is_err());
    assert!(
        report.to_json(RunLimits::default()).is_err(),
        "wider ceiling cannot enlarge selected receipt cap"
    );
    assert!(
        result.is_err(),
        "oversize final receipt must not return a complete report"
    );
    let mut s = ins::Session::new(support::load().2);
    let mut a = ins::adapter(&s);
    assert!(run_profile(&p, &mut a, &mut s, &o).is_ok());
}
fn partial_return(kind: usize) -> serde_json::Value {
    use serde_json::{json, Value};
    let cancelled: Value =
        serde_json::from_slice(include_bytes!("receipt-fixture-cancelled.json")).unwrap();
    let mut v = if kind == 0 {
        cancelled.clone()
    } else {
        support::literal()
    };
    let row = &mut v["case_results"][0];
    let count = if kind == 0 {
        1
    } else if kind <= 2 {
        2
    } else {
        3
    };
    row["entered_stages"] = json!(["prepare", "execute", "collect"][..count].to_vec());
    row["execution"] = "blocked".into();
    row["terminal"] = Value::Null;
    row["oracle_verdict"] = Value::Null;
    row["effective_checks"] = cancelled["case_results"][0]["effective_checks"].clone();
    row["capability"] = cancelled["case_results"][0]["capability"].clone();
    if kind != 3 {
        row["expected_evidence"] = Value::Null;
        row["coverage"] = cancelled["case_results"][0]["coverage"].clone();
    }
    if kind == 2 {
        row["outcome"] = json!({"kind":"operation_error","error":{"key":row["key"],"step_id":"sum","stage":"execute","category":"io","errno":5,"diagnostic_bytes":"78","cause":{"cause":"unknown","method":"literal","evidence_ids":[],"tier":"T0"},"completed_steps":[],"partial_observation":null,"effects":{"registrations":[],"complete":true}}});
    }
    if kind == 4 {
        row["fixture_failure"] = cancelled["case_results"][0]["fixture_failure"].clone();
        row["fixture_failure"]["stage"] = "collect".into();
    }
    row["effect_batches"]
        .as_array_mut()
        .unwrap()
        .truncate(count);
    for (i, name) in ["prepare", "execute", "collect", "judge"]
        .iter()
        .enumerate()
    {
        if i == count - 1 {
            row["execution_checkpoints"][name]["after"] = json!({"kind":"not_recorded"});
        } else if i >= count {
            row["execution_checkpoints"][name] =
                json!({"before":{"kind":"not_recorded"},"after":{"kind":"not_recorded"}});
        }
    }
    for name in ["final_subject", "final_oracle"] {
        v["runner_observations"][name] = json!({"checkpoints":{"before":{"kind":"not_recorded"},"after":{"kind":"not_recorded"}},"value":null,"returned_elapsed_ns":null});
    }
    v["runner_observations"]["completion"] = json!({"kind":"not_recorded"});
    v["run_terminal"] = Value::Null;
    v
}
#[test]
fn b1_returned_partial_responses_require_their_mirror() {
    use serde_json::json;
    for kind in 0..5 {
        let mut v = partial_return(kind);
        let position = if kind == 0 {
            0
        } else if kind <= 2 {
            1
        } else {
            2
        };
        let owner = if position == 1 { "adapter" } else { "fixture" };
        let registration = json!({"resource_id":"R","owner":owner,"origin":v["case_results"][0]["key"],"kind":"owned-state","identity_sha256":"a".repeat(64),"recovery_evidence_id":null});
        let batch = json!({"registrations":[registration],"complete":true});
        let source = if kind == 0 || kind == 4 {
            &mut v["case_results"][0]["fixture_failure"]["effects"]
        } else if kind == 1 {
            &mut v["case_results"][0]["outcome"]["observation"]["effects"]
        } else if kind == 2 {
            &mut v["case_results"][0]["outcome"]["error"]["effects"]
        } else {
            &mut v["case_results"][0]["expected_evidence"]["effects"]
        };
        *source = batch.clone();
        v["case_results"][0]["effect_batches"][position] = batch;
        let mut cv = support::contract_value();
        cv["case_rules"][0]["max_effects"] = 1.into();
        let c = support::rebase(&mut v, &cv);
        let effect = json!({"resource_id":"R","owner":owner,"origin":v["case_results"][0]["key"],"identity_sha256":"a".repeat(64)});
        let case = if owner == "adapter" { 0 } else { 1 };
        v["cleanup_records"][case]["response"]["transitions"] = json!([{"transition_id":"r.done","effect":effect,"to":"retired","evidence_ids":["owned-proof"]}]);
        v["cleanup_records"][case]["transition_ids"] = json!(["r.done"]);
        for i in [case, case + 2] {
            v["cleanup_records"][i]["state_at_run_end"] = "complete".into();
        }
        v["cleanup_records"][case]["state_at_case_end"] = "complete".into();
        assert_eq!(
            RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), c.limits().clone())
                .unwrap()
                .qualification(),
            Qualification::Incomplete,
            "correct returned mirror {kind}"
        );
        v["case_results"][0]["effect_batches"]
            .as_array_mut()
            .unwrap()
            .pop();
        v["cleanup_records"][case]["response"]["transitions"] = json!([]);
        v["cleanup_records"][case]["transition_ids"] = json!([]);
        for i in [case, case + 2] {
            v["cleanup_records"][i]["state_at_run_end"] = "not_required".into();
        }
        v["cleanup_records"][case]["state_at_case_end"] = "not_required".into();
        assert!(
            RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), c.limits().clone()).is_err(),
            "missing returned mirror {kind}"
        );
    }
}
#[test]
fn b1_zero_effect_rule_cannot_lose_a_typed_return() {
    let mut v = partial_return(0);
    v["case_results"][0]["fixture_failure"]["effects"]["registrations"] = serde_json::json!([{"resource_id":"R","owner":"fixture","origin":v["case_results"][0]["key"],"kind":"owned-state","identity_sha256":"a".repeat(64),"recovery_evidence_id":null}]);
    v["case_results"][0]["effect_batches"] = serde_json::json!([]);
    assert!(
        support::imported(&v).is_err(),
        "typed return must enforce selected max_effects even without an after sample"
    );
    let mut tail = partial_return(1);
    tail["case_results"][0]["outcome"] = serde_json::Value::Null;
    tail["case_results"][0]["effect_batches"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert_eq!(
        support::imported(&tail).unwrap().qualification(),
        Qualification::Incomplete,
        "genuine entered/no-return tail"
    );
}
fn vector_manifest(c: &RunContract, operands: Option<&[u8]>) -> VectorManifest {
    let mut v: serde_json::Value = serde_json::from_slice(include_bytes!("bundle.json")).unwrap();
    v["run_contract_sha256"] = c.sha256().as_str().into();
    if let Some(b) = operands {
        for f in v["files"].as_array_mut().unwrap() {
            if f["file_id"] == "operands" {
                f["length"] = b.len().to_string().into();
                f["sha256"] = Digest256::of_bytes(b).as_str().into();
            }
        }
    }
    VectorManifest::load(c, &serde_json::to_vec(&v).unwrap(), c.limits().clone()).unwrap()
}
fn owned_file(bytes: &[u8]) -> (std::path::PathBuf, std::fs::File) {
    use std::io::Write;
    let p = std::env::temp_dir().join(format!(
        "tt02-r1-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&p)
        .unwrap();
    f.write_all(bytes).unwrap();
    (p, f)
}
#[test]
fn a2_single_payload_vector_fits_the_selected_budget() {
    let payload = vec![b'x'; 8_388_608];
    let (path, file) = owned_file(&payload);
    for budget in [9_000_000u64, 20_000_000] {
        let mut cv = support::contract_value();
        cv["limits"]["retained_bytes"] = budget.to_string().into();
        for a in cv["artifacts"].as_array_mut().unwrap() {
            if a["id"] == "operands" {
                a["length"] = payload.len().to_string().into();
                a["sha256"] = Digest256::of_bytes(&payload).as_str().into();
            }
        }
        let c = contract(&cv).unwrap();
        let m = vector_manifest(&c, Some(&payload));
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
        let mut meter = ArtifactMeasurer::new(c.run_id().clone(), c.limits().clone()).unwrap();
        let r = VectorBundle::read(&m, &opened, &mut meter);
        assert!(r.is_ok(),"shared Vec owner must admit one8MiB payload under {budget}; private pointer/capacity control proves no second allocation");
    }
    std::fs::remove_file(path).unwrap();
}
#[test]
fn a2_later_vector_failure_preserves_meter_and_caller_cursors() {
    use std::io::{Seek, SeekFrom};
    let c = support::load().2;
    let m = vector_manifest(&c, None);
    let mut expected = std::fs::File::open(support::root().join("expected.json")).unwrap();
    expected.seek(SeekFrom::Start(7)).unwrap();
    let mut alias = expected.try_clone().unwrap();
    let (path, mut ledger) = owned_file(b"{");
    ledger.seek(SeekFrom::Start(1)).unwrap();
    let operands = std::fs::File::open(support::root().join("operands.bytes")).unwrap();
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
            file: &operands,
        },
    ];
    let mut meter = ArtifactMeasurer::new(c.run_id().clone(), c.limits().clone()).unwrap();
    assert!(VectorBundle::read(&m, &opened, &mut meter).is_err());
    let before = meter.usage();
    assert_eq!(before.attempts, 2);
    assert_eq!(before.bytes_returned, 87);
    assert_eq!(before.last.as_ref().unwrap().file_id().as_str(), "ledger");
    assert_eq!(before.last.as_ref().unwrap().bytes_returned(), 0);
    assert_eq!(before.last.as_ref().unwrap().read_calls(), 0);
    assert!(meter
        .measure(
            c.artifacts()
                .iter()
                .find(|a| a.id().as_str() == "ledger")
                .unwrap(),
            &ledger
        )
        .is_err());
    let after = meter.usage();
    assert_eq!(after.attempts, 3);
    assert_eq!(after.reserved_bytes, before.reserved_bytes + 474);
    assert_eq!(expected.stream_position().unwrap(), 7);
    assert_eq!(alias.stream_position().unwrap(), 7);
    assert_eq!(ledger.stream_position().unwrap(), 1);
    std::fs::remove_file(path).unwrap();
}
#[test]
fn a3_authored_vector_tiers_cannot_be_retagged() {
    for tier in ["T0", "T3", "T4"] {
        let mut catalog: serde_json::Value =
            serde_json::from_slice(include_bytes!("catalog.json")).unwrap();
        catalog["cells"][0]["tier"] = tier.into();
        let bytes = serde_json::to_vec(&catalog).unwrap();
        let catalog = CaseCatalog::load(&bytes, CatalogLimits::default()).unwrap();
        let p =
            ProfilePlan::select(&catalog, &ProfileId::parse("tt02-harness-v1").unwrap()).unwrap();
        let mut cv = support::contract_value();
        cv["catalog_sha256"] = Digest256::of_bytes(&bytes).as_str().into();
        cv["selection"]["required"][0]["tier"] = tier.into();
        cv["case_rules"][0]["tier"] = tier.into();
        let c = RunContract::load(
            &catalog,
            &p,
            &serde_json::to_vec(&cv).unwrap(),
            RunLimits::default(),
        )
        .unwrap();
        let mut bundle: serde_json::Value =
            serde_json::from_slice(include_bytes!("bundle.json")).unwrap();
        bundle["run_contract_sha256"] = c.sha256().as_str().into();
        let manifest = VectorManifest::load(
            &c,
            &serde_json::to_vec(&bundle).unwrap(),
            c.limits().clone(),
        );
        let mut v = support::literal();
        v["run_contract_sha256"] = c.sha256().as_str().into();
        v["selection"] = cv["selection"].clone();
        v["case_results"][0]["tier"] = tier.into();
        v["case_results"][0]["script_sha256"] = c.case_rules()[0].script().sha256().as_str().into();
        let imported =
            RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), c.limits().clone());
        if tier == "T0" {
            assert!(manifest.is_ok());
            assert_eq!(imported.unwrap().qualification(), Qualification::Qualified);
        } else {
            assert!(
                manifest.is_err(),
                "builtin authored provider must refuse {tier} before file admission"
            );
            assert!(
                imported.is_err(),
                "fixed authored ledger cannot certify {tier}"
            );
        }
    }
}
struct MisroutedExpected {
    inner: ins::Session<'static>,
    bad: usize,
}
impl FixtureSession for MisroutedExpected {
    fn contract(&self) -> &RunContract {
        self.inner.contract()
    }
    fn cancellation_probe(&mut self) -> Box<dyn CancellationProbe + 'static> {
        self.inner.cancellation_probe()
    }
    fn prepare(&mut self, i: &CaseInvocation) -> Result<FixtureAccess<'_>, FixtureError> {
        self.inner.prepare(i)
    }
    fn collect(&mut self, i: &CaseInvocation) -> Result<ExpectedEvidence, FixtureError> {
        let e = self.inner.collect(i)?;
        let l = RunLimits::default();
        let mut v = ExpectedEvidenceValues {
            key: e.key().clone(),
            oracle: e.oracle().clone(),
            fixture_schema: e.fixture_schema().clone(),
            truth_kind: TruthKind::FixedBeforeExecute,
            expected_bytes: e.expected_bytes().clone(),
            ledger_bytes: e.ledger_bytes().clone(),
            coverage: e.coverage().clone(),
            effects: e.effects().clone(),
        };
        if *i.key().operation_id() == 1 {
            match self.bad {
                1 => v.key = self.inner.c.schedule()[1].clone(),
                2 => {
                    v.oracle = OracleBinding::new(
                        OracleBindingValues {
                            id: v.oracle.id().clone(),
                            revision: 2,
                            schema_id: v.oracle.schema_id().clone(),
                            source_sha256: *v.oracle.source_sha256(),
                            artifact_id: v.oracle.artifact_id().clone(),
                            provenance: v.oracle.provenance().clone(),
                        },
                        &l,
                    )
                    .unwrap()
                }
                3 => {
                    v.fixture_schema = SchemaBinding::new(
                        SchemaBindingValues {
                            id: v.fixture_schema.id().clone(),
                            revision: 2,
                        },
                        &l,
                    )
                    .unwrap()
                }
                4 => v.ledger_bytes.push(b' '),
                5 => v.expected_bytes.push(b' '),
                6 => {
                    v.coverage[0] = CoverageEvidence::new(
                        CoverageEvidenceValues {
                            id: v.coverage[0].id().clone(),
                            step_ids: v.coverage[0].step_ids().clone(),
                            achieved: 0,
                        },
                        &l,
                    )
                    .unwrap()
                }
                _ => {}
            }
        }
        Ok(ExpectedEvidence::new(v, &l).unwrap())
    }
    fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
        self.inner.retire(r)
    }
}
struct CountJudge {
    inner: support::oracle::ArithmeticOracle,
    calls: std::cell::Cell<usize>,
}
impl CaseOracle for CountJudge {
    fn identity(&self) -> OracleBinding {
        self.inner.identity()
    }
    fn evaluate(&self, c: &CaseSpec, e: &ExpectedEvidence, o: &CaseOutcome) -> AssertionVerdict {
        self.calls.set(self.calls.get() + 1);
        self.inner.evaluate(c, e, o)
    }
}
fn two_contract() -> RunContract {
    let mut cv = support::contract_value();
    cv["case_rules"][0]["attempts"] = 2.into();
    cv["case_rules"][0]["operation_ids"] = serde_json::json!(["1", "2"]);
    cv["case_rules"][0]["max_effects"] = 1.into();
    support::with_model_ledgers(cv)
}
#[test]
fn b2_expected_binding_is_checked_before_judge_and_the_next_case() {
    let (_, p, _) = support::load();
    for bad in 0..7 {
        let c = two_contract();
        let mut s = MisroutedExpected {
            inner: ins::Session::new(c.clone()),
            bad,
        };
        s.inner.effect = true;
        s.inner.mode = ins::Retirement::Now;
        let mut a = ins::adapter(&s.inner);
        let o = CountJudge {
            inner: support::oracle::ArithmeticOracle {
                binding: c.expected_oracle().clone(),
            },
            calls: std::cell::Cell::new(0),
        };
        let result = run_profile(&p, &mut a, &mut s, &o);
        if bad == 0 {
            assert_eq!(result.unwrap().qualification(), Qualification::Qualified);
            assert_eq!(o.calls.get(), 2);
        } else {
            let error = result.unwrap_err();
            assert_eq!(
                o.calls.get(),
                0,
                "invalid ExpectedEvidence {bad} must not reach judge"
            );
            assert_eq!(
                s.inner
                    .events
                    .borrow()
                    .iter()
                    .filter(|e| e.as_str() == "prepare")
                    .count(),
                1,
                "invalid ExpectedEvidence stops later preparation"
            );
            assert_eq!(a.inner.calls, 1);
            let partial = error.partial_report().unwrap();
            assert!(partial.case_results()[0].expected_evidence().is_some());
            assert!(partial.case_results()[0].oracle_verdict().is_none());
            assert!(matches!(
                partial.case_results()[0]
                    .execution_checkpoints()
                    .collect()
                    .after(),
                CheckpointSlot::Sampled { .. }
            ));
            assert_eq!(
                s.inner
                    .events
                    .borrow()
                    .iter()
                    .filter(|e| e.starts_with("retire-fixture-"))
                    .count(),
                2,
                "participating fixture case and run retirement"
            );
        }
    }
}
fn shift_samples(v: &mut serde_json::Value, ns: u64) {
    match v {
        serde_json::Value::Object(o) => {
            for (k, v) in o {
                if k == "poll_started_elapsed_ns"
                    || k == "poll_finished_elapsed_ns"
                    || k == "returned_elapsed_ns"
                {
                    if let Some(n) = v.as_str() {
                        *v = (n.parse::<u64>().unwrap() + ns).to_string().into();
                    }
                } else {
                    shift_samples(v, ns)
                }
            }
        }
        serde_json::Value::Array(a) => {
            for v in a {
                shift_samples(v, ns)
            }
        }
        _ => {}
    }
}
fn two_literal() -> (RunContract, serde_json::Value) {
    use serde_json::json;
    let c = two_contract();
    let mut v = support::literal();
    v["run_contract_sha256"] = c.sha256().as_str().into();
    v["artifacts"] = serde_json::to_value(c.artifacts()).unwrap();
    v["case_results"][0]["script_sha256"] = c.case_rules()[0].script().sha256().as_str().into();
    let key = serde_json::to_value(&c.schedule()[1]).unwrap();
    let mut row = v["case_results"][0].clone();
    for p in [
        &["key"][..],
        &["outcome", "observation", "key"][..],
        &["expected_evidence", "key"][..],
        &["terminal", "key"][..],
    ] {
        let mut at = &mut row;
        for k in p {
            at = &mut at[*k];
        }
        *at = key.clone();
    }
    row["case_cleanup_call_ids"] = json!(["3", "4"]);
    row["terminal"]["after_cleanup_call_id"] = "4".into();
    shift_samples(&mut row["execution_checkpoints"], 100);
    let coverage = row["expected_evidence"]["coverage"].clone();
    let ledger=serde_json::to_vec(&json!({"schema_version":1,"kind":"tt02-vector-ledger","key":key,"truth_kind":"fixed-before-execute","evidence_tier":"T0","coverage":coverage})).unwrap();
    row["expected_evidence"]["ledger_bytes"] = ledger
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        .into();
    v["case_results"].as_array_mut().unwrap().push(row);
    let old = v["cleanup_records"].as_array().unwrap().clone();
    let mut records = vec![];
    for index in 0..6 {
        let source = if index < 4 { index % 2 } else { index - 2 };
        let mut r = old[source].clone();
        r["call_id"] = (index + 1).to_string().into();
        r["response"]["call_id"] = (index + 1).to_string().into();
        if (2..4).contains(&index) {
            r["scope"]["key"] = key.clone();
            r["response"]["scope"] = r["scope"].clone();
        }
        if index >= 2 {
            for field in ["remaining_before_ns", "remaining_after_ns"] {
                let n = r[field].as_str().unwrap().parse::<u64>().unwrap();
                r[field] = (n - 4).to_string().into();
            }
        }
        records.push(r);
    }
    v["cleanup_records"] = json!(records);
    for n in ["final_subject", "final_oracle", "completion"] {
        shift_samples(&mut v["runner_observations"][n], 200);
    }
    v["run_terminal"]["after_cleanup_call_id"] = "6".into();
    (c, v)
}
fn no_participation(v: &mut serde_json::Value, indices: [usize; 2]) {
    use serde_json::{json, Value};
    for i in indices {
        v["cleanup_records"][i]["status"] = "uncalled_no_participation".into();
        v["cleanup_records"][i]["response"] = Value::Null;
        v["cleanup_records"][i]["hook_elapsed_ns"] = "0".into();
        v["cleanup_records"][i]["pending_ids"] = json!([]);
    }
}
#[test]
fn b3_omitted_rows_are_a_trailing_normal_work_boundary() {
    let (c, base) = two_literal();
    assert_eq!(
        RunReport::from_json(&c, &serde_json::to_vec(&base).unwrap(), c.limits().clone())
            .unwrap()
            .qualification(),
        Qualification::Qualified,
        "independently assembled two-attempt positive"
    );
    for interior in [true, false] {
        let mut v = base.clone();
        v["run_terminal"] = serde_json::Value::Null;
        v["case_results"]
            .as_array_mut()
            .unwrap()
            .remove(if interior { 0 } else { 1 });
        no_participation(&mut v, if interior { [0, 1] } else { [2, 3] });
        assert!(
            RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), c.limits().clone()).is_err(),
            "missing row followed by sampled normal work: interior={interior}"
        );
    }
    let mut v = base;
    v["run_terminal"] = serde_json::Value::Null;
    v["case_results"].as_array_mut().unwrap().pop();
    no_participation(&mut v, [2, 3]);
    for n in ["final_subject", "final_oracle"] {
        v["runner_observations"][n] = serde_json::json!({"checkpoints":{"before":{"kind":"not_recorded"},"after":{"kind":"not_recorded"}},"value":null,"returned_elapsed_ns":null});
    }
    v["runner_observations"]["completion"] = serde_json::json!({"kind":"not_recorded"});
    assert_eq!(
        RunReport::from_json(&c, &serde_json::to_vec(&v).unwrap(), c.limits().clone())
            .unwrap()
            .qualification(),
        Qualification::Incomplete,
        "genuine unfinished trailing prefix"
    );
}
struct LongVerdict {
    binding: OracleBinding,
    ids: Vec<Label>,
    long: bool,
}
impl CaseOracle for LongVerdict {
    fn identity(&self) -> OracleBinding {
        self.binding.clone()
    }
    fn evaluate(&self, _: &CaseSpec, _: &ExpectedEvidence, _: &CaseOutcome) -> AssertionVerdict {
        let l = RunLimits::default();
        let n = if self.long { 65_536 } else { 5 };
        AssertionVerdict::new(
            AssertionVerdictValues {
                harness: HarnessValidity::Valid,
                checks: self
                    .ids
                    .iter()
                    .map(|id| {
                        AssertionCheck::new(
                            AssertionCheckValues {
                                id: id.clone(),
                                status: CheckStatus::Pass,
                                reason: Some("x".repeat(n)),
                            },
                            &l,
                        )
                        .unwrap()
                    })
                    .collect(),
                capability: CapabilityEvidence::new(
                    CapabilityEvidenceValues {
                        state: CapabilityState::Supported,
                        method: Label::parse("literal").unwrap(),
                        context: "c".repeat(n),
                        evidence_ids: vec![Label::parse("expected").unwrap()],
                    },
                    &l,
                )
                .unwrap(),
            },
            &l,
        )
        .unwrap()
    }
}
#[test]
fn b5_derived_diagnostics_reserve_payload_before_cloning() {
    let (_, p, _) = support::load();
    for (long, budget) in [(true, 2_097_152u64), (false, 2_097_152), (true, 8_388_608)] {
        let mut cv = support::contract_value();
        for f in ["input_bytes", "observation_bytes", "vector_bytes"] {
            cv["limits"][f] = "1048576".into();
        }
        cv["limits"]["receipt_bytes"] = budget.to_string().into();
        cv["limits"]["retained_bytes"] = budget.to_string().into();
        for n in 0..15 {
            cv["case_rules"][0]["assertions"].as_array_mut().unwrap().push(serde_json::json!({"id":format!("check{n:02}"),"requires_coverage":[],"requires_positive_twin":false}));
        }
        cv["case_rules"][0]["assertions"]
            .as_array_mut()
            .unwrap()
            .sort_by_key(|r| r["id"].as_str().unwrap().to_owned());
        let c = contract(&cv).unwrap();
        let mut s = ins::Session::new(c.clone());
        let mut a = ins::adapter(&s);
        let o = LongVerdict {
            binding: c.expected_oracle().clone(),
            ids: c.case_rules()[0]
                .assertions()
                .iter()
                .map(|a| a.id().clone())
                .collect(),
            long,
        };
        let result = run_profile(&p, &mut a, &mut s, &o);
        if long && budget == 2_097_152 {
            let error = result.unwrap_err();
            let partial = error
                .partial_report()
                .expect("custody preserved on bounded-copy refusal");
            let row = &partial.case_results()[0];
            let raw = row.oracle_verdict().expect("actual raw verdict retained");
            let raw_bytes: usize = raw
                .checks()
                .iter()
                .map(|c| c.reason().as_ref().map_or(0, String::len))
                .sum::<usize>()
                + raw.capability().context().len();
            let derived_bytes: usize = row
                .effective_checks()
                .iter()
                .map(|c| c.reason().as_ref().map_or(0, String::len))
                .sum::<usize>()
                + row.capability().context().len();
            assert!(
                raw_bytes + derived_bytes < budget as usize,
                "unreserved raw/derived diagnostic payload exceeds selected limit: {}",
                raw_bytes + derived_bytes
            );
            assert_ne!(partial.qualification(), Qualification::Qualified);
            assert!(s
                .events
                .borrow()
                .iter()
                .any(|e| e.starts_with("retire-fixture-")));
        } else {
            assert_eq!(
                result.unwrap().qualification(),
                Qualification::Qualified,
                "restored diagnostics/budget"
            );
        }
    }
}
#[test]
fn b5_receipt_decode_peak_is_reserved_before_parsing() {
    // The raw response is intentionally opaque to the receipt importer. Its
    // descriptive oracle claim does not authorize extra decode allocations.
    for budget in [2_200_000u64, 8_388_608] {
        let mut cv = support::contract_value();
        for f in ["input_bytes", "vector_bytes", "observation_bytes"] {
            cv["limits"][f] = "1048576".into();
        }
        cv["limits"]["receipt_bytes"] = "2097152".into();
        cv["limits"]["retained_bytes"] = budget.to_string().into();
        let mut v = support::literal();
        let c = support::rebase(&mut v, &cv);
        v["case_results"][0]["outcome"]["observation"]["bytes"] = "78".repeat(1_000_000).into();
        let bytes = serde_json::to_vec(&v).unwrap();
        let result = RunReport::from_json(&c, &bytes, c.limits().clone());
        if budget == 2_200_000 {
            assert!(
                result.is_err(),
                "parsed hex string and decoded byte payload must fit together before growth"
            );
        } else {
            assert_eq!(
                result.unwrap().qualification(),
                Qualification::Qualified,
                "sufficient admitted decode budget"
            );
        }
    }
}
