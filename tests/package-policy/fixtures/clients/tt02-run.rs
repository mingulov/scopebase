// SPDX-License-Identifier: Apache-2.0
use scopebase_testkit::*;
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};
fn label(s: &str) -> Label {
    Label::parse(s).unwrap()
}
struct Adapter {
    subject: SubjectBinding,
    wrong: bool,
}
fn decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty()
        || bytes.len() > 20
        || bytes.len() > 1 && bytes[0] == b'0'
        || !bytes.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}
fn output(values: &[String]) -> Vec<u8> {
    format!(
        "{{\"schema_version\":1,\"kind\":\"tt02-u64-observation\",\"steps\":[{}]}}",
        values.join(",")
    )
    .into_bytes()
}
fn operation_error(
    i: &CaseInvocation,
    category: CaseErrorCategory,
    step_id: Option<Label>,
    completed_steps: Vec<Label>,
    partial: Option<Vec<u8>>,
) -> CaseError {
    let l = i.limits();
    let preflight = category == CaseErrorCategory::UnsupportedSchema;
    CaseError::new(
        CaseErrorValues {
            key: i.key().clone(),
            step_id,
            stage: label(if preflight {
                "adapter-schema"
            } else {
                "operation"
            }),
            category,
            errno: None,
            diagnostic_bytes: vec![],
            cause: RefusalEvidence::new(
                RefusalEvidenceValues {
                    cause: RefusalCause::Unknown,
                    method: label(if preflight {
                        "adapter-dialect"
                    } else {
                        "client-operation"
                    }),
                    evidence_ids: vec![],
                    tier: EvidenceTier::T0,
                },
                l,
            )
            .unwrap(),
            completed_steps,
            partial_observation: partial.and_then(|bytes| {
                PartialObservation::new(
                    PartialObservationValues {
                        schema_id: i.observation_schema().id().clone(),
                        schema_revision: *i.observation_schema().revision(),
                        bytes,
                    },
                    l,
                )
                .ok()
            }),
            effects: EffectBatch::empty(l),
        },
        l,
    )
    .unwrap()
}
impl Adapter {
    fn execute_with<'a>(
        &mut self,
        i: &CaseInvocation,
        mut input: impl FnMut(&Label) -> Option<&'a [u8]>,
    ) -> Result<Observation, CaseError> {
        if i.script().schema_id().as_str() != "tt02-u64-v1"
            || i.script().steps().iter().any(|s| {
                s.inputs().len() != 1
                    || !s.parameters().is_empty()
                    || !matches!(s.operation().as_str(), "checked-add" | "decimal-length")
            })
        {
            return Err(operation_error(
                i,
                CaseErrorCategory::UnsupportedSchema,
                None,
                vec![],
                None,
            ));
        }
        let mut values = vec![];
        let mut completed = vec![];
        for step in i.script().steps() {
            let bytes = input(&step.inputs()[0]).unwrap_or(b"");
            let lines = bytes
                .strip_suffix(b"\n")
                .map(|s| s.split(|b| *b == b'\n').collect::<Vec<_>>())
                .unwrap_or_default();
            let mut category = CaseErrorCategory::InvalidOutput;
            let n = match step.operation().as_str() {
                "checked-add" if lines.len() == 2 => match (decimal(lines[0]), decimal(lines[1])) {
                    (Some(a), Some(b)) => {
                        let n = a.checked_add(b);
                        if n.is_none() {
                            category = CaseErrorCategory::Refused;
                        }
                        n
                    }
                    _ => None,
                },
                "decimal-length" if lines.len() == 1 && decimal(lines[0]).is_some() => {
                    Some(lines[0].len() as u64)
                }
                _ => None,
            };
            let Some(n) = n else {
                return Err(operation_error(
                    i,
                    category,
                    Some(step.step_id().clone()),
                    completed,
                    Some(output(&values)),
                ));
            };
            let n = if self.wrong { 6 } else { n };
            values.push(format!(
                "{{\"step_id\":\"{}\",\"value\":\"{n}\"}}",
                step.step_id().as_str()
            ));
            completed.push(step.step_id().clone());
        }
        let progress = completed.clone();
        Observation::new(
            ObservationValues {
                key: i.key().clone(),
                schema_id: i.observation_schema().id().clone(),
                schema_revision: *i.observation_schema().revision(),
                completed_steps: completed,
                bytes: output(&values),
                effects: EffectBatch::empty(i.limits()),
            },
            i.limits(),
        )
        .map_err(|_| operation_error(i, CaseErrorCategory::InvalidOutput, None, progress, None))
    }
}
fn dialect_controls(c: &RunContract) {
    let make = |raw: &[u8]| {
        CaseInvocation::new(
            CaseInvocationValues {
                key: c.schedule()[0].clone(),
                observation_schema: c.case_rules()[0].observation_schema().clone(),
                fixture_schema: c.case_rules()[0].fixture_schema().clone(),
                script: OperationScript::load(raw, c.limits()).unwrap(),
                limits: c.limits().clone(),
            },
            c.limits(),
        )
        .unwrap()
    };
    for raw in [
        br#"{"schema_version":1,"kind":"steps-v1","schema_id":"unknown","steps":[{"step_id":"sum","operation":"checked-add","inputs":["operands"],"parameters":[]}]}"#.as_slice(),
        br#"{"schema_version":1,"kind":"steps-v1","schema_id":"tt02-u64-v1","steps":[{"step_id":"sum","operation":"checked-add","inputs":["operands"],"parameters":[]},{"step_id":"next","operation":"bad","inputs":["operands"],"parameters":[]}]}"#,
        br#"{"schema_version":1,"kind":"steps-v1","schema_id":"tt02-u64-v1","steps":[{"step_id":"sum","operation":"checked-add","inputs":[],"parameters":[]}]}"#,
        br#"{"schema_version":1,"kind":"steps-v1","schema_id":"tt02-u64-v1","steps":[{"step_id":"sum","operation":"checked-add","inputs":["operands","second"],"parameters":[]}]}"#,
        br#"{"schema_version":1,"kind":"steps-v1","schema_id":"tt02-u64-v1","steps":[{"step_id":"sum","operation":"checked-add","inputs":["operands"],"parameters":[{"kind":"bool","value":true}]}]}"#,
    ]{let mut reads=0;let error=Adapter{subject:c.expected_subject().clone(),wrong:false}.execute_with(&make(raw),|_|{reads+=1;Some(b"2\n3\n".as_slice())}).unwrap_err();assert_eq!(*error.category(),CaseErrorCategory::UnsupportedSchema);assert_eq!(reads,0);assert!(error.step_id().is_none()&&error.completed_steps().is_empty()&&error.partial_observation().is_none());}
    let good=make(br#"{"schema_version":1,"kind":"steps-v1","schema_id":"tt02-u64-v1","steps":[{"step_id":"sum","operation":"checked-add","inputs":["operands"],"parameters":[]},{"step_id":"digits","operation":"decimal-length","inputs":["number"],"parameters":[]}]}"#);
    let mut a = Adapter {
        subject: c.expected_subject().clone(),
        wrong: false,
    };
    let observed = a
        .execute_with(&good, |id| {
            Some(if id.as_str() == "operands" {
                b"2\n3\n".as_slice()
            } else {
                b"42\n".as_slice()
            })
        })
        .unwrap();
    assert_eq!(observed.bytes(),br#"{"schema_version":1,"kind":"tt02-u64-observation","steps":[{"step_id":"sum","value":"5"},{"step_id":"digits","value":"2"}]}"#);
}
impl ConformanceAdapter for Adapter {
    fn subject(&self) -> SubjectBinding {
        self.subject.clone()
    }
    fn execute(
        &mut self,
        i: &CaseInvocation,
        f: &FixtureAccess<'_>,
    ) -> Result<Observation, CaseError> {
        self.execute_with(i, |id| f.input(id))
    }
    fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
        RetirementReport::new(
            RetirementReportValues {
                call_id: r.call_id(),
                owner: r.owner(),
                scope: r.scope().clone(),
                discovered: vec![],
                transitions: vec![],
                pending_snapshot: r.known_pending().to_vec(),
                complete: true,
                diagnostic: None,
            },
            &RunLimits::default(),
        )
        .unwrap()
    }
}
struct Oracle(OracleBinding);
impl CaseOracle for Oracle {
    fn identity(&self) -> OracleBinding {
        self.0.clone()
    }
    fn evaluate(&self, _: &CaseSpec, e: &ExpectedEvidence, o: &CaseOutcome) -> AssertionVerdict {
        let expected = std::str::from_utf8(e.expected_bytes())
            .unwrap()
            .replace("tt02-u64-expected", "tt02-u64-observation");
        let preflight = matches!(o,CaseOutcome::OperationError(e)if *e.category()==CaseErrorCategory::UnsupportedSchema);
        let pass = matches!(o,CaseOutcome::Observed(x)if x.bytes()==expected.as_bytes());
        let l = RunLimits::default();
        AssertionVerdict::new(
            AssertionVerdictValues {
                harness: HarnessValidity::Valid,
                checks: vec![AssertionCheck::new(
                    AssertionCheckValues {
                        id: label("value.equal"),
                        status: if preflight {
                            CheckStatus::NotJudged
                        } else if pass {
                            CheckStatus::Pass
                        } else {
                            CheckStatus::Fail
                        },
                        reason: None,
                    },
                    &l,
                )
                .unwrap()],
                capability: CapabilityEvidence::new(
                    CapabilityEvidenceValues {
                        state: if preflight {
                            CapabilityState::Unknown
                        } else {
                            CapabilityState::Supported
                        },
                        method: label("client-independent-vector"),
                        context: "T0 model only".into(),
                        evidence_ids: vec![label("expected")],
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
fn run(root: &Path, wrong: bool) -> Qualification {
    let l = RunLimits::default();
    let catalog = CaseCatalog::load(
        &fs::read(root.join("catalog.json")).unwrap(),
        CatalogLimits::default(),
    )
    .unwrap();
    let plan =
        ProfilePlan::select(&catalog, &ProfileId::parse("tt02-harness-v1").unwrap()).unwrap();
    let c = RunContract::load(
        &catalog,
        &plan,
        &fs::read(root.join("contract.json")).unwrap(),
        l.clone(),
    )
    .unwrap();
    dialect_controls(&c);
    let manifest =
        VectorManifest::load(&c, &fs::read(root.join("bundle.json")).unwrap(), l.clone()).unwrap();
    let opened = [
        ("expected", "expected.json"),
        ("ledger", "ledger.json"),
        ("operands", "operands.bytes"),
    ]
    .into_iter()
    .map(|(id, p)| (label(id), File::open(root.join(p)).unwrap()))
    .collect::<Vec<_>>();
    let files = opened
        .iter()
        .map(|(id, f)| OpenedVector {
            file_id: id.clone(),
            file: f,
        })
        .collect::<Vec<_>>();
    let mut meter = ArtifactMeasurer::new(c.run_id().clone(), l).unwrap();
    let bundle = VectorBundle::read(&manifest, &files, &mut meter).unwrap();
    let mut a = Adapter {
        subject: c.expected_subject().clone(),
        wrong,
    };
    let o = Oracle(c.expected_oracle().clone());
    let mut session = VectorFixtureSession::new(c, bundle).unwrap();
    run_profile(&plan, &mut a, &mut session, &o)
        .unwrap()
        .qualification()
}
fn bounded(path: &str) -> Vec<u8> {
    use std::io::Read;
    let mut b = Vec::new();
    File::open(path)
        .unwrap()
        .take(8_388_609)
        .read_to_end(&mut b)
        .unwrap();
    assert!(b.len() <= 8_388_608);
    b
}
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let root = args
        .first()
        .map_or_else(|| PathBuf::from("fixtures/harness"), PathBuf::from);
    if args.len() == 3 {
        let expected = bounded(&args[1]);
        let actual = bounded(&args[2]);
        assert_eq!(expected, actual, "actual consumer build/executable binding");
        println!("actual consumer generated measurement matches independent expectation");
    }
    assert_eq!(run(&root, false), Qualification::Qualified);
    assert_eq!(run(&root, true), Qualification::Failed);
    assert_eq!(run(&root, false), Qualification::Qualified);
    println!("TT02 runner/input/oracle controls passed (T0 model)");
}
