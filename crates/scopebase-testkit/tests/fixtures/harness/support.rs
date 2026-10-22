// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use scopebase_testkit::*;
use std::{fs::File, path::PathBuf};
#[path = "adapter.rs"]
pub mod adapter;
#[path = "oracle.rs"]
pub mod oracle;
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/harness")
}
pub fn load() -> (CaseCatalog, ProfilePlan, RunContract) {
    let c = CaseCatalog::load(
        &std::fs::read(root().join("catalog.json")).unwrap(),
        CatalogLimits::default(),
    )
    .unwrap();
    let p = ProfilePlan::select(&c, &ProfileId::parse("tt02-harness-v1").unwrap()).unwrap();
    let r = RunContract::load(
        &c,
        &p,
        &std::fs::read(root().join("contract.json")).unwrap(),
        RunLimits::default(),
    )
    .unwrap();
    (c, p, r)
}
pub fn session(c: RunContract) -> VectorFixtureSession {
    let m = VectorManifest::load(
        &c,
        &std::fs::read(root().join("bundle.json")).unwrap(),
        c.limits().clone(),
    )
    .unwrap();
    let files = [
        ("expected", "expected.json"),
        ("ledger", "ledger.json"),
        ("operands", "operands.bytes"),
    ]
    .into_iter()
    .map(|(id, p)| {
        (
            Label::parse(id).unwrap(),
            File::open(root().join(p)).unwrap(),
        )
    })
    .collect::<Vec<_>>();
    let opened = files
        .iter()
        .map(|(id, f)| OpenedVector {
            file_id: id.clone(),
            file: f,
        })
        .collect::<Vec<_>>();
    let mut meter = ArtifactMeasurer::new(c.run_id().clone(), c.limits().clone()).unwrap();
    let b = VectorBundle::read(&m, &opened, &mut meter).unwrap();
    VectorFixtureSession::new(c, b).unwrap()
}
pub fn run(wrong: bool) -> RunReport {
    let (_, p, c) = load();
    let mut a = adapter::ArithmeticAdapter {
        subject: c.expected_subject().clone(),
        wrong,
        calls: 0,
    };
    let o = oracle::ArithmeticOracle {
        binding: c.expected_oracle().clone(),
    };
    run_profile(&p, &mut a, &mut session(c), &o).unwrap()
}
pub fn literal() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(root().join("receipt-qualified.json")).unwrap()).unwrap()
}
pub fn imported(v: &serde_json::Value) -> Result<RunReport, HarnessError> {
    let (_, _, c) = load();
    RunReport::from_json(&c, &serde_json::to_vec(v).unwrap(), RunLimits::default())
}
pub fn partial_q(v: &mut serde_json::Value) -> Qualification {
    v["run_terminal"] = serde_json::Value::Null;
    imported(v).unwrap().qualification()
}
pub fn contract_value() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(root().join("contract.json")).unwrap()).unwrap()
}
pub fn changed_contract(v: &serde_json::Value) -> RunContract {
    let (c, p, _) = load();
    RunContract::load(
        &c,
        &p,
        &serde_json::to_vec(v).unwrap(),
        RunLimits::default(),
    )
    .unwrap()
}
pub fn rebase(v: &mut serde_json::Value, contract: &serde_json::Value) -> RunContract {
    let c = changed_contract(contract);
    v["run_contract_sha256"] = c.sha256().as_str().into();
    v["artifacts"] = serde_json::to_value(c.artifacts()).unwrap();
    v["case_results"][0]["script_sha256"] = c.case_rules()[0].script().sha256().as_str().into();
    c
}
pub fn change_coverage(id: &str, count: &str) -> (RunContract, serde_json::Value) {
    let mut v = literal();
    let mut cv = contract_value();
    let mut ledger: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("ledger.json")).unwrap()).unwrap();
    for row in ledger["coverage"].as_array_mut().unwrap() {
        if row["id"] == id {
            row["achieved"] = count.into()
        }
    }
    let bytes = serde_json::to_vec(&ledger).unwrap();
    let hash = Digest256::of_bytes(&bytes).as_str();
    for a in cv["artifacts"].as_array_mut().unwrap() {
        if a["id"] == "ledger" {
            a["sha256"] = hash.clone().into();
            a["length"] = bytes.len().to_string().into()
        }
    }
    let hex = bytes.iter().map(|x| format!("{x:02x}")).collect::<String>();
    v["case_results"][0]["expected_evidence"]["ledger_bytes"] = hex.into();
    v["case_results"][0]["expected_evidence"]["coverage"] = ledger["coverage"].clone();
    for row in v["case_results"][0]["coverage"].as_array_mut().unwrap() {
        if row["id"] == id {
            row["raw_achieved"] = count.into();
            row["effective_achieved"] = count.into()
        }
    }
    v["case_results"][0]["effective_checks"][0]["status"] = "not_judged".into();
    v["case_results"][0]["effective_checks"][0]["reason"] = "prerequisite missing".into();
    v["run_terminal"]["qualification"] = "incomplete".into();
    v["run_terminal"]["reasons"] = serde_json::json!(["case.coverage", "case.not_judged"]);
    let c = rebase(&mut v, &cv);
    (c, v)
}
pub fn session_custom(c: RunContract) -> VectorFixtureSession {
    let mut v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("bundle.json")).unwrap()).unwrap();
    v["run_contract_sha256"] = c.sha256().as_str().into();
    let m = VectorManifest::load(&c, &serde_json::to_vec(&v).unwrap(), c.limits().clone()).unwrap();
    let files = [
        ("expected", "expected.json"),
        ("ledger", "ledger.json"),
        ("operands", "operands.bytes"),
    ]
    .into_iter()
    .map(|(id, p)| {
        (
            Label::parse(id).unwrap(),
            File::open(root().join(p)).unwrap(),
        )
    })
    .collect::<Vec<_>>();
    let opened = files
        .iter()
        .map(|(id, f)| OpenedVector {
            file_id: id.clone(),
            file: f,
        })
        .collect::<Vec<_>>();
    let mut meter = ArtifactMeasurer::new(c.run_id().clone(), c.limits().clone()).unwrap();
    let b = VectorBundle::read(&m, &opened, &mut meter).unwrap();
    VectorFixtureSession::new(c, b).unwrap()
}
#[path = "instrumented.rs"]
pub mod instrumented;
pub fn effect_contract() -> RunContract {
    let mut v = contract_value();
    v["case_rules"][0]["max_effects"] = 2.into();
    changed_contract(&v)
}
pub fn unimplemented() -> (ProfilePlan, RunContract) {
    let mut cv = contract_value();
    let mut catalog: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("catalog.json")).unwrap()).unwrap();
    catalog["cases"][0]["implementation_status"] = "UNIMPLEMENTED".into();
    catalog["cases"][0]["registration"] = serde_json::Value::Null;
    let bytes = serde_json::to_vec(&catalog).unwrap();
    let c = CaseCatalog::load(&bytes, CatalogLimits::default()).unwrap();
    let p = ProfilePlan::select(&c, &ProfileId::parse("tt02-harness-v1").unwrap()).unwrap();
    cv["catalog_sha256"] = c.source_sha256().as_str().into();
    cv["selection"]["required"][0]["implementation_status"] = "UNIMPLEMENTED".into();
    let contract = RunContract::load(
        &c,
        &p,
        &serde_json::to_vec(&cv).unwrap(),
        RunLimits::default(),
    )
    .unwrap();
    (p, contract)
}
#[path = "model_adapter.rs"]
pub mod model_adapter;
#[path = "model_oracle.rs"]
pub mod model_oracle;
pub fn refusal_contract(cause: &str) -> (ProfilePlan, RunContract) {
    refusal_contract_inputs(
        cause,
        LICENSE_INPUT,
        LICENSE_EXPECTED,
        include_bytes!("source-terms.bytes"),
        include_bytes!("elf-license.bin"),
        include_bytes!("loader-license.bin"),
    )
}
pub fn refusal_contract_inputs(
    cause: &str,
    input: &[u8],
    expected: &[u8],
    source: &[u8],
    elf: &[u8],
    loader: &[u8],
) -> (ProfilePlan, RunContract) {
    let mut cv = contract_value();
    let mut cat: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("catalog.json")).unwrap()).unwrap();
    let mut second = cat["cases"][0].clone();
    second["id"] = "H01.refusal".into();
    for (key, file, id, role) in [
        (
            "executable",
            "model_adapter.rs",
            "model-case",
            "case_source",
        ),
        ("oracle", "model_oracle.rs", "model-oracle", "oracle_source"),
    ] {
        let b = std::fs::read(root().join(file)).unwrap();
        let sha = Digest256::of_bytes(&b).as_str();
        let registration = serde_json::json!({"id":id,"revision":1,"path":format!("tests/fixtures/harness/{file}"),"sha256":sha,"entrypoint":format!("model.{key}")});
        second["registration"][key] = registration.clone();
        if key == "oracle" || key == "executable" {
            cat["cases"][0]["registration"][key] = registration;
            if key == "oracle" {
                cv["expected_oracle"]["source_sha256"] = sha.clone().into();
                cv["expected_oracle"]["artifact_id"] = id.into();
            }
        }
        cv["artifacts"].as_array_mut().unwrap().push(serde_json::json!({"id":id,"revision":1,"role":role,"length":b.len().to_string(),"sha256":sha}));
    }
    cat["cases"].as_array_mut().unwrap().push(second);
    cat["profiles"][0]["required_cases"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"case_id":"H01.refusal","case_version":1,"when_extensions":[]}));
    let cat_bytes = serde_json::to_vec(&cat).unwrap();
    let cat = CaseCatalog::load(&cat_bytes, CatalogLimits::default()).unwrap();
    let p = ProfilePlan::select(&cat, &ProfileId::parse("tt02-harness-v1").unwrap()).unwrap();
    cv["catalog_sha256"] = cat.source_sha256().as_str().into();
    let mut required = cv["selection"]["required"][0].clone();
    required["case_id"] = "H01.refusal".into();
    cv["selection"]["required"]
        .as_array_mut()
        .unwrap()
        .insert(0, required);
    let mut rule = cv["case_rules"][0].clone();
    rule["case_key"]["case_id"] = "H01.refusal".into();
    rule["script"]["schema_id"] = "tt02-refusal-v1".into();
    rule["script"]["steps"][0]["operation"] = "emit-model-outcome".into();
    rule["operation_ids"] = serde_json::json!(["2"]);
    rule["intent"] = serde_json::json!({"kind":"expected_refusal","cause":cause,"step_id":"sum","stage":"load","positive_twin":{"case_id":"H01.sum","case_version":1,"cell_id":"model"},"equivalence_assertion":"twin.equivalent"});
    rule["coverage"] = serde_json::json!([{"id":"setup","kind":"setup","minimum":"1","step_ids":["sum"]},{"id":"trigger","kind":"trigger","minimum":"1","step_ids":["sum"]}]);
    rule["assertions"] = serde_json::json!([{"id":"refusal.intended-cause","requires_coverage":["setup","trigger"],"requires_positive_twin":true},{"id":"twin.equivalent","requires_coverage":["setup","trigger"],"requires_positive_twin":true},{"id":"input.license-bytes","requires_coverage":["setup"],"requires_positive_twin":false}]);
    cv["case_rules"].as_array_mut().unwrap().push(rule);
    cv["case_rules"][0]["script"]["schema_id"] = "tt02-refusal-v1".into();
    cv["case_rules"][0]["script"]["steps"][0]["operation"] = "emit-model-outcome".into();
    let key = serde_json::json!({"run_id":cv["run_id"],"case_key":{"case_id":"H01.refusal","case_version":1,"cell_id":"model"},"attempt":1,"operation_id":"2"});
    let coverage = serde_json::json!([{"id":"setup","step_ids":["sum"],"achieved":"1"},{"id":"trigger","step_ids":["sum"],"achieved":"1"}]);
    let ledger=serde_json::to_vec(&serde_json::json!({"schema_version":1,"kind":"tt02-vector-ledger","key":key,"truth_kind":"fixed-before-execute","evidence_tier":"T0","coverage":coverage})).unwrap();
    for (id, role, bytes) in [
        ("model-input", "fixture_input", input),
        ("expected-model", "expected_vector", expected),
        ("model-ledger", "fixture_ledger", ledger.as_slice()),
        ("source-terms", "source_terms", source),
        ("elf-license", "elf_license_bytes", elf),
        ("loader-license", "loader_license_bytes", loader),
        (
            "positive-model-input",
            "fixture_input",
            include_bytes!("positive-input.json"),
        ),
        (
            "positive-model-expected",
            "expected_vector",
            include_bytes!("positive-expected.json"),
        ),
        (
            "positive-object",
            "fixture_input",
            include_bytes!("positive-object.bin"),
        ),
        (
            "negative-object",
            "fixture_input",
            include_bytes!("negative-object.bin"),
        ),
        (
            "positive-license",
            "elf_license_bytes",
            include_bytes!("positive-license.bin"),
        ),
        (
            "equivalence-model",
            "fixture_manifest",
            include_bytes!("model-context.json"),
        ),
    ] {
        cv["artifacts"].as_array_mut().unwrap().push(serde_json::json!({"id":id,"revision":1,"role":role,"length":bytes.len().to_string(),"sha256":Digest256::of_bytes(bytes).as_str()}));
    }
    cv["artifacts"]
        .as_array_mut()
        .unwrap()
        .sort_by_key(|a| a["id"].as_str().unwrap().to_owned());
    let contract = RunContract::load(
        &cat,
        &p,
        &serde_json::to_vec(&cv).unwrap(),
        RunLimits::default(),
    )
    .unwrap();
    (p, contract)
}
pub fn with_model_ledgers(mut cv: serde_json::Value) -> RunContract {
    let first = changed_contract(&cv);
    for key in first.schedule() {
        let rule = first
            .case_rules()
            .iter()
            .find(|r| r.case_key() == key.case_key())
            .unwrap();
        let cov = rule
            .coverage()
            .iter()
            .map(|r| serde_json::json!({"id":r.id(),"step_ids":r.step_ids(),"achieved":"1"}))
            .collect::<Vec<_>>();
        let bytes=serde_json::to_vec(&serde_json::json!({"schema_version":1,"kind":"tt02-vector-ledger","key":key,"truth_kind":"fixed-before-execute","evidence_tier":"T0","coverage":cov})).unwrap();
        cv["artifacts"].as_array_mut().unwrap().push(serde_json::json!({"id":format!("model-ledger-{}",key.operation_id()),"revision":1,"role":"fixture_ledger","length":bytes.len().to_string(),"sha256":Digest256::of_bytes(&bytes).as_str()}));
    }
    cv["artifacts"]
        .as_array_mut()
        .unwrap()
        .sort_by_key(|a| a["id"].as_str().unwrap().to_owned());
    changed_contract(&cv)
}

pub const LICENSE_INPUT: &[u8] = include_bytes!("license-input.json");
pub const LICENSE_EXPECTED: &[u8] = include_bytes!("license-expected.json");
pub fn model_case(
    actual: &'static [u8],
    expected: &'static [u8],
    cause: &str,
    domains: [&[u8]; 3],
) -> (RunContract, RunReport) {
    let (p, c) =
        refusal_contract_inputs(cause, actual, expected, domains[0], domains[1], domains[2]);
    let mut session = instrumented::Session::new(c.clone());
    session.model_input = Some(actual);
    session.expected_override = Some(expected);
    let mut adapter = model_adapter::ModelAdapter {
        arithmetic: adapter::ArithmeticAdapter {
            subject: c.expected_subject().clone(),
            wrong: false,
            calls: 0,
        },
    };
    let oracle = model_oracle::ModelOracle {
        arithmetic: oracle::ArithmeticOracle {
            binding: c.expected_oracle().clone(),
        },
        rules: c.case_rules().to_vec(),
        source_terms: domains[0].to_vec(),
        elf_license: domains[1].to_vec(),
        loader_license: domains[2].to_vec(),
        context: include_bytes!("model-context.json").to_vec(),
        objects: c.artifacts().to_vec(),
    };
    let report = run_profile(&p, &mut adapter, &mut session, &oracle).unwrap();
    (c, report)
}
