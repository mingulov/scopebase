// SPDX-License-Identifier: Apache-2.0
//! Runs every bound model set through the shipped fixture engine and adapter.
use scopebase_testkit::bpf::BpfHostAdapter;
use scopebase_testkit::*;
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};
mod oracle;
fn bounded(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path)
        .unwrap()
        .take(8_388_609)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 8_388_608);
    bytes
}
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    assert_eq!(args.len(), 3);
    let root = Path::new(&args[0]);
    let profile = &args[1];
    let mut completed = Vec::<&str>::new();
    #[cfg(feature = "json")]
    {
        if profile == "bp03-host-json-models-v1" {
            let bytes =
                bounded(&Path::new(&args[2]).join("fixtures/capability-v1/codec/valid-base.bytes"));
            let limits = scopebase_bpf::Limits {
                input_bytes: 65536,
                retained_bytes: 131072,
                work_steps: 8388608,
                sites: 0,
                live_links: 0,
                pending_retirements: 0,
            };
            let record = scopebase_bpf::CapabilityObservation::from_json(&bytes, &limits).unwrap();
            assert_eq!(record.origin(), scopebase_bpf::ObservationOrigin::Imported);
            assert_eq!(
                record.claimed_origin(),
                scopebase_bpf::ObservationOrigin::CallerDescribed
            );
            assert_eq!(record.reason(), &[0, 10, 127, 255]);
            assert_eq!(record.diagnostic(), &[0, 101, 97, 99, 99, 101, 115, 255]);
            assert_eq!(record.state(), scopebase_bpf::CapabilityState::Denied);
            assert_eq!(record.stage(), scopebase_bpf::EvidenceStage::Load);
            assert_eq!(
                record.operation_error().unwrap().stage(),
                scopebase_bpf::Stage::Execute
            );
            assert_eq!(record.to_json(&limits).unwrap(), bytes);
            completed.push("populations.json-direct-api");
        }
    }
    let catalog = CaseCatalog::load(
        &bounded(&root.join("catalog.json")),
        CatalogLimits::default(),
    )
    .unwrap();
    let plan = ProfilePlan::select(&catalog, &ProfileId::parse(profile).unwrap()).unwrap();
    let list = String::from_utf8(bounded(&root.join("runs.txt"))).unwrap();
    let mut count = 0;
    for name in list.lines() {
        assert!(!name.is_empty() && !name.contains('/') && !name.contains(".."));
        let directory = root.join(name);
        let contract = RunContract::load(
            &catalog,
            &plan,
            &bounded(&directory.join("contract.json")),
            RunLimits::default(),
        )
        .unwrap();
        let limits = contract.limits().clone();
        let manifest = VectorManifest::load(
            &contract,
            &bounded(&directory.join("bundle.json")),
            limits.clone(),
        )
        .unwrap();
        let handles = manifest
            .files()
            .iter()
            .map(|row| {
                (
                    row.file_id().clone(),
                    File::open(
                        directory
                            .join("files")
                            .join(format!("{}.bytes", row.file_id().as_str())),
                    )
                    .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let opened = handles
            .iter()
            .map(|(id, file)| OpenedVector {
                file_id: id.clone(),
                file,
            })
            .collect::<Vec<_>>();
        let mut meter = ArtifactMeasurer::new(contract.run_id().clone(), limits.clone()).unwrap();
        let bundle = VectorBundle::read(&manifest, &opened, &mut meter).unwrap();
        let oracle = oracle::LiteralOracle {
            binding: contract.expected_oracle().clone(),
            rules: contract.case_rules().to_vec(),
            limits: limits.clone(),
        };
        let bpf = scopebase_bpf::Limits {
            input_bytes: 131072,
            retained_bytes: 262144,
            work_steps: 8388608,
            sites: 0,
            live_links: 0,
            pending_retirements: 0,
        };
        let mut adapter =
            BpfHostAdapter::new(contract.expected_subject().clone(), bpf, limits.clone()).unwrap();
        let mut session = VectorFixtureSession::new(contract.clone(), bundle).unwrap();
        let report = run_profile_prepared(&plan, &mut adapter, &mut session, &oracle).unwrap();
        assert_eq!(report.origin(), ReportOrigin::ExecutedHere);
        assert_eq!(
            report.qualification(),
            Qualification::Qualified,
            "literal model oracle failed: {name}: {:?}",
            report.reasons()
        );
        for case in report.case_results() {
            assert_eq!(
                *case.capability().state(),
                CapabilityState::Unknown,
                "filter.not-native-support"
            );
            assert_eq!(
                *case.oracle_verdict().unwrap().capability().state(),
                CapabilityState::Unknown
            );
            assert!(case
                .oracle_verdict()
                .unwrap()
                .checks()
                .iter()
                .all(|c| *c.status() == CheckStatus::Pass));
        }
        let bytes = report.to_json(limits.clone()).unwrap();
        fs::write(directory.join("report.json"), &bytes).unwrap();
        let imported = RunReport::from_json(&contract, &bytes, limits).unwrap();
        assert_eq!(imported.origin(), ReportOrigin::Imported);
        assert_eq!(imported.qualification(), Qualification::Qualified);
        count += 1;
    }
    assert_eq!(count, 38, "all fixed filter populations must execute");
    #[cfg(feature = "json")]
    {
        if profile == "bp03-host-json-models-v1" {
            completed.push("populations.json-adapter-cases");
            completed.push("populations.json-report-roundtrip");
        }
    }
    completed.sort_unstable();
    println!(
        "BP03_COMPLETION {{\"client\":\"bp03-populations\",\"groups\":[{}]}}",
        completed
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("bp03-populations: 38 model sets executed through adapter/VectorFixtureSession/run_profile_prepared and reports reimported; actual environment unknown");
}
