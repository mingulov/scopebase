// SPDX-License-Identifier: Apache-2.0
// This client imports an independently authored literal failure; it never calls
// run_profile or uses its producer/serializer to construct expected truth.
use scopebase_testkit::*;
use std::{fs, path::PathBuf};
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let root = args
        .first()
        .map_or_else(|| PathBuf::from("fixtures/harness"), PathBuf::from);
    if args.len() == 3 {
        let expected = bounded(&args[1]);
        let actual = bounded(&args[2]);
        assert!(expected.len() <= 8_388_608 && actual.len() <= 8_388_608);
        assert_eq!(
            expected, actual,
            "actual receipt consumer executable binding"
        );
    }
    let catalog = CaseCatalog::load(
        &fs::read(root.join("catalog.json")).unwrap(),
        CatalogLimits::default(),
    )
    .unwrap();
    let plan =
        ProfilePlan::select(&catalog, &ProfileId::parse("tt02-harness-v1").unwrap()).unwrap();
    let contract = RunContract::load(
        &catalog,
        &plan,
        &fs::read(root.join("contract.json")).unwrap(),
        RunLimits::default(),
    )
    .unwrap();
    let failure = fs::read(root.join("receipt-failed.json")).unwrap();
    let report = RunReport::from_json(&contract, &failure, RunLimits::default()).unwrap();
    assert_eq!(report.origin(), ReportOrigin::Imported);
    assert_eq!(report.qualification(), Qualification::Failed);
    assert_eq!(
        *report.case_results()[0].effective_checks()[0].status(),
        CheckStatus::Fail
    );
    let false_green = std::str::from_utf8(&failure).unwrap().replace(
        "\"qualification\":\"failed\"",
        "\"qualification\":\"qualified\"",
    );
    assert_eq!(
        RunReport::from_json(&contract, false_green.as_bytes(), RunLimits::default())
            .unwrap_err()
            .kind(),
        HarnessErrorKind::InvalidProtocol
    );
    println!("TT02 independent imported failure and false-green controls passed");
}

fn bounded(path: &str) -> Vec<u8> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .take(8_388_609)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 8_388_608);
    bytes
}
