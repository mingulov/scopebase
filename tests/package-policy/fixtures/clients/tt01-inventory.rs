// SPDX-License-Identifier: Apache-2.0
use scopebase_testkit::{CaseCatalog, CaseId, CatalogLimits, ImplementationStatus};
// Independently authored consumer inventory. It does not import the library's
// test catalog or use a production serializer to construct its expected values.
const INPUT:&[u8]=br#"{
 "schema_version":1,"catalog_revision":7,"tasks":["SB01","TT01"],
 "obligations":[{"kind":"regression_family","id":"H33","description":"Source grants and runtime bytes are separate","owners":["SB01","TT01"]}],
 "families":[{"id":"H33","short_contract":"Separate source and runtime license observations","obligations":[{"kind":"regression_family","id":"H33"}]}],
 "cells":[{"id":"source-notice","tier":"T0","description":"Independent source notice inventory","binding":"LOGICAL_ONLY"}],
 "cases":[{"id":"H33.source-closure","family":"H33","version":1,"implementation_status":"UNIMPLEMENTED","owners":["SB01"],"obligations":[{"kind":"regression_family","id":"H33"}],"required_cells":["source-notice"],"registration":null}],
 "profiles":[],"extensions":[]
}"#;
fn main() {
    let catalog =
        CaseCatalog::load(INPUT, CatalogLimits::default()).expect("literal inventory admitted");
    assert_eq!(catalog.revision(), 7);
    let id = CaseId::parse("H33.source-closure").unwrap();
    let case = catalog.case(&id, 1).unwrap();
    assert_eq!(case.family(), "H33");
    assert_eq!(case.owners(), ["SB01"]);
    assert_eq!(case.required_cells(), ["source-notice"]);
    assert_eq!(
        case.implementation_status(),
        ImplementationStatus::Unimplemented
    );
    assert!(case.registration().is_none());
    assert!(catalog.case(&id, 0).is_none());
    assert!(catalog.case(&id, 2).is_none());
    let obligation = &catalog.obligations()[0];
    assert_eq!(obligation.kind(), "regression_family");
    assert_eq!(obligation.id(), "H33");
    assert_eq!(obligation.owners(), ["SB01", "TT01"]);
    println!("tt01 inventory: exact revisions and owners");
}
