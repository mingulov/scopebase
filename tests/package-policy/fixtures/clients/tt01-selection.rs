// SPDX-License-Identifier: Apache-2.0
use scopebase_testkit::{CaseCatalog, CatalogLimits, EvidenceTier, ProfileId, ProfilePlan};
// A second independent consumer with its own diamond and conditional population.
const INPUT:&[u8]=br#"{
 "schema_version":1,"catalog_revision":1,"tasks":["TT01"],
 "obligations":[{"kind":"regression_family","id":"H04","description":"Retained file metadata","owners":["TT01"]}],
 "families":[{"id":"H04","short_contract":"Retain original file identity","obligations":[{"kind":"regression_family","id":"H04"}]}],
 "cells":[{"id":"held","tier":"T0","description":"Held file metadata","binding":"LOGICAL_ONLY"},{"id":"conditional","tier":"T2","description":"Conditional artifact metadata","binding":"LOGICAL_ONLY"}],
 "cases":[
 {"id":"H04.path_swap","family":"H04","version":1,"implementation_status":"UNIMPLEMENTED","owners":["TT01"],"obligations":[{"kind":"regression_family","id":"H04"}],"required_cells":["held"],"registration":null},
 {"id":"H04.extension","family":"H04","version":1,"implementation_status":"UNIMPLEMENTED","owners":["TT01"],"obligations":[{"kind":"regression_family","id":"H04"}],"required_cells":["conditional"],"registration":null}],
 "profiles":[
 {"id":"app-v1","definition_state":"DRAFT","requires_profiles":["left-v1","right-v1"],"requires_extensions":["extra-v1"],"required_cases":[],"open_owners":["TT01"]},
 {"id":"left-v1","definition_state":"DRAFT","requires_profiles":["leaf-v1"],"requires_extensions":[],"required_cases":[{"case_id":"H04.path_swap","case_version":1,"when_extensions":[]}],"open_owners":["TT01"]},
 {"id":"right-v1","definition_state":"DRAFT","requires_profiles":["leaf-v1"],"requires_extensions":[],"required_cases":[{"case_id":"H04.path_swap","case_version":1,"when_extensions":[]}],"open_owners":["TT01"]},
 {"id":"leaf-v1","definition_state":"DRAFT","requires_profiles":[],"requires_extensions":[],"required_cases":[{"case_id":"H04.extension","case_version":1,"when_extensions":["extra-v1"]}],"open_owners":["TT01"]}],
 "extensions":[{"id":"extra-v1","profile":"leaf-v1","requires_profiles":[],"requires_tasks":["TT01"],"required_cases":[]}]
}"#;
fn main() {
    let catalog = CaseCatalog::load(INPUT, CatalogLimits::default()).unwrap();
    let bare = ProfilePlan::select(&catalog, &ProfileId::parse("leaf-v1").unwrap()).unwrap();
    assert!(bare.required().is_empty());
    assert!(bare.extensions().is_empty());
    let plan = ProfilePlan::select(&catalog, &ProfileId::parse("app-v1").unwrap()).unwrap();
    assert_eq!(
        plan.profiles()
            .iter()
            .map(ProfileId::as_str)
            .collect::<Vec<_>>(),
        ["app-v1", "leaf-v1", "left-v1", "right-v1"]
    );
    assert_eq!(
        plan.extensions()
            .iter()
            .map(ProfileId::as_str)
            .collect::<Vec<_>>(),
        ["extra-v1"]
    );
    let tuples = plan
        .required()
        .iter()
        .map(|r| {
            (
                r.case_id().as_str(),
                r.case_version(),
                r.cell_id(),
                r.tier(),
                r.required_by()
                    .iter()
                    .map(ProfileId::as_str)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        tuples,
        vec![
            (
                "H04.extension",
                1,
                "conditional",
                EvidenceTier::T2,
                vec!["leaf-v1"]
            ),
            (
                "H04.path_swap",
                1,
                "held",
                EvidenceTier::T0,
                vec!["left-v1", "right-v1"]
            )
        ]
    );
    assert_eq!(plan.open_owners(), ["TT01"]);
    assert!(!plan.definition_complete());
    assert!(plan
        .validate_selection(plan.profiles(), plan.extensions(), plan.required())
        .is_ok());
    assert!(plan
        .validate_selection(plan.profiles(), plan.extensions(), &plan.required()[..1])
        .is_err());
    println!("tt01 selection: diamond and conditional closure");
}
