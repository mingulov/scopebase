use scopebase_testkit::*;
#[test]
fn exact_ids_and_required_selection() {
    assert!(CaseId::parse("H04.path_swap").is_ok());
    for bad in ["", "H04.path_swap\n", ".H04", "foo/bar", "é"] {
        assert!(CaseId::parse(bad).is_err());
    }
    assert!(CaseId::parse(&"a".repeat(96)).is_ok());
    assert!(CaseId::parse(&"a".repeat(97)).is_err());
    assert!(ProfileId::parse(&"a".repeat(64)).is_ok());
    assert!(ProfileId::parse(&"a".repeat(65)).is_err());
}
use serde_json::{json, Value};
const INITIAL: &[u8] = include_bytes!("fixtures/catalog/cases-v1.json");
const A: &[u8] = include_bytes!("fixtures/catalog/revision-a.json");
const B: &[u8] = include_bytes!("fixtures/catalog/revision-b.json");
fn load(v: &Value) -> Result<CaseCatalog, CatalogError> {
    CaseCatalog::load(&serde_json::to_vec(v).unwrap(), CatalogLimits::default())
}
fn bad(v: &Value, k: CatalogErrorKind) {
    assert_eq!(load(v).unwrap_err().kind(), k)
}
#[test]
fn admission_and_revision_identity() {
    assert!(CaseCatalog::load(INITIAL, CatalogLimits::default()).is_ok());
    assert!(CaseCatalog::load(A, CatalogLimits::default()).is_ok());
    let base: Value = serde_json::from_slice(B).unwrap();
    assert!(load(&base).is_ok());
    let mut v = base.clone();
    let duplicate = v["cases"][0].clone();
    v["cases"].as_array_mut().unwrap().push(duplicate);
    bad(&v, CatalogErrorKind::DuplicateId);
    for (version, kind) in [
        (json!(3), CatalogErrorKind::UnknownReference),
        (json!(0), CatalogErrorKind::InvalidVersion),
        (json!(true), CatalogErrorKind::InvalidVersion),
        (json!(1.0), CatalogErrorKind::InvalidVersion),
        (json!(4294967296u64), CatalogErrorKind::InvalidVersion),
    ] {
        let mut v = base.clone();
        v["profiles"][1]["required_cases"][0]["case_version"] = version;
        bad(&v, kind);
    }
    let mut v = base.clone();
    v["cases"][0]["owners"] = json!(["UNKNOWN"]);
    bad(&v, CatalogErrorKind::UnknownReference);
    let mut v = base.clone();
    v["profiles"][0]["requires_profiles"] = json!(["revision-fixture-v1"]);
    bad(&v, CatalogErrorKind::Cycle);
    let mut v = base.clone();
    v["profiles"][0]["requires_profiles"] = json!(["revision-fixture-v2"]);
    bad(&v, CatalogErrorKind::VersionConflict);
    let mut v = base.clone();
    v["profiles"][0]["definition_state"] = json!("FROZEN");
    bad(&v, CatalogErrorKind::InvalidDefinition);
    let mut v = base.clone();
    v["cases"][1]["runnable"] = json!(true);
    bad(&v, CatalogErrorKind::UnknownField);
    let mut v = base.clone();
    v["cases"][1]
        .as_object_mut()
        .unwrap()
        .remove("registration");
    bad(&v, CatalogErrorKind::InvalidJson);
    let mut v = base.clone();
    v["catalog_revision"] = json!(0);
    bad(&v, CatalogErrorKind::InvalidVersion);
    let mut v = base.clone();
    v["schema_version"] = json!(2);
    bad(&v, CatalogErrorKind::UnsupportedSchema);
}
#[test]
fn strict_json_and_bounds() {
    let source = std::str::from_utf8(A).unwrap();
    for (s, kind) in [
        (
            source.replacen(
                "\"schema_version\": 1",
                "\"schema_version\": 1, \"schema_version\": 1",
                1,
            ),
            CatalogErrorKind::DuplicateField,
        ),
        (format!("{source} {{}}"), CatalogErrorKind::InvalidJson),
        (
            source.replace("H04.revision-fixture", "H04.bad\\n"),
            CatalogErrorKind::InvalidId,
        ),
        (
            format!("{}", "[".repeat(33)),
            CatalogErrorKind::LimitExceeded,
        ),
    ] {
        assert_eq!(
            CaseCatalog::load(s.as_bytes(), CatalogLimits::default())
                .unwrap_err()
                .kind(),
            kind
        );
    }
    assert_eq!(
        CaseCatalog::load(&[0xff], CatalogLimits::default())
            .unwrap_err()
            .kind(),
        CatalogErrorKind::InvalidJson
    );
    let mut limits = CatalogLimits::default();
    limits.max_cases = 1;
    assert!(CaseCatalog::load(A, limits.clone()).is_ok());
    assert_eq!(
        CaseCatalog::load(B, limits).unwrap_err().kind(),
        CatalogErrorKind::LimitExceeded
    );
    let mut limits = CatalogLimits::default();
    limits.max_input_bytes = A.len();
    assert!(CaseCatalog::load(A, limits.clone()).is_ok());
    limits.max_input_bytes -= 1;
    assert_eq!(
        CaseCatalog::load(A, limits).unwrap_err().kind(),
        CatalogErrorKind::InputTooLarge
    );
    let mut limits = CatalogLimits::default();
    limits.max_depth = 0;
    assert_eq!(
        CaseCatalog::load(A, limits).unwrap_err().kind(),
        CatalogErrorKind::InvalidLimits
    );
    let mut limits = CatalogLimits::default();
    limits.max_string_bytes = 10;
    assert_eq!(
        CaseCatalog::load(A, limits).unwrap_err().kind(),
        CatalogErrorKind::LimitExceeded
    );
}
fn select(c: &CaseCatalog, s: &str) -> ProfilePlan {
    ProfilePlan::select(c, &ProfileId::parse(s).unwrap()).unwrap()
}
fn projection(p: &ProfilePlan) -> Vec<(String, u32, String, EvidenceTier, Vec<String>)> {
    p.required()
        .iter()
        .map(|r| {
            (
                r.case_id().as_str().into(),
                r.case_version(),
                r.cell_id().into(),
                r.tier(),
                r.required_by().iter().map(|s| s.as_str().into()).collect(),
            )
        })
        .collect()
}
#[test]
fn composite_and_extension_closure() {
    let c = CaseCatalog::load(INITIAL, CatalogLimits::default()).unwrap();
    assert_eq!(c.revision(), 1);
    assert_eq!(c.obligations().len(), 179);
    let object = select(&c, "compiler-object-v1");
    assert_eq!(
        object
            .required()
            .iter()
            .map(|r| (r.case_id().as_str(), r.tier()))
            .collect::<Vec<_>>(),
        vec![
            ("H33.final-object-license", EvidenceTier::T2),
            ("H33.source-closure", EvidenceTier::T0)
        ]
    );
    let runtime = select(&c, "compiler-runtime-x86-v1");
    assert_eq!(runtime.required().len(), 4);
    let native = select(&c, "native-v1");
    assert_eq!(
        native
            .profiles()
            .iter()
            .map(ProfileId::as_str)
            .collect::<Vec<_>>(),
        [
            "bpf-host-v1",
            "btf-shape-le-v1",
            "capture-core-v1",
            "compiler-object-v1",
            "mojo-elf-v1",
            "native-v1"
        ]
    );
    assert_eq!(
        native
            .extensions()
            .iter()
            .map(ProfileId::as_str)
            .collect::<Vec<_>>(),
        ["btf-runtime-linkage-v1"]
    );
    assert_eq!(
        projection(&native),
        vec![
            (
                "H33.final-object-license".into(),
                1,
                "h33-final-object-license".into(),
                EvidenceTier::T2,
                vec!["compiler-object-v1".into()]
            ),
            (
                "H33.installed-notices".into(),
                1,
                "h33-installed-notices".into(),
                EvidenceTier::T5,
                vec!["mojo-elf-v1".into()]
            ),
            (
                "H33.license-admission".into(),
                1,
                "h33-license-admission".into(),
                EvidenceTier::T4,
                vec!["btf-shape-le-v1".into()]
            ),
            (
                "H33.source-closure".into(),
                1,
                "h33-source-closure".into(),
                EvidenceTier::T0,
                vec!["compiler-object-v1".into()]
            )
        ]
    );
    let bare = select(&c, "btf-shape-le-v1");
    assert!(bare.required().is_empty());
    assert!(bare.extensions().is_empty());
    assert!(!bare.definition_complete());
    let sdk = select(&c, "sdk-live-aya-v1");
    assert_eq!(
        sdk.profiles()
            .iter()
            .map(ProfileId::as_str)
            .collect::<Vec<_>>(),
        [
            "bpf-aya-uprobe-v1",
            "capture-core-v1",
            "compiler-object-v1",
            "held-file-v1",
            "owned-child-v1",
            "process-observation-v1",
            "sdk-host-v1",
            "sdk-live-aya-v1"
        ]
    );
    assert_eq!(sdk.required().len(), 4);
    let v: Value = serde_json::from_slice(INITIAL).unwrap();
    assert_eq!(v["extensions"][0]["required_cases"], json!([]));
    assert!(native
        .required()
        .iter()
        .all(|r| r.implementation_status() == ImplementationStatus::Unimplemented));
    assert!(!native.definition_complete());
    assert_eq!(
        ProfilePlan::select(&c, &ProfileId::parse("btf-runtime-linkage-v1").unwrap())
            .unwrap_err()
            .kind(),
        PlanErrorKind::ExtensionNotProfile
    );
    assert_eq!(
        ProfilePlan::select(&c, &ProfileId::parse("unknown-v1").unwrap())
            .unwrap_err()
            .kind(),
        PlanErrorKind::UnknownProfile
    );
    let mut ps = native.profiles().to_vec();
    ps.reverse();
    let mut rs = native.required().to_vec();
    rs.reverse();
    assert!(native
        .validate_selection(&ps, native.extensions(), &rs)
        .is_ok());
    assert_eq!(
        native
            .validate_selection(&ps, native.extensions(), &rs[1..])
            .unwrap_err()
            .kind(),
        PlanErrorKind::SelectionMismatch
    );
    assert_eq!(
        native
            .validate_selection(&ps[..ps.len() - 1], native.extensions(), &rs)
            .unwrap_err()
            .kind(),
        PlanErrorKind::SelectionMismatch
    );
    assert_eq!(
        native.validate_selection(&ps, &[], &rs).unwrap_err().kind(),
        PlanErrorKind::SelectionMismatch
    );
    rs.push(rs[0].clone());
    assert_eq!(
        native
            .validate_selection(&ps, native.extensions(), &rs)
            .unwrap_err()
            .kind(),
        PlanErrorKind::SelectionMismatch
    );
    drop(c);
    assert_eq!(native.required().len(), 4);
}
#[test]
fn exact_revisions_and_transport() {
    let c = CaseCatalog::load(B, CatalogLimits::default()).unwrap();
    let id = CaseId::parse("H04.revision-fixture").unwrap();
    assert_eq!(
        c.case(&id, 1).unwrap().required_cells(),
        ["revision-before"]
    );
    assert_eq!(
        c.case(&id, 2).unwrap().required_cells(),
        ["revision-before", "revision-after"]
    );
    assert!(c.case(&id, 0).is_none());
    assert!(c.case(&id, 3).is_none());
    assert_eq!(
        projection(&select(&c, "revision-fixture-v1")),
        vec![(
            "H04.revision-fixture".into(),
            1,
            "revision-before".into(),
            EvidenceTier::T0,
            vec!["revision-fixture-v1".into()]
        )]
    );
    assert_eq!(
        projection(&select(&c, "revision-fixture-v2")),
        vec![
            (
                "H04.revision-fixture".into(),
                2,
                "revision-after".into(),
                EvidenceTier::T0,
                vec!["revision-fixture-v2".into()]
            ),
            (
                "H04.revision-fixture".into(),
                2,
                "revision-before".into(),
                EvidenceTier::T0,
                vec!["revision-fixture-v2".into()]
            )
        ]
    );
    let mut v: Value = serde_json::from_slice(B).unwrap();
    v["cases"].as_array_mut().unwrap().reverse();
    let reversed = load(&v).unwrap();
    assert_eq!(
        projection(&select(&c, "revision-fixture-v2")),
        projection(&select(&reversed, "revision-fixture-v2"))
    );
    let mut d: Value = serde_json::from_slice(B).unwrap();
    d["cases"][1]["required_cells"] = json!(["revision-before"]);
    let dp = select(&load(&d).unwrap(), "revision-fixture-v2");
    d["profiles"][1]["required_cases"][0]["case_version"] = json!(1);
    let cp = select(&load(&d).unwrap(), "revision-fixture-v2");
    assert_eq!(
        dp.validate_selection(cp.profiles(), cp.extensions(), cp.required())
            .unwrap_err()
            .kind(),
        PlanErrorKind::SelectionMismatch
    );
}
fn draft(id: &str, requires: Value, required: Value) -> Value {
    json!({"id":id,"definition_state":"DRAFT","requires_profiles":requires,"requires_extensions":[],"required_cases":required,"open_owners":["TT01"]})
}
#[test]
fn mixed_revisions_diamond_and_global_rejection() {
    let mut v: Value = serde_json::from_slice(B).unwrap();
    let req = json!([{"case_id":"H04.revision-fixture","case_version":1,"when_extensions":[]}]);
    v["profiles"].as_array_mut().unwrap().extend([
        draft("revision-left-v1", json!([]), req.clone()),
        draft("revision-right-v1", json!([]), req),
        draft(
            "revision-join-v1",
            json!(["revision-left-v1", "revision-right-v1"]),
            json!([]),
        ),
    ]);
    let valid = load(&v).unwrap();
    let join = select(&valid, "revision-join-v1");
    assert_eq!(
        projection(&join),
        vec![(
            "H04.revision-fixture".into(),
            1,
            "revision-before".into(),
            EvidenceTier::T0,
            vec!["revision-left-v1".into(), "revision-right-v1".into()]
        )]
    );
    v["profiles"][3]["required_cases"][0]["case_version"] = json!(2);
    bad(&v, CatalogErrorKind::VersionConflict);
    v["profiles"][3]["required_cases"][0]["case_version"] = json!(1);
    assert!(load(&v).is_ok());
    let mut v: Value = serde_json::from_slice(B).unwrap();
    v["profiles"][1]["required_cases"]
        .as_array_mut()
        .unwrap()
        .push(json!({"case_id":"H04.revision-fixture","case_version":1,"when_extensions":[]}));
    bad(&v, CatalogErrorKind::VersionConflict);
}
#[test]
fn independent_fixture_accept_reject_table() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/catalog");
    let table: Value = serde_json::from_slice(include_bytes!(
        "fixtures/catalog/admission-expectations.json"
    ))
    .unwrap();
    for row in table.as_array().unwrap() {
        let name = row["file"].as_str().unwrap();
        let raw = std::fs::read(base.join(name)).unwrap();
        let result = CaseCatalog::load(&raw, CatalogLimits::default());
        let expected = row["expected"].as_str().unwrap();
        if expected == "accept" {
            assert!(result.is_ok(), "{name}: {result:?}")
        } else {
            assert_eq!(
                format!("{:?}", result.unwrap_err().kind()),
                expected,
                "{name}"
            )
        }
    }
}
#[test]
fn frozen_extension_owners_are_dependencies() {
    let mut v: Value = serde_json::from_slice(A).unwrap();
    v["profiles"][0]["definition_state"] = json!("FROZEN");
    v["profiles"][0]["open_owners"] = json!([]);
    v["extensions"] = json!([{"id":"extra-v1","profile":"revision-fixture-v1","requires_profiles":[],"requires_tasks":["TT01"],"required_cases":[]}]);
    v["profiles"].as_array_mut().unwrap().push(json!({"id":"whole-v1","definition_state":"FROZEN","requires_profiles":[],"requires_extensions":["extra-v1"],"required_cases":[],"open_owners":[]}));
    let plan = select(&load(&v).unwrap(), "whole-v1");
    assert!(plan.definition_complete());
    assert!(plan.open_owners().is_empty());
    v["profiles"][0]["definition_state"] = json!("DRAFT");
    v["profiles"][0]["open_owners"] = json!(["TT01"]);
    bad(&v, CatalogErrorKind::InvalidDefinition);
    v["profiles"][1]["definition_state"] = json!("DRAFT");
    v["profiles"][1]["open_owners"] = json!(["TT01"]);
    let plan = select(&load(&v).unwrap(), "whole-v1");
    assert!(!plan.definition_complete());
    assert_eq!(plan.open_owners(), ["TT01"]);
}
#[test]
fn every_population_and_work_limit_is_global() {
    let raw = A;
    let base: Value = serde_json::from_slice(raw).unwrap();
    macro_rules! limit {
        ($field:ident,$n:expr) => {{
            let mut l = CatalogLimits::default();
            l.$field = $n;
            assert!(
                CaseCatalog::load(raw, l.clone()).is_ok(),
                stringify!($field)
            );
            l.$field -= 1;
            if l.$field > 0 {
                assert_eq!(
                    CaseCatalog::load(raw, l).unwrap_err().kind(),
                    CatalogErrorKind::LimitExceeded,
                    stringify!($field)
                );
            }
        }};
    }
    limit!(max_cases, 1);
    limit!(max_profiles, 1);
    limit!(max_extensions, 1);
    limit!(max_obligations, 1);
    limit!(max_cells, 2);
    limit!(max_depth, 6);
    limit!(max_selected_cells, 1);
    // Exact eight reference/ownership edges: obligation owner, family ref, case
    // owner/ref/cell/family, profile required declaration and open owner = eight.
    let mut l = CatalogLimits::default();
    l.max_edges = 8;
    assert!(CaseCatalog::load(raw, l.clone()).is_ok());
    l.max_edges = 7;
    assert_eq!(
        CaseCatalog::load(raw, l).unwrap_err().kind(),
        CatalogErrorKind::LimitExceeded
    );
    let mut v = base.clone();
    v["profiles"]
        .as_array_mut()
        .unwrap()
        .push(draft("unselected-v1", json!([]), json!([])));
    let mut l = CatalogLimits::default();
    l.max_profiles = 1;
    assert_eq!(
        CaseCatalog::load(&serde_json::to_vec(&v).unwrap(), l)
            .unwrap_err()
            .kind(),
        CatalogErrorKind::LimitExceeded
    );
    let mut v = base;
    v["cases"][0]["required_cells"] = json!(["revision-before", "revision-after"]);
    let mut l = CatalogLimits::default();
    l.max_selected_cells = 1;
    assert_eq!(
        CaseCatalog::load(&serde_json::to_vec(&v).unwrap(), l)
            .unwrap_err()
            .kind(),
        CatalogErrorKind::LimitExceeded
    );
    let mut l = CatalogLimits::default();
    l.max_cases = 4097;
    assert_eq!(
        CaseCatalog::load(raw, l).unwrap_err().kind(),
        CatalogErrorKind::InvalidLimits
    );
}
#[test]
fn transport_attribution_and_all_duplicate_domains() {
    let mut v: Value = serde_json::from_slice(A).unwrap();
    let req = v["profiles"][0]["required_cases"].clone();
    v["profiles"] = json!([
        draft("left-v1", json!([]), req.clone()),
        draft("right-v1", json!([]), json!([])),
        draft("join-v1", json!(["left-v1", "right-v1"]), json!([]))
    ]);
    let original = select(&load(&v).unwrap(), "join-v1");
    v["profiles"][0]["required_cases"] = json!([]);
    v["profiles"][1]["required_cases"] = req;
    let moved = select(&load(&v).unwrap(), "join-v1");
    assert_eq!(original.profiles(), moved.profiles());
    assert_eq!(original.required()[0].required_by()[0].as_str(), "left-v1");
    assert_eq!(moved.required()[0].required_by()[0].as_str(), "right-v1");
    assert_eq!(
        original
            .validate_selection(original.profiles(), original.extensions(), moved.required())
            .unwrap_err()
            .kind(),
        PlanErrorKind::SelectionMismatch
    );
    let mut profiles = original.profiles().to_vec();
    profiles.push(profiles[0].clone());
    assert_eq!(
        original
            .validate_selection(&profiles, &[], original.required())
            .unwrap_err()
            .kind(),
        PlanErrorKind::SelectionMismatch
    );
    let c = CaseCatalog::load(INITIAL, CatalogLimits::default()).unwrap();
    let n = select(&c, "native-v1");
    let mut exts = n.extensions().to_vec();
    exts.push(exts[0].clone());
    assert_eq!(
        n.validate_selection(n.profiles(), &exts, n.required())
            .unwrap_err()
            .kind(),
        PlanErrorKind::SelectionMismatch
    );
}
#[test]
fn unselected_populations_and_string_exact_bounds() {
    let base: Value = serde_json::from_slice(A).unwrap();
    let mut l = CatalogLimits::default();
    l.max_string_bytes = 35;
    assert!(CaseCatalog::load(A, l.clone()).is_ok());
    l.max_string_bytes = 34;
    assert_eq!(
        CaseCatalog::load(A, l).unwrap_err().kind(),
        CatalogErrorKind::LimitExceeded
    );
    let mut v = base.clone();
    v["obligations"].as_array_mut().unwrap().push(
        json!({"kind":"overlap_row","id":"OV01","description":"unselected","owners":["TT01"]}),
    );
    let mut l = CatalogLimits::default();
    l.max_obligations = 1;
    assert_eq!(
        CaseCatalog::load(&serde_json::to_vec(&v).unwrap(), l)
            .unwrap_err()
            .kind(),
        CatalogErrorKind::LimitExceeded
    );
    let mut v = base.clone();
    v["extensions"] = json!([{"id":"one-v1","profile":"revision-fixture-v1","requires_profiles":[],"requires_tasks":[],"required_cases":[]}]);
    let mut l = CatalogLimits::default();
    l.max_extensions = 1;
    assert!(CaseCatalog::load(&serde_json::to_vec(&v).unwrap(), l.clone()).is_ok());
    let second = v["extensions"][0].clone();
    v["extensions"].as_array_mut().unwrap().push(second);
    v["extensions"][1]["id"] = json!("two-v1");
    assert_eq!(
        CaseCatalog::load(&serde_json::to_vec(&v).unwrap(), l)
            .unwrap_err()
            .kind(),
        CatalogErrorKind::LimitExceeded
    );
    let mut v = base.clone();
    for n in 1..128 {
        v["tasks"]
            .as_array_mut()
            .unwrap()
            .push(json!(format!("T{n}")));
    }
    assert!(load(&v).is_ok());
    v["tasks"].as_array_mut().unwrap().push(json!("T128"));
    bad(&v, CatalogErrorKind::LimitExceeded);
    let mut v = base;
    for n in 1..128 {
        let id = format!("H{n}");
        v["obligations"].as_array_mut().unwrap().push(json!({"kind":"regression_family","id":id,"description":"extra family","owners":["TT01"]}));
        v["families"].as_array_mut().unwrap().push(json!({"id":id,"short_contract":"extra family","obligations":[{"kind":"regression_family","id":id}]}));
    }
    // H4 is distinct from the existing H04.
    assert!(load(&v).is_ok());
    v["families"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"extra","short_contract":"extra family","obligations":[]}));
    bad(&v, CatalogErrorKind::LimitExceeded);
}
#[test]
fn registered_getters_preserve_independent_artifact_identity() {
    let c = CaseCatalog::load(
        include_bytes!("fixtures/catalog/registered.json"),
        CatalogLimits::default(),
    )
    .unwrap();
    let case = c
        .case(&CaseId::parse("H04.revision-fixture").unwrap(), 1)
        .unwrap();
    assert_eq!(
        case.implementation_status(),
        ImplementationStatus::RegisteredExecutable
    );
    let reg = case.registration().unwrap();
    let id: &str = reg.executable().id();
    let entrypoint: &str = reg.executable().entrypoint();
    assert_eq!(id, "artifact.executable");
    assert_eq!(entrypoint, "inspect.executable");
    assert_eq!(reg.executable().revision(), 1);
    assert_eq!(reg.fixture().path(), "artifacts/fixture.txt");
    assert_eq!(reg.oracle().path(), "artifacts/oracle.txt");
    assert_eq!(reg.bad_control().path(), "artifacts/control.txt");
    assert!(!reg.oracle_basis().is_empty());
    assert!(!reg.control_assertion().is_empty());
    assert_eq!(
        select(&c, "revision-fixture-v1").required()[0].implementation_status(),
        ImplementationStatus::RegisteredExecutable
    );
}
#[test]
fn exact_initial_inventory_is_planned_metadata() {
    let v: Value = serde_json::from_slice(INITIAL).unwrap();
    for (field, count) in [
        ("tasks", 86),
        ("obligations", 179),
        ("families", 33),
        ("cells", 4),
        ("cases", 4),
        ("profiles", 19),
        ("extensions", 1),
    ] {
        assert_eq!(v[field].as_array().unwrap().len(), count, "{field}")
    }
    assert!(v["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .all(|p| p["definition_state"] == "DRAFT"));
    assert!(v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["implementation_status"] == "UNIMPLEMENTED" && c["registration"].is_null()));
}

#[test]
fn complete_envelope_revision_evolution_preserves_canonical_registry() {
    let initial: Value = serde_json::from_slice(INITIAL).unwrap();
    let a: Value =
        serde_json::from_slice(include_bytes!("fixtures/catalog/full-revision-a.json")).unwrap();
    let b: Value =
        serde_json::from_slice(include_bytes!("fixtures/catalog/full-revision-b.json")).unwrap();
    let old = vec![(
        "H04.revision-fixture".into(),
        1,
        "revision-before".into(),
        EvidenceTier::T0,
        vec!["revision-fixture-v1".into()],
    )];
    let new = vec![
        (
            "H04.revision-fixture".into(),
            2,
            "revision-after".into(),
            EvidenceTier::T0,
            vec!["revision-fixture-v2".into()],
        ),
        (
            "H04.revision-fixture".into(),
            2,
            "revision-before".into(),
            EvidenceTier::T0,
            vec!["revision-fixture-v2".into()],
        ),
    ];
    let native = vec![
        (
            "H33.final-object-license".into(),
            1,
            "h33-final-object-license".into(),
            EvidenceTier::T2,
            vec!["compiler-object-v1".into()],
        ),
        (
            "H33.installed-notices".into(),
            1,
            "h33-installed-notices".into(),
            EvidenceTier::T5,
            vec!["mojo-elf-v1".into()],
        ),
        (
            "H33.license-admission".into(),
            1,
            "h33-license-admission".into(),
            EvidenceTier::T4,
            vec!["btf-shape-le-v1".into()],
        ),
        (
            "H33.source-closure".into(),
            1,
            "h33-source-closure".into(),
            EvidenceTier::T0,
            vec!["compiler-object-v1".into()],
        ),
    ];
    let id = CaseId::parse("H04.revision-fixture").unwrap();
    for (full, cases, profiles) in [(&a, 5, 20), (&b, 6, 21)] {
        for (field, count) in [
            ("tasks", 86),
            ("obligations", 179),
            ("families", 33),
            ("extensions", 1),
            ("cells", 6),
            ("cases", cases),
            ("profiles", profiles),
        ] {
            assert_eq!(full[field].as_array().unwrap().len(), count, "{field}");
        }
        for field in ["tasks", "obligations", "families", "extensions"] {
            assert_eq!(full[field], initial[field], "preserved {field}");
        }
        for field in ["cells", "cases", "profiles"] {
            for record in initial[field].as_array().unwrap() {
                assert!(
                    full[field].as_array().unwrap().contains(record),
                    "preserved {field}: {record}"
                );
            }
        }
        let catalog = load(full).unwrap();
        assert_eq!(
            catalog.case(&id, 1).unwrap().required_cells(),
            ["revision-before"]
        );
        assert!(catalog.case(&id, 0).is_none());
        assert!(catalog.case(&id, 3).is_none());
        assert_eq!(projection(&select(&catalog, "revision-fixture-v1")), old);
        let plan = select(&catalog, "native-v1");
        assert_eq!(
            plan.profiles()
                .iter()
                .map(ProfileId::as_str)
                .collect::<Vec<_>>(),
            [
                "bpf-host-v1",
                "btf-shape-le-v1",
                "capture-core-v1",
                "compiler-object-v1",
                "mojo-elf-v1",
                "native-v1"
            ]
        );
        assert_eq!(
            plan.extensions()
                .iter()
                .map(ProfileId::as_str)
                .collect::<Vec<_>>(),
            ["btf-runtime-linkage-v1"]
        );
        assert_eq!(projection(&plan), native);
        assert!(!plan.definition_complete());
        assert!(plan
            .required()
            .iter()
            .all(|r| r.implementation_status() == ImplementationStatus::Unimplemented));
        let bare = select(&catalog, "btf-shape-le-v1");
        assert!(bare.required().is_empty());
        assert!(bare.extensions().is_empty());
        assert_eq!(full["extensions"][0]["required_cases"], json!([]));
    }
    let catalog = load(&b).unwrap();
    assert_eq!(
        catalog.case(&id, 2).unwrap().required_cells(),
        ["revision-before", "revision-after"]
    );
    assert_eq!(projection(&select(&catalog, "revision-fixture-v2")), new);
    let mut reversed = b.clone();
    reversed["cases"].as_array_mut().unwrap().reverse();
    let reversed = load(&reversed).unwrap();
    assert_eq!(
        reversed.case(&id, 1).unwrap().required_cells(),
        ["revision-before"]
    );
    assert_eq!(
        reversed.case(&id, 2).unwrap().required_cells(),
        ["revision-before", "revision-after"]
    );
    assert_eq!(projection(&select(&reversed, "revision-fixture-v1")), old);
    assert_eq!(projection(&select(&reversed, "revision-fixture-v2")), new);

    // The canonical unrelated root remains in the same admitted population.
    let mut mixed = b;
    let req = json!([{"case_id":"H04.revision-fixture","case_version":1,"when_extensions":[]}]);
    mixed["profiles"].as_array_mut().unwrap().extend([
        draft("revision-left-v1", json!([]), req.clone()),
        draft("revision-right-v1", json!([]), req),
        draft(
            "revision-join-v1",
            json!(["revision-left-v1", "revision-right-v1"]),
            json!([]),
        ),
    ]);
    let valid = load(&mixed).unwrap();
    assert_eq!(
        projection(&select(&valid, "revision-join-v1")),
        vec![(
            "H04.revision-fixture".into(),
            1,
            "revision-before".into(),
            EvidenceTier::T0,
            vec!["revision-left-v1".into(), "revision-right-v1".into()]
        )]
    );
    assert_eq!(
        select(&valid, "compiler-object-v1")
            .required()
            .iter()
            .map(|r| (r.case_id().as_str(), r.tier()))
            .collect::<Vec<_>>(),
        [
            ("H33.final-object-license", EvidenceTier::T2),
            ("H33.source-closure", EvidenceTier::T0)
        ]
    );
    let right = mixed["profiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p["id"] == "revision-right-v1")
        .unwrap();
    right["required_cases"][0]["case_version"] = json!(2);
    assert!(mixed["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["id"] == "compiler-object-v1"));
    bad(&mixed, CatalogErrorKind::VersionConflict);
}
