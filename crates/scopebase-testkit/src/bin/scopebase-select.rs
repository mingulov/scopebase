// SPDX-License-Identifier: Apache-2.0
//! TT08 tail: `scopebase-select` drives the reviewed causal selector core
//! from CI and local runs.
//!
//! Subcommands: `manifest` (changed paths -> [`ChangeManifest`] JSON),
//! `select` ([`select_affected`] + oracle agreement -> plan JSON), `resolve`
//! (plan cells -> runnable gates or explicit unavailable entries),
//! `account` ([`RunAccounting`] over executed results), `gate`
//! ([`qualification_gate`] over a recorded attempt history).
//!
//! Pure file-to-file JSON transformation; no network, no secrets, no
//! privileged operations. Exit codes: 0 success (or resolved/attested), 1
//! usage/IO/parse/selection error, 2 unresolved retry gate or refused full
//! attestation.

use scopebase_testkit::cli;
use scopebase_testkit::select::{
    check_agreement, expected_selection, qualification_gate, select_affected, AccountingScope,
    AccountingStatus, AttemptOutcome, AttemptRecord, CellKey, Change, ChangeManifest,
    EnvironmentAttribute, EvidenceRef, GateVerdict, OutOfScopeNode, RegistrationRole,
    ResolutionRecord, RunAccounting, SelectionLimits, SelectionPlan,
};
use scopebase_testkit::{CaseCatalog, CaseId, CatalogLimits, ProfileId, ProfilePlan};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

fn usage() -> ! {
    // R04: usage goes through the fallible writer; a dead stderr
    // still exits 1 without a second panic.
    cli::err_line(
        "usage:\n\
         \tscopebase-select manifest --impact <impact.json> --changed <paths.txt> --out <manifest.json>\n\
         \tscopebase-select select --catalog <catalog.json> --manifest <manifest.json> --requested <csv> --out <plan.json>\n\
         \tscopebase-select resolve --catalog <catalog.json> --manifest <manifest.json> --requested <csv> --plan <plan.json> --impact <impact.json> --out <gates.json>\n\
         \tscopebase-select account --catalog <catalog.json> --manifest <manifest.json> --requested <csv> --executed <executed.json> --out <accounting.json> [--attest-full]\n\
         \tscopebase-select gate --attempts <attempts.json> --out <verdict.json>"
    );
    std::process::exit(1);
}

fn fail(message: &str) -> ! {
    // R04: every failure in this binary funnels through here; the
    // fallible write keeps a dead stderr at exit 1 with no panic.
    cli::err_line(&format!("scopebase-select: {message}"));
    std::process::exit(1);
}

/// R04: progress summaries are fallible; a dead stdout fails the
/// command (exit 1) instead of panicking in `println!`.
fn progress(line: String) {
    if !cli::put_line(&line) {
        fail("cannot write progress summary to stdout");
    }
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn opt<'a>(args: &'a [String], name: &str) -> &'a str {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == name {
            match iter.next() {
                Some(value) => return value,
                None => fail(&format!("{name} needs a value")),
            }
        }
    }
    fail(&format!("missing required {name}"));
}

fn read_json(path: &str) -> Value {
    let bytes = std::fs::read(Path::new(path))
        .unwrap_or_else(|e| fail(&format!("cannot read {path}: {e}")));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| fail(&format!("{path} is not valid JSON: {e}")))
}

fn write_json(path: &str, value: &Value) {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    std::fs::write(Path::new(path), bytes)
        .unwrap_or_else(|e| fail(&format!("cannot write {path}: {e}")));
}

fn load_catalog(path: &str) -> CaseCatalog {
    let bytes = std::fs::read(Path::new(path))
        .unwrap_or_else(|e| fail(&format!("cannot read {path}: {e}")));
    CaseCatalog::load(&bytes, CatalogLimits::default())
        .unwrap_or_else(|e| fail(&format!("catalog {path} rejected: {e}")))
}

fn get<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| fail(&format!("missing required field {key:?}")))
}

fn as_str<'a>(value: &'a Value, what: &str) -> &'a str {
    value
        .as_str()
        .unwrap_or_else(|| fail(&format!("{what} must be a string")))
}

fn as_u32(value: &Value, what: &str) -> u32 {
    value
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or_else(|| fail(&format!("{what} must be a u32 integer")))
}

fn parse_profile(value: &Value) -> ProfileId {
    ProfileId::parse(as_str(value, "profile id"))
        .unwrap_or_else(|e| fail(&format!("invalid profile id: {e}")))
}

fn parse_boundary(value: &Value) -> Option<ProfileId> {
    match value {
        Value::Null => None,
        Value::String(_) => Some(parse_profile(value)),
        _ => fail("boundary must be a profile id or null"),
    }
}

fn parse_change(value: &Value) -> Change {
    let kind = as_str(get(value, "type"), "change type");
    match kind {
        "cell" => Change::cell(as_str(get(value, "cell_id"), "cell_id")),
        "case" => {
            let id = CaseId::parse(as_str(get(value, "case_id"), "case_id"))
                .unwrap_or_else(|e| fail(&format!("invalid case id: {e}")));
            Change::case(id, as_u32(get(value, "case_version"), "case_version"))
        }
        "profile" => Change::profile(parse_profile(get(value, "profile"))),
        "extension" => Change::extension(parse_profile(get(value, "extension"))),
        "obligation" => Change::obligation(
            as_str(get(value, "kind"), "kind"),
            as_str(get(value, "id"), "id"),
        ),
        "registration_role" => {
            let id = CaseId::parse(as_str(get(value, "case_id"), "case_id"))
                .unwrap_or_else(|e| fail(&format!("invalid case id: {e}")));
            let role = match as_str(get(value, "role"), "role") {
                "executable" => RegistrationRole::Executable,
                "fixture" => RegistrationRole::Fixture,
                "oracle" => RegistrationRole::Oracle,
                "bad_control" => RegistrationRole::BadControl,
                other => fail(&format!("unknown registration role {other:?}")),
            };
            Change::registration_role(id, as_u32(get(value, "case_version"), "case_version"), role)
        }
        "unknown" => Change::unknown(
            parse_boundary(value.get("boundary").unwrap_or(&Value::Null)),
            as_str(get(value, "reason"), "reason"),
        ),
        "environment" => {
            let attribute = match as_str(get(value, "attribute"), "attribute") {
                "source" => EnvironmentAttribute::Source,
                "dependency" => EnvironmentAttribute::Dependency,
                "features" => EnvironmentAttribute::Features,
                "compiler" => EnvironmentAttribute::Compiler,
                other => fail(&format!("unknown environment attribute {other:?}")),
            };
            Change::environment(
                attribute,
                parse_boundary(value.get("boundary").unwrap_or(&Value::Null)),
            )
        }
        other => fail(&format!("unknown change type {other:?}")),
    }
}

fn parse_manifest_file(path: &str) -> ChangeManifest {
    let value = read_json(path);
    let changes = get(&value, "changes")
        .as_array()
        .unwrap_or_else(|| fail("manifest changes must be an array"));
    ChangeManifest::new(changes.iter().map(parse_change).collect())
}

fn parse_requested(csv: &str) -> Vec<ProfileId> {
    if csv.trim().is_empty() {
        fail("requested profile list must be nonempty");
    }
    csv.split(',')
        .map(|raw| {
            ProfileId::parse(raw.trim())
                .unwrap_or_else(|e| fail(&format!("invalid requested profile: {e}")))
        })
        .collect()
}

fn cell_json(case_id: &str, case_version: u32, cell_id: &str) -> Value {
    let mut object = Map::new();
    object.insert("case_id".to_owned(), Value::String(case_id.to_owned()));
    object.insert("case_version".to_owned(), Value::from(case_version));
    object.insert("cell_id".to_owned(), Value::String(cell_id.to_owned()));
    Value::Object(object)
}

fn parse_cell_key(value: &Value) -> CellKey {
    CellKey::new(
        CaseId::parse(as_str(get(value, "case_id"), "case_id"))
            .unwrap_or_else(|e| fail(&format!("invalid case id: {e}"))),
        as_u32(get(value, "case_version"), "case_version"),
        as_str(get(value, "cell_id"), "cell_id"),
    )
    .unwrap_or_else(|e| fail(&format!("invalid cell key: {e}")))
}

/// Run selection and enforce selector/oracle agreement: a disagreement is a
/// tool defect, never a shippable plan.
fn agreed_plan(
    catalog: &CaseCatalog,
    manifest: &ChangeManifest,
    requested: &[ProfileId],
) -> SelectionPlan {
    let limits = SelectionLimits::default();
    let plan = select_affected(catalog, manifest, requested, &limits)
        .unwrap_or_else(|e| fail(&format!("select_affected rejected: {e}")));
    let expected = expected_selection(catalog, manifest, requested, &limits)
        .unwrap_or_else(|e| fail(&format!("oracle recomputation rejected: {e}")));
    if let Err(disagreement) = check_agreement(&plan, &expected) {
        fail(&format!(
            "selector/oracle disagreement: {} missing, {} extra",
            disagreement.missing().len(),
            disagreement.extra().len()
        ));
    }
    plan
}

fn cmd_manifest(args: &[String]) {
    let impact = read_json(opt(args, "--impact"));
    let changed_path = opt(args, "--changed");
    let out = opt(args, "--out");
    let rules = get(&impact, "path_rules")
        .as_array()
        .unwrap_or_else(|| fail("impact path_rules must be an array"));
    let default = get(&impact, "default_change").clone();
    // Validate the default eagerly so unmatched paths cannot slip through.
    parse_change(&default);
    let text = std::fs::read_to_string(Path::new(changed_path))
        .unwrap_or_else(|e| fail(&format!("cannot read {changed_path}: {e}")));
    // Rules and defaults are already JSON change objects: validate each
    // contributed change through the parser and echo its JSON rendering.
    let mut rendered = Vec::new();
    for line in text.lines() {
        let path = line.trim();
        if path.is_empty() {
            continue;
        }
        let mut decided: Option<Option<Value>> = None;
        for rule in rules {
            let exact = rule.get("path").and_then(Value::as_str);
            let prefix = rule.get("prefix").and_then(Value::as_str);
            if exact.is_none() && prefix.is_none() {
                fail("impact rule needs \"path\" or \"prefix\"");
            }
            let hit =
                exact.is_some_and(|p| p == path) || prefix.is_some_and(|p| path.starts_with(p));
            if !hit {
                continue;
            }
            if let Some(change) = rule.get("change") {
                decided = Some(Some(change.clone()));
            } else if rule.get("none").and_then(Value::as_str).is_some() {
                decided = Some(None);
            } else {
                fail("impact rule needs \"change\" or a \"none\" reason");
            }
            break;
        }
        match decided {
            Some(Some(change)) => {
                parse_change(&change);
                rendered.push(change);
            }
            Some(None) => {}
            None => rendered.push(default.clone()),
        }
    }
    write_json(
        out,
        &Value::Object(Map::from_iter([(
            "changes".to_owned(),
            Value::Array(rendered.clone()),
        )])),
    );
    progress(format!("manifest changes={}", rendered.len()));
}

fn cmd_select(args: &[String]) {
    let catalog = load_catalog(opt(args, "--catalog"));
    let manifest = parse_manifest_file(opt(args, "--manifest"));
    let requested = parse_requested(opt(args, "--requested"));
    let plan = agreed_plan(&catalog, &manifest, &requested);
    let selected: Vec<Value> = plan
        .selected()
        .iter()
        .map(|cell| {
            let mut object = Map::new();
            object.insert(
                "case_id".to_owned(),
                Value::String(cell.key().case_id().as_str().to_owned()),
            );
            object.insert(
                "case_version".to_owned(),
                Value::from(cell.key().case_version()),
            );
            object.insert(
                "cell_id".to_owned(),
                Value::String(cell.key().cell_id().to_owned()),
            );
            object.insert(
                "change_index".to_owned(),
                Value::from(cell.explanation().change_index() as u64),
            );
            Value::Object(object)
        })
        .collect();
    let declared: Vec<Value> = plan
        .declared()
        .iter()
        .map(|key| cell_json(key.case_id().as_str(), key.case_version(), key.cell_id()))
        .collect();
    let unresolved: Vec<Value> = plan
        .unresolved()
        .iter()
        .map(|u| {
            let mut object = Map::new();
            object.insert(
                "change_index".to_owned(),
                Value::from(u.change_index() as u64),
            );
            object.insert(
                "boundary".to_owned(),
                u.boundary()
                    .map_or(Value::Null, |b| Value::String(b.as_str().to_owned())),
            );
            object.insert("reason".to_owned(), Value::String(u.reason().to_owned()));
            Value::Object(object)
        })
        .collect();
    let excluded: Vec<Value> = plan
        .excluded_out_of_scope()
        .iter()
        .map(|node| {
            let mut object = Map::new();
            match node {
                OutOfScopeNode::Profile(p) => {
                    object.insert("kind".to_owned(), Value::String("profile".to_owned()));
                    object.insert("id".to_owned(), Value::String(p.as_str().to_owned()));
                }
                OutOfScopeNode::Extension(e) => {
                    object.insert("kind".to_owned(), Value::String("extension".to_owned()));
                    object.insert("id".to_owned(), Value::String(e.as_str().to_owned()));
                }
                OutOfScopeNode::Case(id, version) => {
                    object.insert("kind".to_owned(), Value::String("case".to_owned()));
                    object.insert("id".to_owned(), Value::String(id.as_str().to_owned()));
                    object.insert("version".to_owned(), Value::from(*version));
                }
            }
            Value::Object(object)
        })
        .collect();
    let mut object = Map::new();
    object.insert(
        "requested".to_owned(),
        Value::Array(
            plan.requested()
                .iter()
                .map(|p| Value::String(p.as_str().to_owned()))
                .collect(),
        ),
    );
    object.insert("selected".to_owned(), Value::Array(selected));
    object.insert("declared".to_owned(), Value::Array(declared));
    object.insert("unresolved".to_owned(), Value::Array(unresolved));
    object.insert("excluded_out_of_scope".to_owned(), Value::Array(excluded));
    object.insert("is_full".to_owned(), Value::Bool(plan.is_full_selection()));
    write_json(opt(args, "--out"), &Value::Object(object));
    progress(format!(
        "select_affected agreement: ok selected={} declared={} full={}",
        plan.selected().len(),
        plan.declared().len(),
        plan.is_full_selection()
    ));
}

fn cmd_resolve(args: &[String]) {
    let catalog = load_catalog(opt(args, "--catalog"));
    let manifest_value = read_json(opt(args, "--manifest"));
    let manifest_changes = get(&manifest_value, "changes")
        .as_array()
        .unwrap_or_else(|| fail("manifest changes must be an array"));
    let manifest = ChangeManifest::new(manifest_changes.iter().map(parse_change).collect());
    let requested = parse_requested(opt(args, "--requested"));
    let plan = agreed_plan(&catalog, &manifest, &requested);
    // Bind resolution to the recorded plan: a stale plan file must not steer
    // gate execution.
    let recorded = read_json(opt(args, "--plan"));
    let recorded_selected: BTreeSet<(String, u32, String)> = get(&recorded, "selected")
        .as_array()
        .unwrap_or_else(|| fail("plan selected must be an array"))
        .iter()
        .map(|c| {
            (
                as_str(get(c, "case_id"), "case_id").to_owned(),
                as_u32(get(c, "case_version"), "case_version"),
                as_str(get(c, "cell_id"), "cell_id").to_owned(),
            )
        })
        .collect();
    let actual_selected: BTreeSet<(String, u32, String)> = plan
        .selected()
        .iter()
        .map(|c| {
            (
                c.key().case_id().as_str().to_owned(),
                c.key().case_version(),
                c.key().cell_id().to_owned(),
            )
        })
        .collect();
    if recorded_selected != actual_selected {
        fail("recorded plan does not match recomputed selection; re-run select");
    }
    let impact = read_json(opt(args, "--impact"));
    let bindings = get(&impact, "cell_bindings")
        .as_object()
        .unwrap_or_else(|| fail("impact cell_bindings must be an object"));
    let mut runnable = Vec::new();
    let mut unavailable = Vec::new();
    for cell in plan.selected() {
        let entry = cell_json(
            cell.key().case_id().as_str(),
            cell.key().case_version(),
            cell.key().cell_id(),
        );
        match bindings.get(cell.key().cell_id()) {
            Some(binding) if binding.get("argv").is_some() => {
                let mut object = entry.as_object().unwrap().clone();
                object.insert(
                    "gate_id".to_owned(),
                    binding
                        .get("gate_id")
                        .cloned()
                        .unwrap_or_else(|| Value::String(cell.key().cell_id().to_owned())),
                );
                object.insert("argv".to_owned(), get(binding, "argv").clone());
                runnable.push(Value::Object(object));
            }
            Some(binding) if binding.get("unavailable").is_some() => {
                let mut object = entry.as_object().unwrap().clone();
                object.insert("reason".to_owned(), get(binding, "unavailable").clone());
                unavailable.push(Value::Object(object));
            }
            _ => {
                let mut object = entry.as_object().unwrap().clone();
                object.insert(
                    "reason".to_owned(),
                    Value::String(format!(
                        "no executable binding for cell {}",
                        cell.key().cell_id()
                    )),
                );
                unavailable.push(Value::Object(object));
            }
        }
    }
    // Affected profile gates: requested profiles whose required checks meet
    // the selection, profiles named directly by a change, or every requested
    // profile when impact is unresolved (broadened). A profile affected only
    // through inactive conditional entries runs no gate; it stays visible in
    // the recorded plan.
    let selected_cells: BTreeSet<(String, u32, String)> = actual_selected;
    let named: BTreeSet<String> = manifest_changes
        .iter()
        .filter_map(|c| match c.get("type").and_then(Value::as_str) {
            Some("profile") => c.get("profile").and_then(Value::as_str).map(str::to_owned),
            Some("extension") => c
                .get("extension")
                .and_then(Value::as_str)
                .map(str::to_owned),
            _ => None,
        })
        .collect();
    let gates = get(&impact, "profile_gates")
        .as_object()
        .unwrap_or_else(|| fail("impact profile_gates must be an object"));
    let mut profile_gates = Vec::new();
    let mut unbound_profiles = Vec::new();
    for root in plan.requested() {
        let profile_plan = ProfilePlan::select(&catalog, root)
            .unwrap_or_else(|e| fail(&format!("profile plan rejected: {e}")));
        let meets_selection = profile_plan.required().iter().any(|cell| {
            selected_cells.contains(&(
                cell.case_id().as_str().to_owned(),
                cell.case_version(),
                cell.cell_id().to_owned(),
            ))
        });
        let in_closure = |id: &str| {
            profile_plan.profiles().iter().any(|p| p.as_str() == id)
                || profile_plan.extensions().iter().any(|e| e.as_str() == id)
        };
        let directly_named = named.iter().any(|n| in_closure(n));
        if !meets_selection && !directly_named && plan.unresolved().is_empty() {
            continue;
        }
        match gates.get(root.as_str()) {
            Some(gate) => {
                let mut object = Map::new();
                object.insert(
                    "profile".to_owned(),
                    Value::String(root.as_str().to_owned()),
                );
                // Impact authors write `id`; `gate_id` stays accepted so both
                // spellings steer the emitted gate, never the profile name.
                object.insert(
                    "gate_id".to_owned(),
                    gate.get("gate_id")
                        .or(gate.get("id"))
                        .cloned()
                        .unwrap_or_else(|| Value::String(root.as_str().to_owned())),
                );
                object.insert("argv".to_owned(), get(gate, "argv").clone());
                profile_gates.push(Value::Object(object));
            }
            None => {
                let mut object = Map::new();
                object.insert(
                    "profile".to_owned(),
                    Value::String(root.as_str().to_owned()),
                );
                object.insert(
                    "reason".to_owned(),
                    Value::String(format!(
                        "affected profile {root} has no executable gate binding",
                        root = root.as_str()
                    )),
                );
                unbound_profiles.push(Value::Object(object));
            }
        }
    }
    let mut object = Map::new();
    object.insert("runnable".to_owned(), Value::Array(runnable));
    object.insert("unavailable".to_owned(), Value::Array(unavailable));
    object.insert("profile_gates".to_owned(), Value::Array(profile_gates));
    object.insert(
        "unbound_profiles".to_owned(),
        Value::Array(unbound_profiles),
    );
    // Fast gates pass through with a normalized `gate_id` derived from the
    // same `gate_id`-or-`id` spelling the profile gates consume, so every
    // emitted gate carries one uniform key and the runner never branches on
    // which section an entry came from.
    let fast_gates: Vec<Value> = get(&impact, "fast_gates")
        .as_array()
        .unwrap_or_else(|| fail("impact fast_gates must be an array"))
        .iter()
        .map(|entry| {
            let mut object = entry
                .as_object()
                .unwrap_or_else(|| fail("fast gate entries must be objects"))
                .clone();
            if object.get("gate_id").is_none() {
                let id = object
                    .get("id")
                    .cloned()
                    .unwrap_or_else(|| fail("fast gate entries need an id"));
                object.insert("gate_id".to_owned(), id);
            }
            Value::Object(object)
        })
        .collect();
    object.insert("fast_gates".to_owned(), Value::Array(fast_gates));
    let out_path = opt(args, "--out").to_owned();
    write_json(&out_path, &Value::Object(object));
    let written = read_json(&out_path);
    progress(format!(
        "resolve: {} runnable cells, {} unavailable, {} profile gates, {} unbound profiles",
        written["runnable"].as_array().unwrap().len(),
        written["unavailable"].as_array().unwrap().len(),
        written["profile_gates"].as_array().unwrap().len(),
        written["unbound_profiles"].as_array().unwrap().len(),
    ));
}

fn cmd_account(args: &[String]) {
    let catalog = load_catalog(opt(args, "--catalog"));
    let manifest = parse_manifest_file(opt(args, "--manifest"));
    let requested = parse_requested(opt(args, "--requested"));
    let plan = agreed_plan(&catalog, &manifest, &requested);
    let executed_value = read_json(opt(args, "--executed"));
    let executed: BTreeSet<CellKey> = get(&executed_value, "executed")
        .as_array()
        .unwrap_or_else(|| fail("executed must be an array"))
        .iter()
        .map(parse_cell_key)
        .collect();
    let inherited: BTreeMap<CellKey, EvidenceRef> = get(&executed_value, "inherited")
        .as_array()
        .unwrap_or_else(|| fail("inherited must be an array"))
        .iter()
        .map(|entry| {
            let key = parse_cell_key(entry);
            let reference = EvidenceRef::new(as_str(get(entry, "evidence"), "evidence"))
                .unwrap_or_else(|e| fail(&format!("invalid evidence ref: {e}")));
            (key, reference)
        })
        .collect();
    let accounting = RunAccounting::account(&plan, &executed, &inherited);
    let keys = |cells: &[CellKey]| {
        Value::Array(
            cells
                .iter()
                .map(|k| cell_json(k.case_id().as_str(), k.case_version(), k.cell_id()))
                .collect(),
        )
    };
    let mut object = Map::new();
    object.insert("declared".to_owned(), keys(accounting.declared()));
    object.insert("selected".to_owned(), keys(accounting.selected()));
    object.insert(
        "executed_selected".to_owned(),
        keys(accounting.executed_selected()),
    );
    object.insert(
        "missing_selected".to_owned(),
        keys(accounting.missing_selected()),
    );
    object.insert(
        "unchanged_with_evidence".to_owned(),
        Value::Array(
            accounting
                .unchanged_with_evidence()
                .iter()
                .map(|(key, reference)| {
                    let mut entry =
                        cell_json(key.case_id().as_str(), key.case_version(), key.cell_id());
                    entry.as_object_mut().unwrap().insert(
                        "evidence".to_owned(),
                        Value::String(reference.label().to_owned()),
                    );
                    entry
                })
                .collect(),
        ),
    );
    object.insert(
        "unchanged_missing_evidence".to_owned(),
        keys(accounting.unchanged_missing_evidence()),
    );
    object.insert(
        "unexpected_executed".to_owned(),
        keys(accounting.unexpected_executed()),
    );
    object.insert(
        "has_unresolved".to_owned(),
        Value::Bool(accounting.has_unresolved()),
    );
    object.insert(
        "status".to_owned(),
        Value::String(
            match accounting.status() {
                AccountingStatus::Complete => "complete",
                AccountingStatus::Incomplete => "incomplete",
            }
            .to_owned(),
        ),
    );
    object.insert(
        "scope".to_owned(),
        Value::String(
            match accounting.scope() {
                AccountingScope::Full => "full",
                AccountingScope::Narrowed => "narrowed",
            }
            .to_owned(),
        ),
    );
    object.insert(
        "full_matrix_complete".to_owned(),
        Value::Bool(accounting.full_matrix_complete()),
    );
    write_json(opt(args, "--out"), &Value::Object(object));
    progress(format!(
        "accounting status={} scope={} full_matrix_complete={} missing_selected={}",
        match accounting.status() {
            AccountingStatus::Complete => "complete",
            AccountingStatus::Incomplete => "incomplete",
        },
        match accounting.scope() {
            AccountingScope::Full => "full",
            AccountingScope::Narrowed => "narrowed",
        },
        accounting.full_matrix_complete(),
        accounting.missing_selected().len()
    ));
    if flag(args, "--attest-full") && accounting.attest_complete().is_err() {
        cli::err_line("scopebase-select: full attestation refused: incomplete denominator");
        std::process::exit(2);
    }
}

fn cmd_gate(args: &[String]) {
    let value = read_json(opt(args, "--attempts"));
    let attempts: Vec<AttemptRecord> = get(&value, "attempts")
        .as_array()
        .unwrap_or_else(|| fail("attempts must be an array"))
        .iter()
        .map(|entry| {
            let outcome = match as_str(get(entry, "outcome"), "outcome") {
                "pass" => AttemptOutcome::Pass,
                "semantic_failure" => AttemptOutcome::SemanticFailure,
                "infrastructure_failure" => AttemptOutcome::InfrastructureFailure,
                other => fail(&format!("unknown outcome {other:?}")),
            };
            AttemptRecord::new(
                as_u32(get(entry, "attempt"), "attempt"),
                outcome,
                as_str(get(entry, "detail"), "detail"),
            )
            .unwrap_or_else(|e| fail(&format!("invalid attempt: {e}")))
        })
        .collect();
    let resolutions: Vec<ResolutionRecord> = get(&value, "resolutions")
        .as_array()
        .unwrap_or_else(|| fail("resolutions must be an array"))
        .iter()
        .map(|entry| {
            ResolutionRecord::new(
                as_u32(get(entry, "failed_attempt"), "failed_attempt"),
                as_str(get(entry, "cause"), "cause"),
                as_str(get(entry, "fix"), "fix"),
                as_str(get(entry, "new_candidate"), "new_candidate"),
            )
            .unwrap_or_else(|e| fail(&format!("invalid resolution: {e}")))
        })
        .collect();
    let verdict = qualification_gate(&attempts, &resolutions)
        .unwrap_or_else(|e| fail(&format!("retry gate rejected: {e}")));
    let mut object = Map::new();
    match &verdict {
        GateVerdict::Resolved { attempts } => {
            object.insert("verdict".to_owned(), Value::String("resolved".to_owned()));
            object.insert("attempts".to_owned(), Value::from(*attempts as u64));
            progress(format!("gate verdict=resolved attempts={attempts}"));
        }
        GateVerdict::Unresolved { failed_attempts } => {
            object.insert("verdict".to_owned(), Value::String("unresolved".to_owned()));
            object.insert(
                "failed_attempts".to_owned(),
                Value::Array(failed_attempts.iter().map(|a| Value::from(*a)).collect()),
            );
            progress(format!(
                "gate verdict=unresolved failed_attempts={failed_attempts:?}"
            ));
        }
    }
    write_json(opt(args, "--out"), &Value::Object(object));
    if matches!(verdict, GateVerdict::Unresolved { .. }) {
        std::process::exit(2);
    }
}

fn main() {
    // R03: non-UTF-8 argv refuses with usage, never panics in args().
    let args = match cli::argv_strings() {
        Some(args) => args,
        None => {
            cli::err_line("argv is not valid Unicode");
            usage();
        }
    };
    if args.len() < 2 {
        usage();
    }
    let rest = args[2..].to_vec();
    match args[1].as_str() {
        "manifest" => cmd_manifest(&rest),
        "select" => cmd_select(&rest),
        "resolve" => cmd_resolve(&rest),
        "account" => cmd_account(&rest),
        "gate" => cmd_gate(&rest),
        _ => usage(),
    }
}
