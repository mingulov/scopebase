// SPDX-License-Identifier: Apache-2.0
//! CP11 consumer contract: MemVeil-shaped reference consumer.
//!
//! Exercises independent fact claims, object generations, sweep order,
//! claim-ledger views, feed presence and correction holders through the
//! real testkit `ConformanceAdapter` seam. Expected bytes are hand-authored
//! here, never derived from capture output. NEW (CP11): no donor lines copied.
use capture_memveil_reference::adapter::MemveilReferenceAdapter;
use scopebase_testkit::{
    CaseError, CaseErrorCategory, CaseId, CaseInvocation, CaseInvocationValues, CaseKey,
    CaseKeyValues, ConformanceAdapter, EffectBatch, FixtureAccess, FixtureInput, InvocationKey,
    InvocationKeyValues, Label, Observation, OperationScript, RunId, RunLimits, SchemaBinding,
    SchemaBindingValues,
};

fn script_json(op: &str) -> Vec<u8> {
    format!(
        "{{\"schema_version\":1,\"kind\":\"steps-v1\",\"schema_id\":\"memveil-script\",\
         \"steps\":[{{\"step_id\":\"only-step\",\"operation\":\"{op}\",\
         \"inputs\":[\"script\"],\"parameters\":[]}}]}}"
    )
    .into_bytes()
}

fn invocation(limits: &RunLimits, op: &str) -> CaseInvocation {
    invocation_full(
        limits,
        "memveil-reference-v1",
        "memveil-fixture-v1",
        &script_json(op),
    )
}

fn invocation_full(
    limits: &RunLimits,
    obs_schema: &str,
    fix_schema: &str,
    script_json: &[u8],
) -> CaseInvocation {
    let script = OperationScript::load(script_json, limits).expect("test script loads");
    let key = InvocationKey::new(
        InvocationKeyValues {
            run_id: RunId::parse("abcdef0123456789abcdef0123456789").expect("run id"),
            case_key: CaseKey::new(
                CaseKeyValues {
                    case_id: CaseId::parse("CP11.memveil-contract").expect("case id"),
                    case_version: 1,
                    cell_id: "contract".to_string(),
                },
                limits,
            )
            .expect("case key"),
            attempt: 1,
            operation_id: 1,
        },
        limits,
    )
    .expect("invocation key");
    CaseInvocation::new(
        CaseInvocationValues {
            key,
            observation_schema: SchemaBinding::new(
                SchemaBindingValues {
                    id: Label::parse(obs_schema).expect("schema"),
                    revision: 1,
                },
                limits,
            )
            .expect("observation schema"),
            fixture_schema: SchemaBinding::new(
                SchemaBindingValues {
                    id: Label::parse(fix_schema).expect("schema"),
                    revision: 1,
                },
                limits,
            )
            .expect("fixture schema"),
            script,
            limits: limits.clone(),
        },
        limits,
    )
    .expect("invocation")
}

fn access<'a>(limits: &'a RunLimits, script: &'a [u8]) -> FixtureAccess<'a> {
    let input = FixtureInput::new(Label::parse("script").expect("slot"), script);
    FixtureAccess::new(
        std::slice::from_ref(&input),
        &[],
        EffectBatch::empty(limits),
        limits,
    )
    .expect("fixture")
}

fn run(op: &str, script: &[u8]) -> Result<Observation, CaseError> {
    let limits = RunLimits::default();
    let inv = invocation(&limits, op);
    run_with(&limits, &inv, script)
}

fn run_with(
    limits: &RunLimits,
    inv: &CaseInvocation,
    script: &[u8],
) -> Result<Observation, CaseError> {
    let fix = access(limits, script);
    MemveilReferenceAdapter::new()
        .expect("adapter builds")
        .execute(inv, &fix)
}

fn lowered(mut apply: impl FnMut(&mut scopebase_testkit::RunLimitValues)) -> RunLimits {
    let base = RunLimits::default();
    let mut values = base.values();
    apply(&mut values);
    base.lowered(values).expect("lowered limits admit")
}

fn text(obs: &Observation) -> &str {
    std::str::from_utf8(obs.bytes()).expect("ascii observation")
}

fn check_envelope(obs: &Observation) {
    assert_eq!(obs.schema_id().as_str(), "memveil-reference-v1");
    assert_eq!(*obs.schema_revision(), 1);
    let steps: Vec<&str> = obs.completed_steps().iter().map(|s| s.as_str()).collect();
    assert_eq!(steps, vec!["only-step"]);
}

#[test]
fn memveil_shaped_independent_facts_and_views() {
    let obs = run("facts", b"case=ok;").expect("facts execute");
    check_envelope(&obs);
    assert_eq!(text(&obs), "match=true;generation=1;");
    let obs = run("sweep", b"case=ok;").expect("sweep executes");
    assert_eq!(text(&obs), "sweep=ok;edges=10;");
    let obs = run("views", b"case=partial-then-final;").expect("views execute");
    assert_eq!(
        text(&obs),
        "first=consumed-loss+query-partial;second=consumed-loss;"
    );
    let obs = run("feed", b"case=complete;").expect("feed executes");
    assert_eq!(text(&obs), "feeds=complete;");
}

#[test]
fn erased_and_unknown_generations_refuse() {
    let obs = run("facts", b"case=erased;").expect("executes");
    assert_eq!(text(&obs), "refuse=GenerationMismatch;");
    let obs = run("facts", b"case=unknown-mapping;").expect("executes");
    assert_eq!(text(&obs), "refuse=GenerationMismatch;");
    let obs = run("facts", b"case=ok;").expect("restored twin passes");
    assert_eq!(text(&obs), "match=true;generation=1;");
}

#[test]
fn sweep_disorder_refuses() {
    let obs = run("sweep", b"case=tie-order;").expect("executes");
    assert_eq!(text(&obs), "refuse=InvalidInterval;");
    let obs = run("sweep", b"case=duplicate-id;").expect("executes");
    assert_eq!(text(&obs), "refuse=DuplicateKey;");
}

#[test]
fn zero_benign_but_atleast_zero_damaging() {
    let obs = run("views", b"case=zero-benign;").expect("executes");
    assert_eq!(text(&obs), "reasons=;");
    let obs = run("views", b"case=atleast-zero-damaging;").expect("executes");
    assert_eq!(text(&obs), "reasons=consumed-loss;");
}

#[test]
fn feed_missing_then_restored() {
    let obs = run("feed", b"case=missing;").expect("executes");
    assert_eq!(text(&obs), "refuse=MissingFeed;");
    let obs = run("feed", b"case=complete;").expect("restored twin passes");
    assert_eq!(text(&obs), "feeds=complete;");
}

#[test]
fn dropped_correction_holder_is_detected() {
    let obs = run("holder", b"case=agree;").expect("executes");
    assert_eq!(
        text(&obs),
        "report_rev1=true;export_rev1=true;report_len=1;export_len=1;agree=true;"
    );
    let obs = run("holder", b"case=dropped;").expect("executes");
    assert_eq!(
        text(&obs),
        "report_rev1=true;export_rev1=false;report_len=1;export_len=1;\
         agree=false;diverged=true;"
    );
    let obs = run("holder", b"case=stale;").expect("executes");
    assert_eq!(text(&obs), "refuse=StaleRevision;report_len=1;");
}

#[test]
fn unknown_op_and_bad_script_refuse() {
    let err = run("no-such-op", b"case=ok;").expect_err("unknown op refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "dispatch");
    let err = run("facts", b"not-a-script").expect_err("bad script refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
    let err = run("facts", b"case=nope;").expect_err("unknown case refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
    let limits = RunLimits::default();
    let inv = invocation(&limits, "facts");
    let fix =
        FixtureAccess::new(&[], &[], EffectBatch::empty(&limits), &limits).expect("empty fixture");
    let err = MemveilReferenceAdapter::new()
        .expect("adapter builds")
        .execute(&inv, &fix)
        .expect_err("missing slot refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
}

// RB4 (R07): the observation honors the invocation's own byte ceiling
// by refusing, never by truncating. The sweep/ok body is 18 bytes; a
// ceiling of 4 refuses at collect with the full diagnostic.
#[test]
fn lowered_observation_ceiling_refuses_at_collect() {
    let limits = lowered(|v| v.observation_bytes = 4);
    let inv = invocation(&limits, "sweep");
    let err = run_with(&limits, &inv, b"case=ok;").expect_err("over-ceiling refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "collect");
}

// RB4 (R07): exact-fit twin. A ceiling of exactly 18 delivers the whole
// body; the refusal above is about the ceiling, not the case.
#[test]
fn exact_observation_ceiling_completes_whole() {
    let limits = lowered(|v| v.observation_bytes = 18);
    let inv = invocation(&limits, "sweep");
    let obs = run_with(&limits, &inv, b"case=ok;").expect("exact fit completes");
    assert_eq!(text(&obs), "sweep=ok;edges=10;");
}

// RB4 (R02): a tight-but-legal label ceiling still delivers the refusal
// (no panic): the convenience method/stage tags fit the live ceiling
// while the category and cause stay exact. Six bytes admits the
// "script" slot but neither "dispatch" nor "execute".
#[test]
fn tight_label_ceiling_fits_refusal_tags() {
    let limits = lowered(|v| v.label_bytes = 6);
    let json = format!(
        "{{\"schema_version\":1,\"kind\":\"steps-v1\",\"schema_id\":\"s\",\
         \"steps\":[{{\"step_id\":\"s\",\"operation\":\"nope\",\
         \"inputs\":[\"script\"],\"parameters\":[]}}]}}",
    )
    .into_bytes();
    let inv = invocation_full(&limits, "m-v1", "m-f1", &json);
    let err = run_with(&limits, &inv, b"case=ok;").expect_err("unknown op refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "dispat");
    assert_eq!(err.cause().method().as_str(), "execut");
}

#[test]
fn subject_names_resolved_consumer() {
    let subject = MemveilReferenceAdapter::new()
        .expect("adapter builds")
        .subject();
    assert_eq!(subject.package_name(), "capture-memveil-reference");
    assert_eq!(subject.package_version(), "0.1.0");
    assert_eq!(subject.consumer().name(), "memveil-adapter");
    assert_eq!(
        subject.host(),
        &format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
    );
    assert_eq!(subject.target(), subject.host());
}
