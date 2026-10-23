// SPDX-License-Identifier: Apache-2.0
//! CP11 consumer contract: OSSL-shaped reference consumer.
//!
//! Exercises alternative site bounds, neutral validation with versioned
//! late corrections, feed presence and correction holders through the real
//! testkit `ConformanceAdapter` seam. Expected bytes are hand-authored here,
//! never derived from capture output. NEW (CP11): no donor lines copied.
use capture_ossl_reference::adapter::OsslReferenceAdapter;
use scopebase_testkit::{
    CaseError, CaseErrorCategory, CaseId, CaseInvocation, CaseInvocationValues, CaseKey,
    CaseKeyValues, ConformanceAdapter, EffectBatch, FixtureAccess, FixtureInput, InvocationKey,
    InvocationKeyValues, Label, Observation, OperationScript, RunId, RunLimits, SchemaBinding,
    SchemaBindingValues,
};

fn script_json(op: &str) -> Vec<u8> {
    format!(
        "{{\"schema_version\":1,\"kind\":\"steps-v1\",\"schema_id\":\"ossl-script\",\
         \"steps\":[{{\"step_id\":\"only-step\",\"operation\":\"{op}\",\
         \"inputs\":[\"script\"],\"parameters\":[]}}]}}"
    )
    .into_bytes()
}

fn invocation(limits: &RunLimits, op: &str) -> CaseInvocation {
    invocation_full(
        limits,
        "ossl-reference-v1",
        "ossl-fixture-v1",
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
            run_id: RunId::parse("fedcba9876543210fedcba9876543210").expect("run id"),
            case_key: CaseKey::new(
                CaseKeyValues {
                    case_id: CaseId::parse("CP11.ossl-contract").expect("case id"),
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
    OsslReferenceAdapter::new()
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
    assert_eq!(obs.schema_id().as_str(), "ossl-reference-v1");
    assert_eq!(*obs.schema_revision(), 1);
    let steps: Vec<&str> = obs.completed_steps().iter().map(|s| s.as_str()).collect();
    assert_eq!(steps, vec!["only-step"]);
}

#[test]
fn ossl_shaped_shared_site_bounds() {
    let obs = run("bounds", b"case=shared;").expect("bounds execute");
    check_envelope(&obs);
    assert_eq!(text(&obs), "lower=0;upper=10;");
    let obs = run("bounds", b"case=definite;").expect("executes");
    assert_eq!(text(&obs), "lower=10;upper=10;");
    let obs = run("bounds", b"case=combine;").expect("executes");
    assert_eq!(text(&obs), "lower=10;upper=20;");
    let obs = run("bounds", b"case=unknown;").expect("executes");
    assert_eq!(text(&obs), "lower=0;upper=unknown;");
    let obs = run("feed", b"case=complete;").expect("feed executes");
    assert_eq!(text(&obs), "feeds=complete;");
}

#[test]
fn unknown_and_zero_stay_distinct() {
    let obs = run("bounds", b"case=zero-unknown;").expect("executes");
    assert_eq!(text(&obs), "lower=0;upper=unknown;");
    let obs = run("bounds", b"case=excluded;").expect("executes");
    assert_eq!(text(&obs), "lower=0;upper=0;");
}

#[test]
fn alias_and_admission_negatives() {
    let obs = run("bounds", b"case=alias-multiply;").expect("executes");
    assert_eq!(text(&obs), "refuse=DuplicateKey;");
    let obs = run("bounds", b"case=empty-complete;").expect("executes");
    assert_eq!(text(&obs), "refuse=MissingProvenance;");
    let obs = run("bounds", b"case=class-mismatch;").expect("executes");
    assert_eq!(text(&obs), "refuse=ConservationMismatch;");
}

#[test]
fn neutral_versioned_corrections() {
    let obs = run("neutral", b"case=ok;").expect("neutral executes");
    assert_eq!(
        text(&obs),
        "counters=1;losses=1;signals=1;claims=1;partitions=1;corrections=1;"
    );
    let obs = run("neutral", b"case=bad-correction;").expect("executes");
    assert_eq!(text(&obs), "refuse=StaleRevision;");
    let obs = run("neutral", b"case=dup-channel;").expect("executes");
    assert_eq!(text(&obs), "refuse=DuplicateKey;");
    let obs = run("neutral", b"case=bad-partition;").expect("executes");
    assert_eq!(text(&obs), "refuse=ConservationMismatch;");
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
        "report_rev1=true;export_rev1=true;report=10+10;export=10+10;agree=true;"
    );
    let obs = run("holder", b"case=dropped;").expect("executes");
    assert_eq!(
        text(&obs),
        "report_rev1=true;export_rev1=false;report=10+10;export=0+10;\
         agree=false;diverged=true;"
    );
    let obs = run("holder", b"case=stale;").expect("executes");
    assert_eq!(text(&obs), "refuse=StaleRevision;report=10+10;");
}

#[test]
fn unknown_op_and_bad_script_refuse() {
    let err = run("no-such-op", b"case=ok;").expect_err("unknown op refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "dispatch");
    let err = run("neutral", b"not-a-script").expect_err("bad script refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
    let err = run("neutral", b"case=nope;").expect_err("unknown case refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
    let limits = RunLimits::default();
    let inv = invocation(&limits, "neutral");
    let fix =
        FixtureAccess::new(&[], &[], EffectBatch::empty(&limits), &limits).expect("empty fixture");
    let err = OsslReferenceAdapter::new()
        .expect("adapter builds")
        .execute(&inv, &fix)
        .expect_err("missing slot refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
}

// RB4 (R07): the observation honors the invocation's own byte ceiling
// by refusing, never by truncating. The bounds/shared body is 17
// bytes; a ceiling of 4 refuses at collect with the full diagnostic.
#[test]
fn lowered_observation_ceiling_refuses_at_collect() {
    let limits = lowered(|v| v.observation_bytes = 4);
    let inv = invocation(&limits, "bounds");
    let err = run_with(&limits, &inv, b"case=shared;").expect_err("over-ceiling refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "collect");
}

// RB4 (R07): exact-fit twin. A ceiling of exactly 17 delivers the whole
// body; the refusal above is about the ceiling, not the case.
#[test]
fn exact_observation_ceiling_completes_whole() {
    let limits = lowered(|v| v.observation_bytes = 17);
    let inv = invocation(&limits, "bounds");
    let obs = run_with(&limits, &inv, b"case=shared;").expect("exact fit completes");
    assert_eq!(text(&obs), "lower=0;upper=10;");
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
    let inv = invocation_full(&limits, "o-v1", "o-f1", &json);
    let err = run_with(&limits, &inv, b"case=shared;").expect_err("unknown op refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "dispat");
    assert_eq!(err.cause().method().as_str(), "execut");
}

#[test]
fn subject_names_resolved_consumer() {
    let subject = OsslReferenceAdapter::new()
        .expect("adapter builds")
        .subject();
    assert_eq!(subject.package_name(), "capture-ossl-reference");
    assert_eq!(subject.package_version(), "0.1.0");
    assert_eq!(subject.consumer().name(), "ossl-adapter");
    assert_eq!(
        subject.host(),
        &format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
    );
    assert_eq!(subject.target(), subject.host());
}
