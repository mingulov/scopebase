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
    script_json_with_id(op, "ossl-script")
}

/// S34 (R33): same script envelope under an explicit dialect id, so
/// alien-script negatives stay otherwise valid.
fn script_json_with_id(op: &str, schema_id: &str) -> Vec<u8> {
    format!(
        "{{\"schema_version\":1,\"kind\":\"steps-v1\",\"schema_id\":\"{schema_id}\",\
         \"steps\":[{{\"step_id\":\"only-step\",\"operation\":\"{op}\",\
         \"inputs\":[\"script\"],\"parameters\":[]}}]}}"
    )
    .into_bytes()
}

fn invocation(limits: &RunLimits, op: &str) -> CaseInvocation {
    invocation_full(
        limits,
        "ossl-reference-v1",
        1,
        "ossl-fixture-v1",
        1,
        &script_json(op),
    )
}

fn invocation_full(
    limits: &RunLimits,
    obs_schema: &str,
    obs_rev: u32,
    fix_schema: &str,
    fix_rev: u32,
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
                    revision: obs_rev,
                },
                limits,
            )
            .expect("observation schema"),
            fixture_schema: SchemaBinding::new(
                SchemaBindingValues {
                    id: Label::parse(fix_schema).expect("schema"),
                    revision: fix_rev,
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
fn unknown_op_unsupported_bad_script_invalid_output() {
    // S44: missing/malformed operation data after dialect admission
    // is InvalidOutput with the attempted step, never Refused.
    let err = run("no-such-op", b"case=ok;").expect_err("unknown op unsupported");
    assert_eq!(*err.category(), CaseErrorCategory::UnsupportedSchema);
    assert_eq!(err.stage().as_str(), "adapter-schema");
    assert!(err.step_id().is_none(), "dialect rejection names no step");
    let err = run("neutral", b"not-a-script").expect_err("bad script invalid");
    assert_eq!(*err.category(), CaseErrorCategory::InvalidOutput);
    assert_eq!(err.stage().as_str(), "admission");
    assert_eq!(err.step_id().as_ref().map(Label::as_str), Some("only-step"));
    let err = run("neutral", b"case=nope;").expect_err("unknown case invalid");
    assert_eq!(*err.category(), CaseErrorCategory::InvalidOutput);
    assert_eq!(err.stage().as_str(), "admission");
    assert_eq!(err.step_id().as_ref().map(Label::as_str), Some("only-step"));
    let limits = RunLimits::default();
    let inv = invocation(&limits, "neutral");
    let fix =
        FixtureAccess::new(&[], &[], EffectBatch::empty(&limits), &limits).expect("empty fixture");
    let err = OsslReferenceAdapter::new()
        .expect("adapter builds")
        .execute(&inv, &fix)
        .expect_err("missing slot invalid");
    assert_eq!(*err.category(), CaseErrorCategory::InvalidOutput);
    assert_eq!(err.stage().as_str(), "admission");
    assert_eq!(err.step_id().as_ref().map(Label::as_str), Some("only-step"));
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
fn tight_label_ceiling_fits_unsupported_tags() {
    let limits = lowered(|v| v.label_bytes = 6);
    let json = format!(
        "{{\"schema_version\":1,\"kind\":\"steps-v1\",\"schema_id\":\"s\",\
         \"steps\":[{{\"step_id\":\"s\",\"operation\":\"nope\",\
         \"inputs\":[\"script\"],\"parameters\":[]}}]}}",
    )
    .into_bytes();
    let inv = invocation_full(&limits, "o-v1", 1, "o-f1", 1, &json);
    let err = run_with(&limits, &inv, b"case=shared;").expect_err("alien dialect unsupported");
    assert_eq!(*err.category(), CaseErrorCategory::UnsupportedSchema);
    assert_eq!(err.stage().as_str(), "adapte");
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

fn step_json(step_id: &str, op: &str, inputs: &str, parameters: &str) -> String {
    format!(
        "{{\"step_id\":\"{step_id}\",\"operation\":\"{op}\",\
         \"inputs\":{inputs},\"parameters\":{parameters}}}"
    )
}

fn script_steps_json(schema_id: &str, steps: &[String]) -> Vec<u8> {
    format!(
        "{{\"schema_version\":1,\"kind\":\"steps-v1\",\"schema_id\":\"{schema_id}\",\
         \"steps\":[{steps}]}}",
        steps = steps.join(",")
    )
    .into_bytes()
}

fn check_unsupported(err: &CaseError) {
    assert_eq!(*err.category(), CaseErrorCategory::UnsupportedSchema);
    assert_eq!(err.stage().as_str(), "adapter-schema");
    assert!(err.step_id().is_none(), "dialect rejection names no step");
    assert!(err.completed_steps().is_empty());
}

/// S34 (R33): an otherwise-valid invocation under an alien script
/// dialect is pre-read UnsupportedSchema — even with an empty
/// fixture, which proves the dialect admits before any slot is
/// touched (a slot check would refuse missing-slot instead).
#[test]
fn alien_script_dialect_unsupported_before_reads() {
    let limits = RunLimits::default();
    let script = script_json_with_id("bounds", "alien-script");
    let inv = invocation_full(
        &limits,
        "ossl-reference-v1",
        1,
        "ossl-fixture-v1",
        1,
        &script,
    );
    let fix =
        FixtureAccess::new(&[], &[], EffectBatch::empty(&limits), &limits).expect("empty fixture");
    for (name, fix) in [
        ("empty", &fix),
        (
            "full",
            &FixtureAccess::new(
                &[FixtureInput::new(
                    Label::parse("script").expect("slot"),
                    b"case=shared;",
                )],
                &[],
                EffectBatch::empty(&limits),
                &limits,
            )
            .expect("full fixture"),
        ),
    ] {
        let err = OsslReferenceAdapter::new()
            .expect("adapter builds")
            .execute(&inv, fix)
            .expect_err(&format!("alien script unsupported ({name})"));
        check_unsupported(&err);
    }
    // Unknown opcodes admit the same way: pre-read, before slots.
    let inv = invocation(&limits, "no-such-op");
    let err = OsslReferenceAdapter::new()
        .expect("adapter builds")
        .execute(&inv, &fix)
        .expect_err("unknown op unsupported before reads");
    check_unsupported(&err);
}

// S34: an alien observation schema rejects before effects. The case
// data below is valid and would succeed without the preflight.
#[test]
fn alien_observation_schema_rejects_before_effects() {
    let limits = RunLimits::default();
    let inv = invocation_full(
        &limits,
        "alien-schema-v9",
        1,
        "ossl-fixture-v1",
        1,
        &script_json("bounds"),
    );
    let err = run_with(&limits, &inv, b"case=shared;").expect_err("alien schema rejects");
    check_unsupported(&err);
}

// S34: alien fixture schema and revision mismatches reject too.
#[test]
fn alien_fixture_schema_or_revision_rejects() {
    let limits = RunLimits::default();
    for (obs, obs_rev, fix, fix_rev) in [
        ("ossl-reference-v1", 1, "alien-fixture-v9", 1),
        ("ossl-reference-v1", 2, "ossl-fixture-v1", 1),
        ("ossl-reference-v1", 1, "ossl-fixture-v1", 2),
    ] {
        let inv = invocation_full(&limits, obs, obs_rev, fix, fix_rev, &script_json("bounds"));
        let err = run_with(&limits, &inv, b"case=shared;").expect_err("alien envelope rejects");
        check_unsupported(&err);
    }
}

// S34: multi-step scripts reject — including a valid first step with
// an unsupported later step, which the old first-step dispatch
// silently ignored while executing the leader.
#[test]
fn multi_step_script_rejects() {
    let limits = RunLimits::default();
    for (name, steps) in [
        (
            "valid-valid",
            vec![
                step_json("first", "bounds", "[\"script\"]", "[]"),
                step_json("second", "bounds", "[\"script\"]", "[]"),
            ],
        ),
        (
            "valid-unsupported",
            vec![
                step_json("first", "bounds", "[\"script\"]", "[]"),
                step_json("second", "no-such-op", "[\"script\"]", "[]"),
            ],
        ),
    ] {
        let inv = invocation_full(
            &limits,
            "ossl-reference-v1",
            1,
            "ossl-fixture-v1",
            1,
            &script_steps_json("ossl-script", &steps),
        );
        let err = run_with(&limits, &inv, b"case=shared;")
            .expect_err(&format!("multi-step rejects ({name})"));
        check_unsupported(&err);
    }
    // An empty step list is unconstructible: OperationScript::load
    // rejects it ("empty script"), so the adapter's zero-step arm is
    // defensive only and has no loader-built test.
}

// S34: step parameters and wrong declared-input sets reject.
#[test]
fn parameters_and_input_shape_reject() {
    let limits = RunLimits::default();
    let with_params = script_steps_json(
        "ossl-script",
        &[step_json(
            "only-step",
            "bounds",
            "[\"script\"]",
            "[{\"kind\":\"u64\",\"value\":\"7\"}]",
        )],
    );
    let inv = invocation_full(
        &limits,
        "ossl-reference-v1",
        1,
        "ossl-fixture-v1",
        1,
        &with_params,
    );
    let err = run_with(&limits, &inv, b"case=shared;").expect_err("parameters reject");
    check_unsupported(&err);

    for inputs in ["[]", "[\"script\",\"body\"]", "[\"body\"]"] {
        let json = script_steps_json(
            "ossl-script",
            &[step_json("only-step", "bounds", inputs, "[]")],
        );
        let inv = invocation_full(&limits, "ossl-reference-v1", 1, "ossl-fixture-v1", 1, &json);
        let err = run_with(&limits, &inv, b"case=shared;").expect_err("shape rejects");
        check_unsupported(&err);
    }
}
