// SPDX-License-Identifier: Apache-2.0
//! CP11 consumer contract: KryProbe-shaped reference consumer.
//!
//! Exercises insertion folds, counter deltas, capped signals, loss facts,
//! feed presence and correction holders through the real testkit
//! `ConformanceAdapter` seam. Expected bytes are hand-authored here, never
//! derived from capture output. NEW (CP11): no donor lines copied.
use capture_kryprobe_reference::adapter::KryprobeReferenceAdapter;
use scopebase_testkit::{
    CaseError, CaseErrorCategory, CaseId, CaseInvocation, CaseInvocationValues, CaseKey,
    CaseKeyValues, ConformanceAdapter, EffectBatch, FixtureAccess, FixtureInput, InvocationKey,
    InvocationKeyValues, Label, Observation, OperationScript, RunId, RunLimits, SchemaBinding,
    SchemaBindingValues,
};

fn script_json(op: &str) -> Vec<u8> {
    format!(
        "{{\"schema_version\":1,\"kind\":\"steps-v1\",\"schema_id\":\"kryprobe-script\",\
         \"steps\":[{{\"step_id\":\"only-step\",\"operation\":\"{op}\",\
         \"inputs\":[\"script\"],\"parameters\":[]}}]}}"
    )
    .into_bytes()
}

fn invocation(limits: &RunLimits, op: &str) -> CaseInvocation {
    let script = OperationScript::load(&script_json(op), limits).expect("test script loads");
    let key = InvocationKey::new(
        InvocationKeyValues {
            run_id: RunId::parse("0123456789abcdef0123456789abcdef").expect("run id"),
            case_key: CaseKey::new(
                CaseKeyValues {
                    case_id: CaseId::parse("CP11.kryprobe-contract").expect("case id"),
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
                    id: Label::parse("kryprobe-reference-v1").expect("schema"),
                    revision: 1,
                },
                limits,
            )
            .expect("observation schema"),
            fixture_schema: SchemaBinding::new(
                SchemaBindingValues {
                    id: Label::parse("kryprobe-fixture-v1").expect("schema"),
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
    let fix = access(&limits, script);
    KryprobeReferenceAdapter::new()
        .expect("adapter builds")
        .execute(&inv, &fix)
}

fn text(obs: &Observation) -> &str {
    std::str::from_utf8(obs.bytes()).expect("ascii observation")
}

fn check_envelope(obs: &Observation) {
    assert_eq!(obs.schema_id().as_str(), "kryprobe-reference-v1");
    assert_eq!(*obs.schema_revision(), 1);
    let steps: Vec<&str> = obs.completed_steps().iter().map(|s| s.as_str()).collect();
    assert_eq!(steps, vec!["only-step"]);
}

#[test]
fn kryprobe_shaped_fold_and_loss() {
    let obs = run("fold", b"case=ok;").expect("fold executes");
    check_envelope(&obs);
    assert_eq!(text(&obs), "total=10;owner=7;");
    let obs = run("signals", b"case=fold;").expect("signals execute");
    assert_eq!(text(&obs), "fold=7;");
    let obs = run("delta", b"case=ok;").expect("delta executes");
    assert_eq!(text(&obs), "delta=exact:5;");
    let obs = run("feed", b"case=complete;").expect("feed executes");
    assert_eq!(text(&obs), "feeds=complete;");
    let obs = run("bytes", b"case=survive;").expect("bytes execute");
    assert_eq!(text(&obs), "bytes=5;magnitude=unknown;");
    let obs = run("identity", b"case=unknown;").expect("identity executes");
    assert_eq!(text(&obs), "identity=unknown:NotObserved;");
}

#[test]
fn fold_negatives_refuse() {
    let obs = run("fold", b"case=duplicate-owner;").expect("executes");
    assert_eq!(text(&obs), "refuse=ConflictingProvenance;");
    let obs = run("fold", b"case=saturated;").expect("executes");
    assert_eq!(text(&obs), "refuse=SaturatedCount;");
    let obs = run("fold", b"case=missing-owner;").expect("executes");
    assert_eq!(text(&obs), "refuse=MissingProvenance;");
}

#[test]
fn delta_unknowns_stay_unknown() {
    let obs = run("delta", b"case=missing-baseline;").expect("executes");
    assert_eq!(text(&obs), "delta=unknown:MissingBaseline;");
    let obs = run("delta", b"case=decrease;").expect("executes");
    assert_eq!(text(&obs), "delta=unknown:ResetOrWrap;");
    let obs = run("delta", b"case=overlap;").expect("executes");
    assert_eq!(text(&obs), "delta=unknown:PartialRead;");
}

#[test]
fn feed_missing_then_restored() {
    let obs = run("feed", b"case=missing;").expect("executes");
    assert_eq!(text(&obs), "refuse=MissingFeed;");
    let obs = run("feed", b"case=complete;").expect("restored twin passes");
    assert_eq!(text(&obs), "feeds=complete;");
}

#[test]
fn signals_over_cap_refuses() {
    let obs = run("signals", b"case=over-cap;").expect("executes");
    assert_eq!(text(&obs), "refuse=InvalidSample;");
}

#[test]
fn dropped_correction_holder_is_detected() {
    let obs = run("holder", b"case=agree;").expect("executes");
    assert_eq!(
        text(&obs),
        "report_rev1=true;export_rev1=true;report_value=7;export_value=7;agree=true;"
    );
    let obs = run("holder", b"case=dropped;").expect("executes");
    assert_eq!(
        text(&obs),
        "report_rev1=true;export_rev1=false;report_value=7;export_value=10;\
         agree=false;diverged=true;"
    );
    let obs = run("holder", b"case=stale;").expect("executes");
    assert_eq!(text(&obs), "refuse=StaleRevision;report_value=7;");
}

#[test]
fn unknown_op_and_bad_script_refuse() {
    let err = run("no-such-op", b"case=ok;").expect_err("unknown op refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "dispatch");
    let err = run("fold", b"not-a-script").expect_err("bad script refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
    let err = run("fold", b"case=nope;").expect_err("unknown case refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
    let limits = RunLimits::default();
    let inv = invocation(&limits, "fold");
    let fix =
        FixtureAccess::new(&[], &[], EffectBatch::empty(&limits), &limits).expect("empty fixture");
    let err = KryprobeReferenceAdapter::new()
        .expect("adapter builds")
        .execute(&inv, &fix)
        .expect_err("missing slot refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
}

#[test]
fn subject_names_resolved_consumer() {
    let subject = KryprobeReferenceAdapter::new()
        .expect("adapter builds")
        .subject();
    assert_eq!(subject.package_name(), "capture-kryprobe-reference");
    assert_eq!(subject.package_version(), "0.1.0");
    assert_eq!(subject.consumer().name(), "kryprobe-adapter");
    assert_eq!(
        subject.host(),
        &format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
    );
    assert_eq!(subject.target(), subject.host());
}
