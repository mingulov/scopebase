// SPDX-License-Identifier: Apache-2.0
//! LX11 consumer contract: owned-workload observer reference consumer.
//!
//! Exercises real process acquisition, birth verification, maps/mountinfo
//! observation and mapping verdicts through the testkit `ConformanceAdapter`
//! seam. Live observations assert relational facts (birth equality, address
//! containment, verdict kinds), never absolute counts. The TT03 stat oracle
//! independently cross-checks every birth the Linux API reports. Expected
//! bytes are hand-authored here from the frozen contracts.
//! NEW (LX11): no donor lines copied.
use linux_observe_reference::adapter::ObserveReferenceAdapter;
use scopebase_linux::conformance::FixtureRoot;
use scopebase_testkit::{
    CaseError, CaseErrorCategory, CaseId, CaseInvocation, CaseInvocationValues, CaseKey,
    CaseKeyValues, ConformanceAdapter, EffectBatch, FixtureAccess, FixtureInput, InvocationKey,
    InvocationKeyValues, Label, Observation, OperationScript, RunId, RunLimits, SchemaBinding,
    SchemaBindingValues,
};

fn script_json(op: &str) -> Vec<u8> {
    format!(
        "{{\"schema_version\":1,\"kind\":\"steps-v1\",\"schema_id\":\"observe-script\",\
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
                    case_id: CaseId::parse("LX11.observe-contract").expect("case id"),
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
                    id: Label::parse("observe-reference-v1").expect("schema"),
                    revision: 1,
                },
                limits,
            )
            .expect("observation schema"),
            fixture_schema: SchemaBinding::new(
                SchemaBindingValues {
                    id: Label::parse("observe-fixture-v1").expect("schema"),
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

fn owned_root(test: &str) -> FixtureRoot {
    let name = format!("lx11-observe-{}-{test}", std::process::id());
    FixtureRoot::create(&std::env::temp_dir(), &name).expect("fixture root")
}

fn run(op: &str, script: &[u8]) -> Result<Observation, CaseError> {
    let limits = RunLimits::default();
    let inv = invocation(&limits, op);
    let input = FixtureInput::new(Label::parse("script").expect("slot"), script);
    let fix = FixtureAccess::new(
        std::slice::from_ref(&input),
        &[],
        EffectBatch::empty(&limits),
        &limits,
    )
    .expect("fixture");
    ObserveReferenceAdapter::new()
        .expect("adapter builds")
        .execute(&inv, &fix)
}

fn text(obs: &Observation) -> &str {
    std::str::from_utf8(obs.bytes()).expect("ascii observation")
}

fn check_envelope(obs: &Observation) {
    assert_eq!(obs.schema_id().as_str(), "observe-reference-v1");
    assert_eq!(*obs.schema_revision(), 1);
    let steps: Vec<&str> = obs.completed_steps().iter().map(|s| s.as_str()).collect();
    assert_eq!(steps, vec!["only-step"]);
}

#[test]
fn acquire_self_verifies_birth_against_oracle() {
    let obs = run("acquire-self", b"case=self;").expect("executes");
    check_envelope(&obs);
    assert_eq!(
        text(&obs),
        "birth=AliveSameBirth;self_zombie=false;starttime_match=true;"
    );
    let pid = std::process::id();
    let script = format!("case=pid;pid={pid};");
    let obs = run("acquire", script.as_bytes()).expect("executes");
    assert_eq!(
        text(&obs),
        "birth=AliveSameBirth;self_zombie=false;starttime_match=true;"
    );
}

#[test]
fn acquire_dead_pid_refuses_typed() {
    let obs = run("acquire", b"case=dead;").expect("executes");
    assert_eq!(text(&obs), "refuse=AcquireProcess:Disappeared;");
}

#[test]
fn spawned_child_is_observed_then_reaped() {
    let exe = env!("CARGO_BIN_EXE_linux-observe-reference");
    let script = format!("case=child;child={exe};");
    let obs = run("spawn-observe", script.as_bytes()).expect("executes");
    check_envelope(&obs);
    assert_eq!(
        text(&obs),
        "birth=AliveSameBirth;child_maps=true;starttime_match=true;reaped=true;gone=true;"
    );
}

#[test]
fn own_maps_contain_live_stack_address() {
    let obs = run("maps-self", b"case=self;").expect("executes");
    check_envelope(&obs);
    assert_eq!(text(&obs), "nonempty=true;self_containing=true;");
}

#[test]
fn own_mount_table_is_nonempty() {
    let obs = run("mounts-self", b"case=self;").expect("executes");
    check_envelope(&obs);
    assert_eq!(text(&obs), "nonempty=true;");
}

#[test]
fn mapping_verdicts_stay_deterministic() {
    let root = owned_root("mapping");
    let empty = root.write_file("empty.bin", b"").expect("empty");
    let script = format!("case=empty;path={};", empty.display());
    let obs = run("mapping", script.as_bytes()).expect("executes");
    check_envelope(&obs);
    assert_eq!(text(&obs), "verdict=inconclusive:EmptyFile;");
    let file = root.write_file("data.bin", b"hello world").expect("data");
    let script = format!("case=unmapped;path={};", file.display());
    let obs = run("mapping", script.as_bytes()).expect("executes");
    assert_eq!(text(&obs), "verdict=mismatch:RangeUnmapped;");
    let script = format!("case=incoherent;path={};", file.display());
    let obs = run("mapping", script.as_bytes()).expect("executes");
    assert_eq!(text(&obs), "refuse=ConfigureMapping:InvalidInput;");
    root.close().expect("cleanup");
}

#[test]
fn unknown_op_case_and_bad_script_refuse() {
    let err = run("no-such-op", b"case=self;").expect_err("unknown op refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "dispatch");
    let err = run("acquire", b"not-a-script").expect_err("bad script refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
    let err = run("acquire", b"case=nope;").expect_err("unknown case refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
    let err = run("spawn-observe", b"case=child;").expect_err("missing child refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
    let err = run("mapping", b"case=empty;").expect_err("missing path refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
    let limits = RunLimits::default();
    let inv = invocation(&limits, "acquire-self");
    let fix =
        FixtureAccess::new(&[], &[], EffectBatch::empty(&limits), &limits).expect("empty fixture");
    let err = ObserveReferenceAdapter::new()
        .expect("adapter builds")
        .execute(&inv, &fix)
        .expect_err("missing slot refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
}

#[test]
fn subject_names_resolved_consumer() {
    let subject = ObserveReferenceAdapter::new()
        .expect("adapter builds")
        .subject();
    assert_eq!(subject.package_name(), "linux-observe-reference");
    assert_eq!(subject.package_version(), "0.1.0");
    assert_eq!(subject.consumer().name(), "observe-adapter");
    assert_eq!(
        subject.host(),
        &format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
    );
    assert_eq!(subject.target(), subject.host());
}
