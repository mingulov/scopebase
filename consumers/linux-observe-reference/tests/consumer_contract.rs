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
    invocation_full(
        limits,
        "observe-reference-v1",
        1,
        "observe-fixture-v1",
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

fn owned_root(test: &str) -> FixtureRoot {
    let name = format!("lx11-observe-{}-{test}", std::process::id());
    FixtureRoot::create(&std::env::temp_dir(), &name).expect("fixture root")
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
    let input = FixtureInput::new(Label::parse("script").expect("slot"), script);
    let fix = FixtureAccess::new(
        std::slice::from_ref(&input),
        &[],
        EffectBatch::empty(limits),
        limits,
    )
    .expect("fixture");
    ObserveReferenceAdapter::new()
        .expect("adapter builds")
        .execute(inv, &fix)
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

fn lowered(mut apply: impl FnMut(&mut scopebase_testkit::RunLimitValues)) -> RunLimits {
    let base = RunLimits::default();
    let mut values = base.values();
    apply(&mut values);
    base.lowered(values).expect("lowered limits admit")
}

fn step_json(step_id: &str, op: &str, inputs: &str, parameters: &str) -> String {
    format!(
        "{{\"step_id\":\"{step_id}\",\"operation\":\"{op}\",\
         \"inputs\":{inputs},\"parameters\":{parameters}}}"
    )
}

fn script_steps_json(steps: &[String]) -> Vec<u8> {
    format!(
        "{{\"schema_version\":1,\"kind\":\"steps-v1\",\"schema_id\":\"observe-script\",\
         \"steps\":[{}]}}",
        steps.join(",")
    )
    .into_bytes()
}

fn check_unsupported(err: &CaseError) {
    assert_eq!(*err.category(), CaseErrorCategory::UnsupportedSchema);
    assert_eq!(err.stage().as_str(), "adapter-schema");
    assert!(err.step_id().is_none(), "dialect rejection names no step");
    assert!(err.completed_steps().is_empty());
}

// F27: an alien observation schema rejects before effects. The
// acquire-self script would succeed without the preflight.
#[test]
fn alien_observation_schema_rejects_before_effects() {
    let limits = RunLimits::default();
    let inv = invocation_full(
        &limits,
        "alien-schema-v9",
        1,
        "observe-fixture-v1",
        1,
        &script_json("acquire-self"),
    );
    let err = run_with(&limits, &inv, b"case=self;").expect_err("alien schema rejects");
    check_unsupported(&err);
}

// F27: alien fixture schema and revision mismatches reject too.
#[test]
fn alien_fixture_schema_or_revision_rejects() {
    let limits = RunLimits::default();
    for (obs, obs_rev, fix, fix_rev) in [
        ("observe-reference-v1", 1, "alien-fixture-v9", 1),
        ("observe-reference-v1", 2, "observe-fixture-v1", 1),
        ("observe-reference-v1", 1, "observe-fixture-v1", 2),
    ] {
        let inv = invocation_full(&limits, obs, obs_rev, fix, fix_rev, &script_json("mapping"));
        let err = run_with(&limits, &inv, b"case=self;").expect_err("alien envelope rejects");
        check_unsupported(&err);
    }
}

// F27: multi-step scripts reject; the old first-step dispatch would
// have executed the leading valid step instead.
#[test]
fn multi_step_script_rejects() {
    let limits = RunLimits::default();
    let steps = vec![
        step_json("first", "acquire-self", "[\"script\"]", "[]"),
        step_json("second", "acquire-self", "[\"script\"]", "[]"),
    ];
    let inv = invocation_full(
        &limits,
        "observe-reference-v1",
        1,
        "observe-fixture-v1",
        1,
        &script_steps_json(&steps),
    );
    let err = run_with(&limits, &inv, b"case=self;").expect_err("multi-step rejects");
    check_unsupported(&err);
}

// F27: step parameters and wrong declared-input sets reject.
#[test]
fn parameters_and_input_shape_reject() {
    let limits = RunLimits::default();
    let with_params = script_steps_json(&[step_json(
        "only-step",
        "acquire-self",
        "[\"script\"]",
        "[{\"kind\":\"bool\",\"value\":true}]",
    )]);
    let inv = invocation_full(
        &limits,
        "observe-reference-v1",
        1,
        "observe-fixture-v1",
        1,
        &with_params,
    );
    let err = run_with(&limits, &inv, b"case=self;").expect_err("parameters reject");
    check_unsupported(&err);

    for inputs in ["[]", "[\"script\",\"body\"]", "[\"body\"]"] {
        let json = script_steps_json(&[step_json("only-step", "acquire-self", inputs, "[]")]);
        let inv = invocation_full(
            &limits,
            "observe-reference-v1",
            1,
            "observe-fixture-v1",
            1,
            &json,
        );
        let err = run_with(&limits, &inv, b"case=self;").expect_err("shape rejects");
        check_unsupported(&err);
    }
}

// RB4 (R07): the observation honors the invocation's own byte ceiling
// by refusing, never by truncating. The empty-mapping verdict is 30
// bytes; a ceiling of 7 refuses at collect with the full diagnostic.
#[test]
fn lowered_observation_ceiling_refuses_at_collect() {
    let root = owned_root("low-obs");
    let empty = root.write_file("empty.bin", b"").expect("file");
    let empty = empty.to_string_lossy().into_owned();
    let limits = lowered(|v| v.observation_bytes = 7);
    let inv = invocation(&limits, "mapping");
    let script = format!("case=empty;path={empty};");
    let err = run_with(&limits, &inv, script.as_bytes()).expect_err("over-ceiling refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "collect");
    root.close().expect("cleanup");
}

// RB4 (R07): exact-fit twin. A ceiling of exactly 31 delivers the whole
// verdict; the refusal above is about the ceiling, not the case.
#[test]
fn exact_observation_ceiling_completes_whole() {
    let root = owned_root("exact-obs");
    let empty = root.write_file("empty.bin", b"").expect("file");
    let empty = empty.to_string_lossy().into_owned();
    let limits = lowered(|v| v.observation_bytes = 31);
    let inv = invocation(&limits, "mapping");
    let script = format!("case=empty;path={empty};");
    let obs = run_with(&limits, &inv, script.as_bytes()).expect("exact fit completes");
    assert_eq!(obs.bytes(), b"verdict=inconclusive:EmptyFile;");
    root.close().expect("cleanup");
}

// F26: refusal diagnostics honor the invocation's own byte ceiling.
#[test]
fn lowered_diagnostic_ceiling_truncates_refusal() {
    let limits = lowered(|v| v.diagnostic_bytes = 8);
    let inv = invocation(&limits, "acquire");
    let err = run_with(&limits, &inv, b"case=nope;").expect_err("unknown case refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.diagnostic_bytes(), b"LX11:unk");
}

// RB4 (R02): a tight-but-legal label ceiling still delivers the refusal
// (no panic): the convenience method/stage tags fit the live ceiling
// while the category and cause stay exact. Six bytes admits the
// "script" slot but neither "adapter-schema" nor "execute".
#[test]
fn tight_label_ceiling_fits_refusal_tags() {
    let limits = lowered(|v| v.label_bytes = 6);
    // The script envelope carries its own schema id, so the shared
    // builder cannot load here; every label in this script fits the
    // 6-byte ceiling by hand.
    let json = format!(
        // The operation is short on purpose ("nope" fits 6 bytes); the
        // schema preflight rejects before the operation is ever checked.
        "{{\"schema_version\":1,\"kind\":\"steps-v1\",\"schema_id\":\"s\",\
         \"steps\":[{{\"step_id\":\"s\",\"operation\":\"nope\",\
         \"inputs\":[\"script\"],\"parameters\":[]}}]}}",
    )
    .into_bytes();
    let inv = invocation_full(&limits, "o-v1", 1, "f-v1", 1, &json);
    let err = run_with(&limits, &inv, b"case=self;").expect_err("alien schema refuses");
    assert_eq!(*err.category(), CaseErrorCategory::UnsupportedSchema);
    assert_eq!(err.stage().as_str(), "adapte");
    assert_eq!(err.cause().method().as_str(), "execut");
    assert!(err.step_id().is_none(), "dialect rejection names no step");
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

// R03/R04/R34: executable boundary tests. `run()` unit tests cannot
// exercise argv decoding or dead stdio; these drive the real binary.

fn bin() -> std::path::PathBuf {
    // Compile-time lookup (cargo sets this when the binary target is in
    // the build plan); a filtered run that excludes the binary fails
    // loudly here instead of skipping vacuously.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_linux-observe-reference"))
}

fn scratch(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "lx11-cli-{}-{}-{}",
        tag,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// R03: non-UTF-8 argv refuses with usage (exit 2), never panics in
/// `env::args()` (old code exited 101).
#[test]
fn non_utf8_argv_refuses_with_usage() {
    use std::os::unix::ffi::OsStringExt;
    let out = std::process::Command::new(bin())
        .arg(std::ffi::OsString::from_vec(b"observe\xff".to_vec()))
        .output()
        .expect("spawn binary");
    assert_eq!(out.status.code(), Some(2), "usage refusal, not a panic");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not valid Unicode"), "{stderr:?}");
    assert!(stderr.contains("usage:"), "{stderr:?}");
}

/// R04: a dead stdout exits 1 with a stderr report, never panics
/// (old `println!` exited 101). Smoke prints its subject line before
/// any scenario, so the failure is scenario-independent.
#[test]
fn dead_stdout_exits_1_without_panic() {
    let full = std::fs::File::create("/dev/full").expect("/dev/full opens");
    let out = std::process::Command::new(bin())
        .stdout(full)
        .output()
        .expect("spawn binary");
    assert_eq!(out.status.code(), Some(1), "IO failure, not a panic");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("output write failed"), "{stderr:?}");
}

/// R04: a dead stderr keeps the already-determined usage code (exit
/// 2); the unreportable report is not a second failure.
#[test]
fn dead_stderr_keeps_usage_code() {
    let full = std::fs::File::create("/dev/full").expect("/dev/full opens");
    let out = std::process::Command::new(bin())
        .arg("observe")
        .stderr(full)
        .output()
        .expect("spawn binary");
    assert_eq!(
        out.status.code(),
        Some(2),
        "usage code survives dead stderr"
    );
}

/// R04: both streams dead still exits 1 (the subject line cannot
/// land), never panics.
#[test]
fn both_streams_dead_exits_1() {
    let out = std::process::Command::new(bin())
        .stdout(std::fs::File::create("/dev/full").expect("/dev/full opens"))
        .stderr(std::fs::File::create("/dev/full").expect("/dev/full opens"))
        .output()
        .expect("spawn binary");
    assert_eq!(out.status.code(), Some(1));
}

/// R34: a hostile TMPDIR (delimiter-bearing) refuses before creating
/// anything: the owned parent gains no entries.
#[test]
fn hostile_tmpdir_strands_nothing() {
    let owned = scratch("tmpdir");
    let hostile = owned.join("sub;dir");
    std::fs::create_dir(&hostile).unwrap();
    let out = std::process::Command::new(bin())
        .env("TMPDIR", &hostile)
        .output()
        .expect("spawn binary");
    assert_eq!(out.status.code(), Some(1), "smoke refuses hostile paths");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("';'"), "{stderr:?}");
    let leftovers: Vec<_> = std::fs::read_dir(&hostile).unwrap().collect();
    assert!(leftovers.is_empty(), "stranded fixtures: {leftovers:?}");
    let _ = std::fs::remove_dir_all(&owned);
}

/// R34 control: a clean smoke succeeds and retires its own tree
/// (guards the print-after-close reorder).
#[test]
fn clean_smoke_succeeds_and_cleans_up() {
    let owned = scratch("smoke");
    let out = std::process::Command::new(bin())
        .env("TMPDIR", &owned)
        .output()
        .expect("spawn binary");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("subject: "), "{stdout:?}");
    assert!(stdout.contains("acquire-self: "), "{stdout:?}");
    let leftovers: Vec<_> = std::fs::read_dir(&owned).unwrap().collect();
    assert!(leftovers.is_empty(), "smoke left residue: {leftovers:?}");
    let _ = std::fs::remove_dir_all(&owned);
}
