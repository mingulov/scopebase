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
    script_json_with_id(op, "observe-script")
}

/// R33: same script envelope under an explicit dialect id, so
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
    // S14: roots stage under one process-wide private parent
    // (0700, ours) instead of shared temp. Root names stay unique
    // per test, so parallel tests share the parent safely; the
    // staging dir itself is one empty dir per test-binary run.
    static STAGING: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    let staging = STAGING.get_or_init(|| {
        // Exclusive create, skipping stale names from crashed
        // runs (same pid reused) — never removing anything.
        for n in 0..1024u32 {
            let dir = std::env::temp_dir().join(format!(
                "scopebase-staging-observe-{}-{n}",
                std::process::id()
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                        .expect("staging mode");
                    return dir;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("staging: {error}"),
            }
        }
        panic!("staging names exhausted");
    });
    let name = format!("lx11-observe-{}-{test}", std::process::id());
    FixtureRoot::create(staging, &name).expect("fixture root")
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
fn unknown_op_unsupported_bad_script_invalid_output() {
    // R33: an unknown opcode is a dialect this adapter does not
    // speak: pre-read UnsupportedSchema, not a dispatch refusal.
    let err = run("no-such-op", b"case=self;").expect_err("unknown op unsupported");
    assert_eq!(*err.category(), CaseErrorCategory::UnsupportedSchema);
    assert_eq!(err.stage().as_str(), "adapter-schema");
    // S44: missing/malformed operation data after dialect admission
    // is InvalidOutput with the attempted step, never Refused.
    let err = run("acquire", b"not-a-script").expect_err("bad script invalid");
    assert_eq!(*err.category(), CaseErrorCategory::InvalidOutput);
    assert_eq!(err.stage().as_str(), "admission");
    assert_eq!(err.step_id().as_ref().map(Label::as_str), Some("only-step"));
    let err = run("acquire", b"case=nope;").expect_err("unknown case invalid");
    assert_eq!(*err.category(), CaseErrorCategory::InvalidOutput);
    assert_eq!(err.stage().as_str(), "admission");
    assert_eq!(err.step_id().as_ref().map(Label::as_str), Some("only-step"));
    let err = run("spawn-observe", b"case=child;").expect_err("missing child invalid");
    assert_eq!(*err.category(), CaseErrorCategory::InvalidOutput);
    assert_eq!(err.stage().as_str(), "admission");
    assert_eq!(err.step_id().as_ref().map(Label::as_str), Some("only-step"));
    let err = run("mapping", b"case=empty;").expect_err("missing path invalid");
    assert_eq!(*err.category(), CaseErrorCategory::InvalidOutput);
    assert_eq!(err.stage().as_str(), "admission");
    assert_eq!(err.step_id().as_ref().map(Label::as_str), Some("only-step"));
    let limits = RunLimits::default();
    let inv = invocation(&limits, "acquire-self");
    let fix =
        FixtureAccess::new(&[], &[], EffectBatch::empty(&limits), &limits).expect("empty fixture");
    let err = ObserveReferenceAdapter::new()
        .expect("adapter builds")
        .execute(&inv, &fix)
        .expect_err("missing slot invalid");
    assert_eq!(*err.category(), CaseErrorCategory::InvalidOutput);
    assert_eq!(err.stage().as_str(), "admission");
    assert_eq!(err.step_id().as_ref().map(Label::as_str), Some("only-step"));
}

/// R33: an otherwise-valid invocation under an alien script
/// dialect is pre-read UnsupportedSchema — even with an empty
/// fixture, which proves the dialect admits before any slot is
/// touched (a slot check would refuse missing-slot instead).
#[test]
fn alien_script_dialect_unsupported_before_reads() {
    let limits = RunLimits::default();
    let script = script_json_with_id("acquire-self", "alien-script");
    let inv = invocation_full(
        &limits,
        "observe-reference-v1",
        1,
        "observe-fixture-v1",
        1,
        &script,
    );
    let fix =
        FixtureAccess::new(&[], &[], EffectBatch::empty(&limits), &limits).expect("empty fixture");
    let err = ObserveReferenceAdapter::new()
        .expect("adapter builds")
        .execute(&inv, &fix)
        .expect_err("alien script unsupported");
    assert_eq!(*err.category(), CaseErrorCategory::UnsupportedSchema);
    assert_eq!(err.stage().as_str(), "adapter-schema");
    // Unknown opcodes admit the same way: pre-read, before slots.
    let inv = invocation(&limits, "no-such-op");
    let err = ObserveReferenceAdapter::new()
        .expect("adapter builds")
        .execute(&inv, &fix)
        .expect_err("unknown op unsupported before reads");
    assert_eq!(*err.category(), CaseErrorCategory::UnsupportedSchema);
    assert_eq!(err.stage().as_str(), "adapter-schema");
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

// F26: error diagnostics honor the invocation's own byte ceiling.
#[test]
fn lowered_diagnostic_ceiling_truncates_invalid_output() {
    let limits = lowered(|v| v.diagnostic_bytes = 8);
    let inv = invocation(&limits, "acquire");
    let err = run_with(&limits, &inv, b"case=nope;").expect_err("unknown case invalid");
    assert_eq!(*err.category(), CaseErrorCategory::InvalidOutput);
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

/// S35: a non-UTF-8 TMPDIR refuses with the Unicode message before
/// creating anything: the owned parent gains no entries, and no
/// lossy doppelganger name is ever interpolated.
#[test]
fn non_utf8_tmpdir_refuses_and_strands_nothing() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let owned = scratch("tmpdir-utf8");
    let hostile =
        std::ffi::OsString::from_vec([owned.as_os_str().as_bytes(), b"/sub-\xff-dir"].concat());
    std::fs::create_dir(&hostile).unwrap();
    let out = std::process::Command::new(bin())
        .env("TMPDIR", &hostile)
        .output()
        .expect("spawn binary");
    assert_eq!(out.status.code(), Some(1), "smoke refuses hostile paths");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not valid Unicode"), "{stderr:?}");
    let leftovers: Vec<_> = std::fs::read_dir(&hostile).unwrap().collect();
    assert!(leftovers.is_empty(), "stranded fixtures: {leftovers:?}");
    let _ = std::fs::remove_dir_all(&owned);
}

/// S35: a smoke binary reached beneath a non-UTF-8 directory refuses
/// instead of executing the lossy doppelganger. The copy lives at
/// `<scratch>/dir-\xff/smoke-bin`, so the old lossy conversion named
/// `<scratch>/dir-\u{FFFD}/smoke-bin` — the script planted there
/// writes the canary iff it is ever executed.
#[test]
fn non_utf8_exe_location_executes_nothing() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::PermissionsExt;
    let owned = scratch("exe-utf8");
    let invalid =
        std::ffi::OsString::from_vec([owned.as_os_str().as_bytes(), b"/dir-\xff"].concat());
    std::fs::create_dir(&invalid).unwrap();
    let copied = std::path::Path::new(&invalid).join("smoke-bin");
    std::fs::copy(bin(), &copied).unwrap();
    std::fs::set_permissions(&copied, std::fs::Permissions::from_mode(0o755)).unwrap();
    let doppel_dir = owned.join("dir-\u{FFFD}");
    std::fs::create_dir(&doppel_dir).unwrap();
    let canary = owned.join("canary");
    let script = format!(
        "#!/bin/sh\necho executed > \"{}\"\n",
        canary.to_string_lossy()
    );
    let doppel = doppel_dir.join("smoke-bin");
    std::fs::write(&doppel, script).unwrap();
    std::fs::set_permissions(&doppel, std::fs::Permissions::from_mode(0o755)).unwrap();
    // Sanity: the planted script really is what a lossy conversion
    // of the copy's path would name.
    let lossy = copied.to_string_lossy().into_owned();
    assert_eq!(
        std::path::PathBuf::from(lossy),
        doppel,
        "doppelganger must sit at the lossy name"
    );
    // Invoke through an ASCII symlink: argv stays valid Unicode (so
    // R03 argv admission passes) while current_exe resolves beneath
    // the non-UTF-8 directory — exactly the finding's launch shape.
    let link = owned.join("link-bin");
    std::os::unix::fs::symlink(&copied, &link).unwrap();
    let owned_tmp = owned.join("tmp");
    std::fs::create_dir(&owned_tmp).unwrap();
    let out = std::process::Command::new(&link)
        .env("TMPDIR", &owned_tmp)
        .output()
        .expect("spawn relocated binary");
    assert_eq!(out.status.code(), Some(1), "smoke refuses hostile paths");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not valid Unicode"), "{stderr:?}");
    assert!(!canary.exists(), "doppelganger executable must never run");
    let _ = std::fs::remove_dir_all(&owned);
}
