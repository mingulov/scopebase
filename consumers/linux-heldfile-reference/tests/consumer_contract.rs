// SPDX-License-Identifier: Apache-2.0
//! LX11 consumer contract: held-file inspector reference consumer.
//!
//! Exercises real held-file open/stat, bounded positional reads, strict
//! maps/mountinfo parsing and bounded directory walks through the testkit
//! `ConformanceAdapter` seam. Expected bytes are hand-authored here from the
//! frozen Linux contracts, never derived from implementation output.
//! NEW (LX11): no donor lines copied.
use linux_heldfile_reference::adapter::HeldfileReferenceAdapter;
use scopebase_linux::conformance::FixtureRoot;
use scopebase_testkit::{
    CaseError, CaseErrorCategory, CaseId, CaseInvocation, CaseInvocationValues, CaseKey,
    CaseKeyValues, ConformanceAdapter, EffectBatch, FixtureAccess, FixtureInput, InvocationKey,
    InvocationKeyValues, Label, Observation, OperationScript, RunId, RunLimits, SchemaBinding,
    SchemaBindingValues,
};

const MAPS_TWO: &[u8] = b"1000-1800 r--p 0000 0b:02 91 /fixtures/alpha\n\
                             1800-2400 r-xp 0800 0b:02 91 /fixtures/alpha\n";
const MAPS_BAD: &[u8] = b"1000-1800 r--p 0000 0b:02 91 /fixtures/alpha\n\
                            1800-2400 r-xp 0800 0b:02 91 /fixtures/alpha\n\
                            broken\n";
const MOUNTS_TWO: &[u8] = b"17 1 0:42 / /mnt rw - fuse.demo source rw\n\
                              18 1 0:43 / /merged rw - overlay overlay rw,lowerdir=/lower\n";
const MOUNTS_BAD: &[u8] = b"17 1 0:42 / /mnt rw - fuse.demo source rw\n\
                              18 1 0:43 / /merged rw - overlay overlay rw,lowerdir=/lower\n\
                              broken\n";

fn script_json(op: &str) -> Vec<u8> {
    script_json_with_id(op, "heldfile-script")
}

/// R33: same script envelope under an explicit dialect id, so
/// alien-script negatives stay otherwise valid.
fn script_json_with_id(op: &str, schema_id: &str) -> Vec<u8> {
    // F27: declared inputs must cover exactly the slots the adapter
    // consumes; parse operations additionally consume the body slot.
    let inputs = if op == "parse-maps" || op == "parse-mountinfo" {
        "[\"script\",\"body\"]"
    } else {
        "[\"script\"]"
    };
    format!(
        "{{\"schema_version\":1,\"kind\":\"steps-v1\",\"schema_id\":\"{schema_id}\",\
         \"steps\":[{{\"step_id\":\"only-step\",\"operation\":\"{op}\",\
         \"inputs\":{inputs},\"parameters\":[]}}]}}"
    )
    .into_bytes()
}

fn invocation(limits: &RunLimits, op: &str) -> CaseInvocation {
    invocation_full(
        limits,
        "heldfile-reference-v1",
        1,
        "heldfile-fixture-v1",
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
                    case_id: CaseId::parse("LX11.heldfile-contract").expect("case id"),
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
                "scopebase-staging-heldfile-{}-{n}",
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
    let name = format!("lx11-heldfile-{}-{test}", std::process::id());
    FixtureRoot::create(staging, &name).expect("fixture root")
}

fn run(op: &str, script: &[u8], body: Option<&[u8]>) -> Result<Observation, CaseError> {
    let limits = RunLimits::default();
    let inv = invocation(&limits, op);
    run_with(&limits, &inv, script, body)
}

fn run_with(
    limits: &RunLimits,
    inv: &CaseInvocation,
    script: &[u8],
    body: Option<&[u8]>,
) -> Result<Observation, CaseError> {
    let script_input = FixtureInput::new(Label::parse("script").expect("slot"), script);
    let body_input;
    let inputs: &[_] = match body {
        Some(raw) => {
            body_input = FixtureInput::new(Label::parse("body").expect("slot"), raw);
            &[script_input, body_input]
        }
        None => std::slice::from_ref(&script_input),
    };
    let fix = FixtureAccess::new(inputs, &[], EffectBatch::empty(limits), limits).expect("fix");
    HeldfileReferenceAdapter::new()
        .expect("adapter builds")
        .execute(inv, &fix)
}

fn text(obs: &Observation) -> &str {
    std::str::from_utf8(obs.bytes()).expect("ascii observation")
}

fn check_envelope(obs: &Observation) {
    assert_eq!(obs.schema_id().as_str(), "heldfile-reference-v1");
    assert_eq!(*obs.schema_revision(), 1);
    let steps: Vec<&str> = obs.completed_steps().iter().map(|s| s.as_str()).collect();
    assert_eq!(steps, vec!["only-step"]);
}

#[test]
fn open_stat_tracks_held_file() {
    let root = owned_root("open-ok");
    let file = root.write_file("a.txt", b"hello world").expect("fixture");
    let script = format!("case=ok;path={};", file.display());
    let obs = run("open", script.as_bytes(), None).expect("open executes");
    check_envelope(&obs);
    assert_eq!(text(&obs), "stat=len:11;");
    root.close().expect("cleanup");
}

#[test]
fn open_refusals_stay_typed() {
    let root = owned_root("open-bad");
    let missing = root.path().join("absent.txt");
    let script = format!("case=missing;path={};", missing.display());
    let obs = run("open", script.as_bytes(), None).expect("executes");
    assert_eq!(text(&obs), "refuse=AcquirePath:Disappeared;");
    let dir = root.path().to_string_lossy().into_owned();
    let script = format!("case=dir;path={dir};");
    let obs = run("open", script.as_bytes(), None).expect("executes");
    assert_eq!(text(&obs), "refuse=ValidateFile:NonRegular;");
    let target = root.write_file("real.txt", b"hello world").expect("target");
    let link = root.path().join("link.txt");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let script = format!("case=symlink;path={};", link.display());
    let obs = run("open", script.as_bytes(), None).expect("executes");
    // O_PATH|NOFOLLOW opens the link itself, so the type gate (not ELOOP)
    // refuses; a followed link would have reported stat=len:11 instead.
    assert_eq!(text(&obs), "refuse=ValidateFile:NonRegular;");
    root.close().expect("cleanup");
}

#[test]
fn positional_read_counts_calls() {
    let root = owned_root("read-ok");
    let file = root.write_file("a.txt", b"hello world").expect("fixture");
    let script = format!("case=ok;path={};", file.display());
    let obs = run("read", script.as_bytes(), None).expect("read executes");
    check_envelope(&obs);
    assert_eq!(text(&obs), "bytes=11;calls=2;");
    let empty = root.write_file("empty.txt", b"").expect("empty");
    let script = format!("case=empty;path={};", empty.display());
    let obs = run("read", script.as_bytes(), None).expect("read executes");
    assert_eq!(text(&obs), "bytes=0;calls=1;");
    root.close().expect("cleanup");
}

#[test]
fn read_limits_and_cancellation_refuse() {
    let root = owned_root("read-bad");
    let file = root.write_file("a.txt", b"hello world").expect("fixture");
    let script = format!("case=tiny;path={};", file.display());
    let obs = run("read", script.as_bytes(), None).expect("executes");
    assert_eq!(text(&obs), "refuse=ReadFile:LimitExceeded(InputBytes);");
    let script = format!("case=cancelled;path={};", file.display());
    let obs = run("read", script.as_bytes(), None).expect("executes");
    assert_eq!(text(&obs), "refuse=ReadFile:Cancelled;");
    root.close().expect("cleanup");
}

#[test]
fn maps_parse_lookup_and_whole_refusal() {
    let obs = run("parse-maps", b"case=ok;", Some(MAPS_TWO)).expect("executes");
    check_envelope(&obs);
    assert_eq!(text(&obs), "entries=2;containing=true;");
    let obs = run("parse-maps", b"case=live;", Some(MAPS_TWO)).expect("executes");
    assert_eq!(text(&obs), "entries=2;");
    let obs = run("parse-maps", b"case=bad;", Some(MAPS_BAD)).expect("executes");
    assert_eq!(text(&obs), "refuse=ParseMaps:Malformed:line=3;");
}

#[test]
fn mountinfo_parse_and_whole_refusal() {
    let obs = run("parse-mountinfo", b"case=ok;", Some(MOUNTS_TWO)).expect("executes");
    check_envelope(&obs);
    assert_eq!(text(&obs), "entries=2;first=/mnt;");
    let obs = run("parse-mountinfo", b"case=bad;", Some(MOUNTS_BAD)).expect("executes");
    assert_eq!(text(&obs), "refuse=ParseMounts:Malformed:line=3;");
}

#[test]
fn walk_lists_sorted_tree_then_done() {
    let root = owned_root("walk-ok");
    root.write_file("a.txt", b"a").expect("a");
    root.write_file("sub/b.txt", b"b").expect("b");
    let dir = root.path().to_string_lossy().into_owned();
    let script = format!("case=ok;root={dir};");
    let obs = run("walk", script.as_bytes(), None).expect("walk executes");
    check_envelope(&obs);
    assert_eq!(text(&obs), "entries=a.txt,sub,sub/b.txt;done=true;");
    root.close().expect("cleanup");
}

#[test]
fn walk_tight_and_missing_refuse() {
    let root = owned_root("walk-bad");
    root.write_file("a.txt", b"a").expect("a");
    root.write_file("sub/b.txt", b"b").expect("b");
    let dir = root.path().to_string_lossy().into_owned();
    let script = format!("case=tight;root={dir};");
    let obs = run("walk", script.as_bytes(), None).expect("executes");
    assert_eq!(text(&obs), "refuse=WalkDirectory:LimitExceeded(Entries);");
    let missing = root.path().join("absent-dir");
    let script = format!("case=missing;root={};", missing.display());
    let obs = run("walk", script.as_bytes(), None).expect("executes");
    assert_eq!(text(&obs), "refuse=WalkDirectory:Disappeared;");
    root.close().expect("cleanup");
}

#[test]
fn unknown_op_unsupported_bad_script_invalid_output() {
    // R33: an unknown opcode is a dialect this adapter does not
    // speak: pre-read UnsupportedSchema, not a dispatch refusal.
    let err = run("no-such-op", b"case=ok;", None).expect_err("unknown op unsupported");
    assert_eq!(*err.category(), CaseErrorCategory::UnsupportedSchema);
    assert_eq!(err.stage().as_str(), "adapter-schema");
    // S44: missing/malformed operation data after dialect admission
    // is InvalidOutput with the attempted step, never Refused.
    let err = run("open", b"not-a-script", None).expect_err("bad script invalid");
    assert_eq!(*err.category(), CaseErrorCategory::InvalidOutput);
    assert_eq!(err.stage().as_str(), "admission");
    assert_eq!(err.step_id().as_ref().map(Label::as_str), Some("only-step"));
    let err = run("open", b"case=nope;", None).expect_err("unknown case invalid");
    assert_eq!(*err.category(), CaseErrorCategory::InvalidOutput);
    assert_eq!(err.stage().as_str(), "admission");
    assert_eq!(err.step_id().as_ref().map(Label::as_str), Some("only-step"));
    let err = run("open", b"case=ok;", None).expect_err("missing path invalid");
    assert_eq!(*err.category(), CaseErrorCategory::InvalidOutput);
    assert_eq!(err.stage().as_str(), "admission");
    assert_eq!(err.step_id().as_ref().map(Label::as_str), Some("only-step"));
    let err = run("parse-maps", b"case=ok;", None).expect_err("missing body invalid");
    assert_eq!(*err.category(), CaseErrorCategory::InvalidOutput);
    assert_eq!(err.stage().as_str(), "admission");
    assert_eq!(err.step_id().as_ref().map(Label::as_str), Some("only-step"));
    let limits = RunLimits::default();
    let inv = invocation(&limits, "open");
    let fix =
        FixtureAccess::new(&[], &[], EffectBatch::empty(&limits), &limits).expect("empty fixture");
    let err = HeldfileReferenceAdapter::new()
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
    let script = script_json_with_id("open", "alien-script");
    let inv = invocation_full(
        &limits,
        "heldfile-reference-v1",
        1,
        "heldfile-fixture-v1",
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
                    b"case=ok;",
                )],
                &[],
                EffectBatch::empty(&limits),
                &limits,
            )
            .expect("full fixture"),
        ),
    ] {
        let err = HeldfileReferenceAdapter::new()
            .expect("adapter builds")
            .execute(&inv, fix)
            .expect_err(&format!("alien script unsupported ({name})"));
        assert_eq!(*err.category(), CaseErrorCategory::UnsupportedSchema);
        assert_eq!(err.stage().as_str(), "adapter-schema");
    }
    // Unknown opcodes admit the same way: pre-read, before slots.
    let inv = invocation(&limits, "no-such-op");
    let err = HeldfileReferenceAdapter::new()
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
        "{{\"schema_version\":1,\"kind\":\"steps-v1\",\"schema_id\":\"heldfile-script\",\
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

// F27: an alien observation schema rejects before effects. The script
// below names a real file and would succeed without the preflight.
#[test]
fn alien_observation_schema_rejects_before_effects() {
    let root = owned_root("alien-obs");
    root.write_file("real.txt", b"eleven bytes").expect("file");
    let path = root.path().join("real.txt");
    let path = path.to_string_lossy().into_owned();
    let limits = RunLimits::default();
    let inv = invocation_full(
        &limits,
        "alien-schema-v9",
        1,
        "heldfile-fixture-v1",
        1,
        &script_json("open"),
    );
    let script = format!("case=ok;path={path};");
    let err = run_with(&limits, &inv, script.as_bytes(), None).expect_err("alien schema rejects");
    check_unsupported(&err);
    root.close().expect("cleanup");
}

// F27: alien fixture schema and revision mismatches reject too.
#[test]
fn alien_fixture_schema_or_revision_rejects() {
    let limits = RunLimits::default();
    for (obs, obs_rev, fix, fix_rev) in [
        ("heldfile-reference-v1", 1, "alien-fixture-v9", 1),
        ("heldfile-reference-v1", 2, "heldfile-fixture-v1", 1),
        ("heldfile-reference-v1", 1, "heldfile-fixture-v1", 2),
    ] {
        let inv = invocation_full(&limits, obs, obs_rev, fix, fix_rev, &script_json("open"));
        let err = run_with(&limits, &inv, b"case=ok;", None).expect_err("alien envelope rejects");
        check_unsupported(&err);
    }
}

// F27: multi-step scripts reject; the old first-step dispatch would
// have executed the leading valid step instead.
#[test]
fn multi_step_script_rejects() {
    let limits = RunLimits::default();
    let steps = vec![
        step_json("first", "open", "[\"script\"]", "[]"),
        step_json("second", "open", "[\"script\"]", "[]"),
    ];
    let inv = invocation_full(
        &limits,
        "heldfile-reference-v1",
        1,
        "heldfile-fixture-v1",
        1,
        &script_steps_json(&steps),
    );
    let err = run_with(&limits, &inv, b"case=ok;", None).expect_err("multi-step rejects");
    check_unsupported(&err);
    // An empty step list is unconstructible: OperationScript::load
    // rejects it ("empty script"), so the adapter's zero-step arm is
    // defensive only and has no loader-built test.
}

// F27: step parameters and wrong declared-input sets reject. The
// parse-maps row carries a body slot, so only the declaration is wrong.
#[test]
fn parameters_and_input_shape_reject() {
    let limits = RunLimits::default();
    let with_params = script_steps_json(&[step_json(
        "only-step",
        "open",
        "[\"script\"]",
        "[{\"kind\":\"u64\",\"value\":\"7\"}]",
    )]);
    let inv = invocation_full(
        &limits,
        "heldfile-reference-v1",
        1,
        "heldfile-fixture-v1",
        1,
        &with_params,
    );
    let err = run_with(&limits, &inv, b"case=ok;", None).expect_err("parameters reject");
    check_unsupported(&err);

    for (op, inputs, body) in [
        ("open", "[]", None),
        ("open", "[\"script\",\"body\"]", None),
        ("open", "[\"body\"]", None),
        ("parse-maps", "[\"script\"]", Some(MAPS_TWO)),
    ] {
        let json = script_steps_json(&[step_json("only-step", op, inputs, "[]")]);
        let inv = invocation_full(
            &limits,
            "heldfile-reference-v1",
            1,
            "heldfile-fixture-v1",
            1,
            &json,
        );
        let err = run_with(&limits, &inv, b"case=ok;", body).expect_err("shape rejects");
        check_unsupported(&err);
    }
}

// RB4 (R07): the observation honors the invocation's own byte ceiling
// by refusing, never by truncating. The open/stat body is 12 bytes; a
// ceiling of 4 refuses at collect with the full diagnostic.
#[test]
fn lowered_observation_ceiling_refuses_at_collect() {
    let root = owned_root("low-obs");
    root.write_file("real.txt", b"eleven bytes").expect("file");
    let path = root.path().join("real.txt");
    let path = path.to_string_lossy().into_owned();
    let limits = lowered(|v| v.observation_bytes = 4);
    let inv = invocation(&limits, "open");
    let script = format!("case=ok;path={path};");
    let err = run_with(&limits, &inv, script.as_bytes(), None).expect_err("over-ceiling refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "collect");
    root.close().expect("cleanup");
}

// RB4 (R07): exact-fit twin. A ceiling of exactly 12 delivers the whole
// 12-byte body; the refusal above is about the ceiling, not the case.
#[test]
fn exact_observation_ceiling_completes_whole() {
    let root = owned_root("exact-obs");
    root.write_file("real.txt", b"eleven bytes").expect("file");
    let path = root.path().join("real.txt");
    let path = path.to_string_lossy().into_owned();
    let limits = lowered(|v| v.observation_bytes = 12);
    let inv = invocation(&limits, "open");
    let script = format!("case=ok;path={path};");
    let obs = run_with(&limits, &inv, script.as_bytes(), None).expect("exact fit completes");
    assert_eq!(obs.bytes(), b"stat=len:12;");
    root.close().expect("cleanup");
}

// F26: error diagnostics honor the invocation's own byte ceiling.
#[test]
fn lowered_diagnostic_ceiling_truncates_invalid_output() {
    let limits = lowered(|v| v.diagnostic_bytes = 8);
    let inv = invocation(&limits, "open");
    let err = run_with(&limits, &inv, b"case=nope;", None).expect_err("unknown case invalid");
    assert_eq!(*err.category(), CaseErrorCategory::InvalidOutput);
    assert_eq!(err.diagnostic_bytes().len(), 8);
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
    // builders (15-byte "heldfile-script") cannot load here; every
    // label in this script fits the 6-byte ceiling by hand.
    let json = format!(
        "{{\"schema_version\":1,\"kind\":\"steps-v1\",\"schema_id\":\"s\",\
         \"steps\":[{{\"step_id\":\"s\",\"operation\":\"open\",\
         \"inputs\":[\"script\"],\"parameters\":[]}}]}}",
    )
    .into_bytes();
    let inv = invocation_full(&limits, "o-v1", 1, "f-v1", 1, &json);
    let err = run_with(&limits, &inv, b"case=ok;", None).expect_err("alien schema refuses");
    assert_eq!(*err.category(), CaseErrorCategory::UnsupportedSchema);
    assert_eq!(err.stage().as_str(), "adapte");
    assert_eq!(err.cause().method().as_str(), "execut");
    assert!(err.step_id().is_none(), "dialect rejection names no step");
}

#[test]
fn subject_names_resolved_consumer() {
    let subject = HeldfileReferenceAdapter::new()
        .expect("adapter builds")
        .subject();
    assert_eq!(subject.package_name(), "linux-heldfile-reference");
    assert_eq!(subject.package_version(), "0.1.0");
    assert_eq!(subject.consumer().name(), "heldfile-adapter");
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
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_linux-heldfile-reference"))
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
        .arg(std::ffi::OsString::from_vec(b"inspect\xff".to_vec()))
        .output()
        .expect("spawn binary");
    assert_eq!(out.status.code(), Some(2), "usage refusal, not a panic");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not valid Unicode"), "{stderr:?}");
    assert!(stderr.contains("usage:"), "{stderr:?}");
}

/// R04: a dead stdout exits 1 with a stderr report, never panics
/// (old `println!` exited 101). Smoke prints its subject line before
/// any scenario, so the failure is scenario-independent; exiting
/// there also precedes fixture creation, so nothing strands.
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
        .arg("inspect")
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
/// anything: the owned parent gains no entries. Old code created the
/// root and its files, then stranded them on the `;` refusal.
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
/// (guards the print-after-close reorder: same output, owned parent
/// empty afterwards).
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
    assert!(stdout.contains("open: stat=len:11;"), "{stdout:?}");
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
