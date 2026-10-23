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
    format!(
        "{{\"schema_version\":1,\"kind\":\"steps-v1\",\"schema_id\":\"heldfile-script\",\
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
                    id: Label::parse("heldfile-reference-v1").expect("schema"),
                    revision: 1,
                },
                limits,
            )
            .expect("observation schema"),
            fixture_schema: SchemaBinding::new(
                SchemaBindingValues {
                    id: Label::parse("heldfile-fixture-v1").expect("schema"),
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
    let name = format!("lx11-heldfile-{}-{test}", std::process::id());
    FixtureRoot::create(&std::env::temp_dir(), &name).expect("fixture root")
}

fn run(op: &str, script: &[u8], body: Option<&[u8]>) -> Result<Observation, CaseError> {
    let limits = RunLimits::default();
    let inv = invocation(&limits, op);
    let script_input = FixtureInput::new(Label::parse("script").expect("slot"), script);
    let body_input;
    let inputs: &[_] = match body {
        Some(raw) => {
            body_input = FixtureInput::new(Label::parse("body").expect("slot"), raw);
            &[script_input, body_input]
        }
        None => std::slice::from_ref(&script_input),
    };
    let fix = FixtureAccess::new(inputs, &[], EffectBatch::empty(&limits), &limits).expect("fix");
    HeldfileReferenceAdapter::new()
        .expect("adapter builds")
        .execute(&inv, &fix)
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
fn unknown_op_case_and_bad_script_refuse() {
    let err = run("no-such-op", b"case=ok;", None).expect_err("unknown op refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "dispatch");
    let err = run("open", b"not-a-script", None).expect_err("bad script refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
    let err = run("open", b"case=nope;", None).expect_err("unknown case refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
    let err = run("open", b"case=ok;", None).expect_err("missing path refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
    let err = run("parse-maps", b"case=ok;", None).expect_err("missing body refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
    let limits = RunLimits::default();
    let inv = invocation(&limits, "open");
    let fix =
        FixtureAccess::new(&[], &[], EffectBatch::empty(&limits), &limits).expect("empty fixture");
    let err = HeldfileReferenceAdapter::new()
        .expect("adapter builds")
        .execute(&inv, &fix)
        .expect_err("missing slot refuses");
    assert_eq!(*err.category(), CaseErrorCategory::Refused);
    assert_eq!(err.stage().as_str(), "admission");
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
