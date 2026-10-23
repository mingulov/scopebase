// SPDX-License-Identifier: Apache-2.0
//! Developer conformance vocabulary tests. NEW (LX11): no donor lines copied.
use super::*;
use crate::{
    control::OperationControl,
    file::{HeldFile, ProcFdResolver, SymlinkPolicy},
    procfs::{parse_maps, ParseLimits},
};

#[test]
fn ledger_renders_exact_sequence() {
    let mut ledger = ExpectedLedger::new();
    assert!(ledger.is_empty());
    assert_eq!(ledger.len(), 0);
    assert_eq!(ledger.render(), "");
    ledger.record("stat", "len:11");
    ledger.record("bytes", "11");
    assert!(!ledger.is_empty());
    assert_eq!(ledger.len(), 2);
    assert_eq!(ledger.render(), "stat=len:11;bytes=11;");
}

#[test]
fn refusal_encodes_stage_reason_and_line() {
    let resolver = ProcFdResolver::open_self().expect("self resolver");
    let missing = std::env::temp_dir().join("lx11-conformance-absent.txt");
    let _ = std::fs::remove_file(&missing);
    let error = HeldFile::open(&missing, &resolver, SymlinkPolicy::RejectFinal)
        .expect_err("missing file refuses");
    assert_eq!(refusal_of(&error), "refuse=AcquirePath:Disappeared;");
    let limits = ParseLimits {
        max_bytes: 1024,
        max_entries: 16,
        max_line_bytes: 256,
    };
    let error = parse_maps(b"1000-1800 r--p 0000 0b:02 91 /a\nbroken\n", limits)
        .expect_err("bad row refuses");
    assert_eq!(refusal_of(&error), "refuse=ParseMaps:Malformed:line=2;");
    let token = crate::control::CancelToken::new();
    token.cancel();
    let control = OperationControl::new(None, token);
    let root = FixtureRoot::create(
        &std::env::temp_dir(),
        &format!("lx11-conformance-{}-cancel", std::process::id()),
    )
    .expect("root");
    let file = root.write_file("a.txt", b"hello world").expect("file");
    let held = HeldFile::open(&file, &resolver, SymlinkPolicy::RejectFinal).expect("held");
    let error = held
        .read_all(
            crate::file::ReadLimits {
                max_bytes: 1024,
                max_read_calls: 16,
                max_buffer_capacity: 1024,
            },
            &control,
        )
        .expect_err("cancelled read refuses");
    assert_eq!(refusal_of(&error), "refuse=ReadFile:Cancelled;");
    root.close().expect("cleanup");
}

#[test]
fn fixture_root_owns_tree_and_cleans_up() {
    let name = format!("lx11-conformance-{}-tree", std::process::id());
    let root = FixtureRoot::create(&std::env::temp_dir(), &name).expect("root");
    assert!(root.path().is_dir());
    let file = root.write_file("sub/b.txt", b"second").expect("nested");
    assert_eq!(std::fs::read(&file).expect("read back"), b"second");
    assert!(file.starts_with(root.path()));
    let dir = root.subdir("sub").expect("subdir");
    assert!(dir.is_dir());
    let kept = root.path().to_path_buf();
    root.close().expect("close removes tree");
    assert!(!kept.exists());
}

#[test]
fn fixture_root_rejects_escapes() {
    assert!(FixtureRoot::create(&std::env::temp_dir(), "").is_err());
    assert!(FixtureRoot::create(&std::env::temp_dir(), "..").is_err());
    assert!(FixtureRoot::create(&std::env::temp_dir(), "a/b").is_err());
    assert!(FixtureRoot::create(&std::env::temp_dir(), "/abs").is_err());
    let name = format!("lx11-conformance-{}-escape", std::process::id());
    let root = FixtureRoot::create(&std::env::temp_dir(), &name).expect("root");
    assert!(root.write_file("/abs.txt", b"x").is_err());
    assert!(root.write_file("../out.txt", b"x").is_err());
    assert!(root.write_file("sub/../../out.txt", b"x").is_err());
    assert!(root.subdir("..").is_err());
    assert!(!std::env::temp_dir().join("out.txt").exists());
    root.close().expect("cleanup");
}
