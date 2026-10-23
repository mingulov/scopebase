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
    // F29: the absent path lives in an exclusively owned root, so no
    // shared-temp file is ever removed to establish absence.
    let absence_root = FixtureRoot::create(
        &std::env::temp_dir(),
        &format!("lx11-conformance-{}-absence", std::process::id()),
    )
    .expect("root");
    let missing = absence_root.path().join("absent.txt");
    assert!(!missing.exists());
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
    absence_root.close().expect("absence cleanup");
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
    // F29: the root sits in an exclusively owned parent holding an
    // out.txt canary. A failed escape guard would overwrite the
    // canary (all these escapes resolve to parent/out.txt); the old
    // test instead asserted on shared temp/out.txt, whose absence
    // depended on unrelated files.
    let parent = FixtureRoot::create(
        &std::env::temp_dir(),
        &format!("lx11-conformance-{}-escape-parent", std::process::id()),
    )
    .expect("parent");
    let canary = parent.write_file("out.txt", b"canary").expect("canary");
    let root = FixtureRoot::create(parent.path(), "escape-root").expect("root");
    assert!(root.write_file("/abs.txt", b"x").is_err());
    assert!(root.write_file("../out.txt", b"x").is_err());
    assert!(root.write_file("sub/../../out.txt", b"x").is_err());
    assert!(root.subdir("..").is_err());
    assert_eq!(
        std::fs::read(&canary).expect("canary reads"),
        b"canary",
        "escape guard failed: parent canary overwritten"
    );
    root.close().expect("cleanup");
    parent.close().expect("parent cleanup");
}

/// F25: symlinks planted inside the root never redirect writes or
/// directory creation outside it. Intermediate links, final links,
/// links through `subdir`, and `subdir` onto a link all refuse with
/// `ELOOP`, and the outside canary tree is untouched. The old
/// lexical join followed every one of these.
#[test]
fn fixture_root_refuses_symlinks_at_every_level() {
    use std::os::unix::fs::symlink;
    let parent = FixtureRoot::create(
        &std::env::temp_dir(),
        &format!("lx11-conformance-{}-symlink-parent", std::process::id()),
    )
    .expect("parent");
    let outside = parent.subdir("outside").expect("outside dir");
    let canary = parent.write_file("outside/canary.txt", b"canary").expect("canary");
    let root = FixtureRoot::create(parent.path(), "link-root").expect("root");

    // Intermediate symlink: linkdir -> ../outside. The DIRECTORY
    // check fires on the unfollowed link (ENOTDIR); NOFOLLOW alone
    // would report ELOOP. Either errno proves refusal without
    // traversal; both are accepted for kernel-version robustness.
    symlink("../outside", root.path().join("linkdir")).expect("plant intermediate link");
    let err = root
        .write_file("linkdir/pwned.txt", b"evil")
        .expect_err("intermediate symlink refuses");
    let eloop = rustix::io::Errno::LOOP.raw_os_error();
    let enotdir = rustix::io::Errno::NOTDIR.raw_os_error();
    assert!(
        err.raw_os_error() == Some(eloop) || err.raw_os_error() == Some(enotdir),
        "want ELOOP or ENOTDIR, saw {err}"
    );
    assert!(
        !outside.join("pwned.txt").exists(),
        "intermediate link wrote outside the root"
    );
    assert!(root.subdir("linkdir/new").is_err(), "subdir through link refuses");

    // Final symlink: link.txt -> ../outside/canary.txt.
    symlink("../outside/canary.txt", root.path().join("link.txt")).expect("plant final link");
    let err = root
        .write_file("link.txt", b"evil")
        .expect_err("final symlink refuses");
    assert_eq!(err.raw_os_error(), Some(rustix::io::Errno::LOOP.raw_os_error()), "want ELOOP, saw {err}");
    assert_eq!(
        std::fs::read(&canary).expect("canary reads"),
        b"canary",
        "final link overwrote the outside canary"
    );

    // Dangling final link under subdir: EEXIST on mkdirat, then the
    // NOFOLLOW verification refuses.
    symlink("nowhere-target", root.path().join("danglink")).expect("plant dangling link");
    assert!(
        root.subdir("danglink").is_err(),
        "subdir onto a symlink refuses"
    );

    // Positive control: real nested paths still work beside the links.
    let file = root.write_file("sub/deep.txt", b"deep").expect("nested write");
    assert_eq!(std::fs::read(&file).expect("read back"), b"deep");
    assert!(root.subdir("sub").is_ok(), "existing dir reuses");
    root.close().expect("cleanup");
    parent.close().expect("parent cleanup");
}
