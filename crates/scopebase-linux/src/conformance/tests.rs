// SPDX-License-Identifier: Apache-2.0
//! Developer conformance vocabulary tests. NEW (LX11): no donor lines copied.
use super::*;
use crate::{
    control::OperationControl,
    file::{HeldFile, ProcFdResolver, SymlinkPolicy},
    procfs::{parse_maps, ParseLimits},
};
use std::sync::atomic::{AtomicU64, Ordering};

/// S14: private staging for roots under test. Exclusive by
/// construction: we create it (exclusive `create_dir`, skipping
/// stale names from crashed runs — never removing anything we did
/// not just create), we own it, mode 0700. Pair with
/// `drop_staging`, whose empty-only removal fails loudly on
/// stranded residue instead of hiding it.
fn staging(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    for _ in 0..1024 {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("lx11-staging-{}-{tag}-{n}", std::process::id()));
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
}

fn drop_staging(dir: &Path) {
    std::fs::remove_dir(dir).expect("staging drops empty");
}

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
    let absence_stage = staging("absence");
    let absence_root = FixtureRoot::create(
        &absence_stage,
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
    let cancel_stage = staging("cancel");
    let root = FixtureRoot::create(
        &cancel_stage,
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
    drop_staging(&cancel_stage);
    absence_root.close().expect("absence cleanup");
    drop_staging(&absence_stage);
}

#[test]
fn fixture_root_owns_tree_and_cleans_up() {
    let name = format!("lx11-conformance-{}-tree", std::process::id());
    let stage = staging("tree");
    let root = FixtureRoot::create(&stage, &name).expect("root");
    assert!(root.path().is_dir());
    let file = root.write_file("sub/b.txt", b"second").expect("nested");
    assert_eq!(std::fs::read(&file).expect("read back"), b"second");
    assert!(file.starts_with(root.path()));
    let dir = root.subdir("sub").expect("subdir");
    assert!(dir.is_dir());
    let kept = root.path().to_path_buf();
    root.close().expect("close removes tree");
    assert!(!kept.exists());
    drop_staging(&stage);
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
    let stage = staging("escape");
    let parent = FixtureRoot::create(
        &stage,
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
    drop_staging(&stage);
}

/// F25: symlinks planted inside the root never redirect writes or
/// directory creation outside it. Intermediate links, final links,
/// links through `subdir`, and `subdir` onto a link all refuse with
/// `ELOOP`, and the outside canary tree is untouched. The old
/// lexical join followed every one of these.
#[test]
fn fixture_root_refuses_symlinks_at_every_level() {
    use std::os::unix::fs::symlink;
    let stage = staging("symlink");
    let parent = FixtureRoot::create(
        &stage,
        &format!("lx11-conformance-{}-symlink-parent", std::process::id()),
    )
    .expect("parent");
    let outside = parent.subdir("outside").expect("outside dir");
    let canary = parent
        .write_file("outside/canary.txt", b"canary")
        .expect("canary");
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
    assert!(
        root.subdir("linkdir/new").is_err(),
        "subdir through link refuses"
    );

    // Final symlink: link.txt -> ../outside/canary.txt.
    symlink("../outside/canary.txt", root.path().join("link.txt")).expect("plant final link");
    let err = root
        .write_file("link.txt", b"evil")
        .expect_err("final symlink refuses");
    assert_eq!(
        err.raw_os_error(),
        Some(rustix::io::Errno::LOOP.raw_os_error()),
        "want ELOOP, saw {err}"
    );
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
    let file = root
        .write_file("sub/deep.txt", b"deep")
        .expect("nested write");
    assert_eq!(std::fs::read(&file).expect("read back"), b"deep");
    assert!(root.subdir("sub").is_ok(), "existing dir reuses");
    root.close().expect("cleanup");
    parent.close().expect("parent cleanup");
    drop_staging(&stage);
}

/// R14: replacing an ancestor redirects neither writes nor cleanup.
/// The root is created under grand/a; grand/a is then renamed away
/// and a FRESH grand/a/root planted. Writes must land in the moved
/// original, and close must retire it while the plant stands.
#[test]
fn fixture_root_survives_ancestor_replacement() {
    let grand = staging("anc");
    let old = grand.join("a");
    let moved = grand.join("b");
    std::fs::create_dir(&old).expect("grand/a");
    // The ancestor is a create-parent: pin exclusive modes rather
    // than inheriting the ambient umask.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o755)).expect("old mode");
    }
    let root = FixtureRoot::create(&old, "root").expect("root");
    root.write_file("before.txt", b"before")
        .expect("pre-move write");
    std::fs::rename(&old, &moved).expect("rename ancestor away");
    // Attacker's fresh tree at the advisory path.
    std::fs::create_dir_all(old.join("root")).expect("plant fresh root");
    std::fs::write(old.join("root").join("plant.txt"), b"plant").expect("plant canary");

    let file = root
        .write_file("after.txt", b"after")
        .expect("post-move write");
    assert!(
        !old.join("root").join("after.txt").exists(),
        "write landed in the planted ancestor tree"
    );
    assert_eq!(
        std::fs::read(moved.join("root").join("after.txt")).expect("read moved"),
        b"after",
        "write did not stay with the pinned root"
    );
    assert_eq!(
        std::fs::read(moved.join("root").join("before.txt")).expect("read moved old"),
        b"before"
    );
    drop(file);
    root.close().expect("close retires the pinned original");
    assert!(!moved.join("root").exists(), "pinned original not retired");
    assert_eq!(
        std::fs::read(old.join("root").join("plant.txt")).expect("plant reads"),
        b"plant",
        "close deleted the planted replacement"
    );
    std::fs::remove_dir_all(&grand).expect("grand cleanup");
}

/// R14: swapping another directory in at the root path is refused by
/// close: the replacement (with its canary) stands and close reports
/// an error instead of deleting it.
#[test]
fn fixture_root_close_refuses_root_replacement() {
    let base = staging("swap");
    let root = FixtureRoot::create(&base, "root").expect("root");
    root.write_file("owned.txt", b"owned").expect("owned write");
    std::fs::rename(base.join("root"), base.join("orig")).expect("move original away");
    // Attacker's replacement: non-empty, so even a path-based rmdir
    // could not take it — but close must refuse by IDENTITY, before
    // any unlink attempt.
    std::fs::create_dir(base.join("root")).expect("plant replacement");
    std::fs::write(base.join("root").join("canary.txt"), b"canary").expect("plant canary");

    let err = root.close().expect_err("close refuses the replacement");
    assert_eq!(
        std::fs::read(base.join("root").join("canary.txt")).expect("canary reads"),
        b"canary",
        "close deleted the replacement: {err}"
    );
    assert!(
        err.to_string().contains("replaced"),
        "unexpected error: {err}"
    );
    // Our original tree was cleared (we own it) but its name stands —
    // the unlink never ran against the wrong inode.
    assert!(base.join("orig").is_dir(), "original dir entry vanished");
    std::fs::remove_dir_all(&base).expect("base cleanup");
}

/// R14: an EMPTY directory planted at the root path is likewise
/// refused — the pre-unlink identity check fires before the name is
/// removed, so the plant survives and the error names replacement.
#[test]
fn fixture_root_close_refuses_empty_replacement() {
    let base = staging("empty");
    let root = FixtureRoot::create(&base, "root").expect("root");
    std::fs::rename(base.join("root"), base.join("orig")).expect("move original away");
    std::fs::create_dir(base.join("root")).expect("plant empty replacement");

    let err = root.close().expect_err("close refuses the empty plant");
    assert!(base.join("root").is_dir(), "empty plant was unlinked");
    assert!(
        err.to_string().contains("replaced"),
        "unexpected error: {err}"
    );
    std::fs::remove_dir_all(&base).expect("base cleanup");
}

/// R14: `clear_dir` unlinks symlinks (even ones pointing at
/// directories) instead of following them: the outside canary tree
/// survives close.
#[test]
fn fixture_root_close_unlinks_symlinks_without_following() {
    use std::os::unix::fs::symlink;
    let base = staging("links");
    std::fs::create_dir(base.join("outside")).expect("outside");
    std::fs::write(base.join("outside").join("canary.txt"), b"canary").expect("canary");
    let root = FixtureRoot::create(&base, "root").expect("root");
    root.write_file("sub/deep.txt", b"deep").expect("nested");
    symlink("../outside/canary.txt", base.join("root").join("file-link")).expect("plant file link");
    symlink("../outside", base.join("root").join("dir-link")).expect("plant dir link");
    root.close().expect("close clears links");
    assert!(!base.join("root").exists(), "root not retired");
    assert_eq!(
        std::fs::read(base.join("outside").join("canary.txt")).expect("canary reads"),
        b"canary",
        "close followed a symlink out of the root"
    );
    std::fs::remove_dir_all(&base).expect("base cleanup");
}

/// S14/D1: shared parents refuse. A world-writable or
/// group-writable parent admits a foreign swapper into both the
/// mkdir/open acquisition window and the verify/unlink destruction
/// window, so creation refuses with `PermissionDenied` and names
/// the private-0700 staging remedy. (Foreign OWNERSHIP also
/// refuses, by the same check, but no unprivileged test can
/// fabricate another owner's directory.)
#[test]
fn fixture_root_refuses_shared_parents() {
    use std::os::unix::fs::PermissionsExt;
    let stage = staging("shared");
    for (tag, mode) in [("world", 0o777), ("group", 0o770)] {
        let shared = stage.join(tag);
        std::fs::create_dir(&shared).expect("shared dir");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(mode))
            .expect("shared mode");
        let err = FixtureRoot::create(&shared, "root").expect_err("shared parent refuses");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "{tag}: wrong kind: {err}"
        );
        assert!(
            err.to_string().contains("0700"),
            "{tag}: remedy unnamed: {err}"
        );
        assert!(!shared.join("root").exists(), "{tag}: refusal left residue");
        std::fs::remove_dir(&shared).expect("shared cleanup");
    }
    drop_staging(&stage);
}

/// S14/D2: fresh roots nest. Creation pins 0755 regardless of
/// ambient umask, so a root can parent another root three deep;
/// closing inside-out retires every level.
#[test]
fn fixture_root_nests_three_deep() {
    let stage = staging("nest");
    let outer = FixtureRoot::create(&stage, "outer").expect("outer");
    let middle = FixtureRoot::create(outer.path(), "middle").expect("middle");
    let inner = FixtureRoot::create(middle.path(), "inner").expect("inner");
    inner.write_file("deep.txt", b"deep").expect("deep write");
    assert_eq!(
        std::fs::read(middle.path().join("inner").join("deep.txt")).expect("deep read"),
        b"deep"
    );
    let kept = outer.path().to_path_buf();
    inner.close().expect("inner close");
    middle.close().expect("middle close");
    outer.close().expect("outer close");
    assert!(!kept.exists(), "nested tree not retired");
    drop_staging(&stage);
}

/// S13/D5: the nested unlink proof fires on multi-linked entries.
/// A hardlink planted inside the root would survive any single
/// unlink, so close refuses loudly instead of reporting "removed"
/// over a surviving inode. (Pre-proof code returned `Ok` here,
/// unlinking both names across two visits.)
#[test]
fn fixture_root_close_refuses_hardlinked_entry() {
    let stage = staging("hardlink");
    let root = FixtureRoot::create(&stage, "root").expect("root");
    let first = root.write_file("a.txt", b"linked").expect("write");
    std::fs::hard_link(&first, stage.join("root").join("b.txt")).expect("plant hardlink");
    let err = root.close().expect_err("close refuses the surviving inode");
    assert!(
        err.to_string().contains("replaced during removal"),
        "unexpected error: {err}"
    );
    // The refused close unlinked at most the first-visited name
    // (readdir order is unspecified); the inode itself survives
    // under the other name — that survival is exactly what the
    // proof reports.
    let a = stage.join("root").join("a.txt");
    let b = stage.join("root").join("b.txt");
    let survivor = [a.as_path(), b.as_path()]
        .into_iter()
        .filter_map(|p| std::fs::read(p).ok())
        .find(|bytes| bytes == b"linked");
    assert!(
        survivor.is_some(),
        "refused close destroyed the inode it claimed survived"
    );
    // Manual retirement: remove whichever names remain, then the dir.
    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);
    std::fs::remove_dir(stage.join("root")).expect("remove root");
    drop_staging(&stage);
}

/// S48: transactional acquisition. `open_created` removes the
/// name when the follow-up open fails, so a failed acquisition
/// strands nothing. With stable modes a just-created root always
/// opens (any parent permitting `mkdirat` also permits the
/// lookup), so production reaches the cleanup only on a mid-call
/// mode change or a resource fault; this test pins a
/// directory-shape refusal through the same branch to prove the
/// removal runs and the ORIGINAL error — not a cleanup wrapper
/// — reports.
#[test]
fn fixture_root_create_cleans_up_after_open_failure() {
    use rustix::fs::{AtFlags, Mode, OFlags};
    use std::os::unix::fs::symlink;
    let stage = staging("txcreate");
    symlink("dangling-target", stage.join("link")).expect("plant link");
    let parent_fd = rustix::fs::open(
        &stage,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("parent fd");
    let name = CString::new("link").expect("cstr");
    // `O_DIRECTORY | O_NOFOLLOW` on a symlink refuses with
    // `ENOTDIR` (the directory shape is checked first).
    let err = open_created(&parent_fd, &name, AtFlags::empty()).expect_err("symlink refuses");
    assert_eq!(
        err.raw_os_error(),
        Some(rustix::io::Errno::NOTDIR.raw_os_error()),
        "want ENOTDIR, saw {err}"
    );
    assert!(
        !err.to_string().contains("cleanup"),
        "clean removal must not wrap the error: {err}"
    );
    assert!(
        !stage.join("link").exists() && std::fs::symlink_metadata(stage.join("link")).is_err(),
        "failed acquisition stranded the name"
    );
    drop_staging(&stage);
}
