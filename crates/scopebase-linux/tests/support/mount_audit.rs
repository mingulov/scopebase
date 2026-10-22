// SPDX-License-Identifier: Apache-2.0
// Standalone mount-only client. Distinct raw/decoded/ID-table audit.
use scopebase_linux::procfs::{parse_mountinfo, MountOptionalKind, ParseLimits};
const L: ParseLimits = ParseLimits {
    max_bytes: 4096,
    max_entries: 64,
    max_line_bytes: 512,
};
fn main() {
    let t = parse_mountinfo(include_bytes!("fixtures/mountinfo_valid.bin"), L).unwrap();
    assert_eq!(
        t.entries().map(|e| e.id().number()).collect::<Vec<_>>(),
        [17, 18, 19, 2]
    );
    let first = t.entry_by_number(17).unwrap();
    assert_eq!((first.device().major(), first.device().minor()), (0, 42));
    assert_eq!(first.filesystem_type().raw(), b"fuse.demo\\043tag");
    assert_eq!(first.filesystem_type().decoded(), b"fuse.demo#tag");
    assert_eq!(first.source().decoded(), b"source#tag");
    let optional: Vec<_> = first.optional_fields().collect();
    assert_eq!(optional[0].kind(), MountOptionalKind::Shared(7));
    assert_eq!(optional[1].field().raw(), b"x:\\377");
    assert_eq!(optional[1].field().decoded(), b"x:\xff");
    assert_eq!(
        t.entry_by_number(18).unwrap().super_options().decoded(),
        b"rw,lowerdir=/lower,part"
    );
    assert_eq!(
        t.entry_by_number(19).unwrap().super_options().decoded(),
        b"rw,key=part=value"
    );
    let e = t.entry_by_number(2).unwrap();
    assert_eq!(e.root().decoded(), b"/root dir");
    assert_eq!(e.mount_point().decoded(), b"/mount\tpoint");
    assert_eq!(e.source().decoded(), b"\\043");
    assert_eq!(e.id(), e.parent_id());
    assert_eq!(
        e.optional_fields().map(|f| f.kind()).collect::<Vec<_>>(),
        [
            MountOptionalKind::Master(3),
            MountOptionalKind::PropagateFrom(4),
            MountOptionalKind::Unbindable,
            MountOptionalKind::Unknown
        ]
    );
    let other = parse_mountinfo(b"17 1 9:2 / /other rw - ext4 /dev/b rw\n", L).unwrap();
    let o = other.entry_by_number(17).unwrap();
    assert_ne!(first.id(), o.id());
    assert_eq!((o.device().major(), o.device().minor()), (9, 2));
    assert!(t.entry_by_number(9999).is_none());
    let bad = parse_mountinfo(include_bytes!("fixtures/mountinfo_invalid.bin"), L).unwrap_err();
    assert_eq!(bad.parse_line(), Some(4));
    assert_eq!(bad.charges().parse().unwrap().entries_validated(), 4);
    for spelling in ["\\000", "\\400", "\\777", "\\099", "\\04", "\\"] {
        let input = format!("23 1 0:1 / / rw - fs {spelling} rw\n");
        assert!(parse_mountinfo(input.as_bytes(), L).is_err());
    }
    println!("mount_audit: 4 rows; A1 escapes, A2 duplicate line, scoped IDs and raw/decoded assertions passed");
}
