// SPDX-License-Identifier: Apache-2.0
// Standalone maps-only client. Literal inventory/address oracle, no procfs I/O.
use scopebase_linux::{
    error::{Reason, Stage},
    procfs::{parse_maps, MapsPathKind, ParseLimits},
};
const L: ParseLimits = ParseLimits {
    max_bytes: 4096,
    max_entries: 64,
    max_line_bytes: 512,
};
fn main() {
    let s = parse_maps(include_bytes!("fixtures/maps_valid.bin"), L).unwrap();
    assert_eq!(s.len(), 6);
    assert_eq!(
        s.entries().filter(|e| e.permissions()[2] == b'x').count(),
        4
    );
    for (a, expected) in [
        (0x1000, Some(0x20)),
        (0x17ff, Some(0x81f)),
        (0x1800, Some(0x40)),
        (0x2400, Some(0x60)),
        (0x2800, None),
    ] {
        assert_eq!(s.containing(a).and_then(|e| e.file_offset_at(a)), expected);
    }
    let first = s.entries().next().unwrap();
    assert_eq!(
        (
            first.file_key().device_major(),
            first.file_key().device_minor(),
            first.file_key().inode()
        ),
        (11, 2, 91)
    );
    assert_eq!(first.raw_path(), Some(b"/alpha".as_slice()));
    assert_eq!(
        s.entries().nth(3).unwrap().path_kind(),
        MapsPathKind::Absent
    );
    assert_eq!(s.entries().nth(4).unwrap().path_kind(), MapsPathKind::Other);
    let raw = s.entries().next_back().unwrap();
    assert_eq!(raw.raw_path(), Some(b"/raw-\xff\\012 (deleted)".as_slice()));
    assert!(raw.path_evidence().has_deleted_suffix());
    assert!(raw.path_evidence().has_escaped_newline());
    assert!(!raw.path_evidence().is_utf8());
    let e = parse_maps(include_bytes!("fixtures/maps_invalid.bin"), L).unwrap_err();
    assert_eq!(e.parse_line(), Some(4));
    assert_eq!(e.charges().parse().unwrap().entries_validated(), 3);
    let a3_good = include_bytes!("fixtures/maps_a3_valid.bin");
    let a3_bad = include_bytes!("fixtures/maps_a3_invalid.bin");
    assert_eq!(
        a3_good.as_slice(),
        b"1000-1800 r--p 0000 0b:02 91 /fixtures/alpha\n\
          1800-2400 r-xp 0800 0b:02 91 /fixtures/alpha\n\
          2400-2800 rw-p 1400 0b:02 91 /fixtures/alpha\n"
    );
    assert_eq!(
        a3_bad.as_slice(),
        [a3_good.as_slice(), b"broken\n"].concat()
    );
    let a3 = parse_maps(a3_good, L).unwrap();
    assert_eq!(a3.len(), 3);
    for (entry, expected) in a3.entries().zip([
        (0x1000, 0x1800, *b"r--p", 0),
        (0x1800, 0x2400, *b"r-xp", 0x800),
        (0x2400, 0x2800, *b"rw-p", 0x1400),
    ]) {
        assert_eq!(
            (
                entry.start(),
                entry.end(),
                entry.permissions(),
                entry.file_offset()
            ),
            expected
        );
        assert_eq!(
            (
                entry.file_key().device_major(),
                entry.file_key().device_minor(),
                entry.file_key().inode()
            ),
            (11, 2, 91)
        );
        assert_eq!(entry.raw_path(), Some(b"/fixtures/alpha".as_slice()));
    }
    for (address, expected) in [
        (0x1000, Some(0)),
        (0x17ff, Some(0x7ff)),
        (0x1800, Some(0x800)),
        (0x23ff, Some(0x13ff)),
        (0x2400, Some(0x1400)),
        (0x27ff, Some(0x17ff)),
        (0x2800, None),
    ] {
        assert_eq!(
            a3.containing(address)
                .and_then(|e| e.file_offset_at(address)),
            expected
        );
    }
    assert!(
        parse_maps(a3_bad, L).is_err(),
        "A3 whole-input refusal after valid prefix"
    );
    let e = parse_maps(a3_bad, L).unwrap_err();
    assert_eq!(
        (e.stage(), e.reason(), e.parse_line()),
        (Stage::ParseMaps, Reason::Malformed, Some(4))
    );
    assert_eq!(e.charges().parse().unwrap().entries_validated(), 3);
    assert_eq!(
        (
            e.effect().attempted_operations(),
            e.effect().completed_operations()
        ),
        (0, 0)
    );
    assert_eq!(
        (
            e.charges().syscall_attempts(),
            e.charges().fd_acquisitions(),
            e.charges().peak_new_fds()
        ),
        (0, 0, 0)
    );
    println!("maps_inventory: 6 generic regions, exact A3 3-region prefix and whole-input refusal passed");
}
