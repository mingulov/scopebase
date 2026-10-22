// SPDX-License-Identifier: Apache-2.0
// P selected regressions: LX05-S07..S11,S16,S18; Apache destination under OWNER grant.
// Each literal expectation predates the parser; see frozen LX05 preservation map.
use scopebase_linux::{
    error::{CleanupDisposition, DescriptorFlagEffect, LimitKind, Reason, Stage},
    procfs::*,
};
#[path = "support/proc_reference.rs"]
mod reference;
const L: ParseLimits = ParseLimits {
    max_bytes: 4096,
    max_entries: 64,
    max_line_bytes: 512,
};
const SORTED: &[u8] = b"00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/dbus-daemon\n7f2b40000000-7f2b40021000 r-xp 00021000 08:01 999 /opt/with space/lib.so\n7f2b50000000-7f2b50001000 r--p 00002000 08:01 998 /usr/lib/gone.so (deleted)\n7f8a1c000000-7f8a1c021000 rw-p 00000000 00:00 0\n7ffc55555000-7ffc55576000 rw-p 00000000 00:00 0 [stack]\n";
const ONE: &[u8] = b"1000-2000 r-xp 0000 08:01 7 /opt/provider.so\n";
const MOUNT: &[u8] = b"17 1 8:1 / /a rw - ext4 /dev/a rw\n";
fn bad_maps(b: &[u8], line: usize, valid: usize) {
    let e = parse_maps(b, L).unwrap_err();
    assert_eq!(e.reason(), Reason::Malformed);
    assert_eq!(e.parse_line(), Some(line));
    assert_eq!(e.charges().parse().unwrap().entries_validated(), valid);
}
fn bad_mount(b: &[u8], line: usize, valid: usize) {
    let e = parse_mountinfo(b, L).unwrap_err();
    assert_eq!(e.reason(), Reason::Malformed);
    assert_eq!(e.parse_line(), Some(line));
    assert_eq!(e.charges().parse().unwrap().entries_validated(), valid);
}
#[test]
fn ported_parses_entries_and_preserves_path_bytes() {
    let s = parse_maps(SORTED, L).unwrap();
    assert_eq!(s.len(), 5);
    let rows = [
        (
            0x400000,
            0x452000,
            0,
            *b"r-xp",
            8,
            2,
            173521,
            Some(b"/usr/bin/dbus-daemon".as_slice()),
        ),
        (
            0x7f2b40000000,
            0x7f2b40021000,
            0x21000,
            *b"r-xp",
            8,
            1,
            999,
            Some(b"/opt/with space/lib.so".as_slice()),
        ),
        (
            0x7f2b50000000,
            0x7f2b50001000,
            0x2000,
            *b"r--p",
            8,
            1,
            998,
            Some(b"/usr/lib/gone.so (deleted)".as_slice()),
        ),
        (0x7f8a1c000000, 0x7f8a1c021000, 0, *b"rw-p", 0, 0, 0, None),
        (
            0x7ffc55555000,
            0x7ffc55576000,
            0,
            *b"rw-p",
            0,
            0,
            0,
            Some(b"[stack]".as_slice()),
        ),
    ];
    for (e, w) in s.entries().zip(rows) {
        assert_eq!(
            (
                e.start(),
                e.end(),
                e.file_offset(),
                e.permissions(),
                e.file_key().device_major(),
                e.file_key().device_minor(),
                e.file_key().inode(),
                e.raw_path()
            ),
            w
        );
    }
    let unsorted=b"00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/dbus-daemon\n7f8a1c000000-7f8a1c021000 rw-p 00000000 00:00 0\n7ffc55555000-7ffc55576000 rw-p 00000000 00:00 0 [stack]\n7f2b40000000-7f2b40021000 r-xp 00021000 08:01 999 /opt/with space/lib.so\n7f2b50000000-7f2b50001000 r--p 00002000 08:01 998 /usr/lib/gone.so (deleted)\n";
    bad_maps(unsorted, 4, 3);
}
#[test]
fn ported_resolves_with_segment_offset_arithmetic() {
    let s = parse_maps(SORTED, L).unwrap();
    for (a, o, p, i, path) in [
        (
            0x7f2b40000abc,
            0x21abc,
            1,
            999,
            b"/opt/with space/lib.so".as_slice(),
        ),
        (
            0x400010,
            0x10,
            2,
            173521,
            b"/usr/bin/dbus-daemon".as_slice(),
        ),
    ] {
        let e = s.containing(a).unwrap();
        assert_eq!(e.file_offset_at(a), Some(o));
        assert_eq!(e.file_key().device_minor(), p);
        assert_eq!(e.file_key().inode(), i);
        assert_eq!(e.raw_path(), Some(path));
        assert_eq!(e.permissions(), *b"r-xp");
    }
}
#[test]
fn ported_classifies_anonymous_and_unmapped() {
    let s = parse_maps(SORTED, L).unwrap();
    assert_eq!(
        s.containing(0x7f8a1c000500).unwrap().path_kind(),
        MapsPathKind::Absent
    );
    assert_eq!(
        s.containing(0x7ffc55555100).unwrap().raw_path(),
        Some(b"[stack]".as_slice())
    );
    assert!(s.containing(1).is_none());
    assert!(s.containing(0x452000).is_none());
}
#[test]
fn ported_unusable_file_paths_remain_file_evidence() {
    let s=parse_maps(b"1000-2000 r-xp 0000 08:01 1 /tmp/nonutf8-\xff.so\n2000-3000 r-xp 0000 08:01 2 /tmp/literal\\012name.so\n3000-4000 r-xp 0000 08:01 3 /tmp/gone.so (deleted)\n",L).unwrap();
    for (e, (raw, utf8, escape, deleted)) in s.entries().zip([
        (b"/tmp/nonutf8-\xff.so".as_slice(), false, false, false),
        (b"/tmp/literal\\012name.so", true, true, false),
        (b"/tmp/gone.so (deleted)", true, false, true),
    ]) {
        assert_eq!(e.path_kind(), MapsPathKind::Absolute);
        assert_eq!(e.raw_path(), Some(raw));
        let p = e.path_evidence();
        assert_eq!(
            (p.is_utf8(), p.has_escaped_newline(), p.has_deleted_suffix()),
            (utf8, escape, deleted)
        );
    }
}
#[test]
fn ported_malformed_nonempty_line_is_rejected() {
    bad_maps(b"not a maps line\n", 1, 0);
    let mut b = ONE.to_vec();
    b.extend(b"not a maps line\n");
    bad_maps(&b, 2, 1);
}
#[test]
fn ported_map_index_requires_sorted_non_overlapping_intervals() {
    for b in [
        b"3000-4000 r-xp 0 0:0 0\n1000-2000 r-xp 0 0:0 0\n".as_slice(),
        b"1000-3000 r-xp 0 0:0 0\n2000-4000 r-xp 0 0:0 0\n",
        b"1000-2000 r-xp 0 0:0 0\n1000-3000 r-xp 0 0:0 0\n",
    ] {
        bad_maps(b, 2, 1);
    }
    for b in [
        b"1000-1000 r-xp 0 0:0 0\n".as_slice(),
        b"2000-1000 r-xp 0 0:0 0\n",
    ] {
        bad_maps(b, 1, 0);
    }
    let mut rows: Vec<_> = SORTED.split_inclusive(|b| *b == b'\n').collect();
    rows.swap(0, 1);
    bad_maps(&rows.concat(), 2, 1);
}
#[test]
fn ported_invalid_snapshot_is_distinguishable_from_valid_absence() {
    let good = b"1000-2000 r-xp 0 08:01 7 /opt/provider.so\n3000-4000 rw-p 0 00:00 0\n";
    let s = parse_maps(good, L).unwrap();
    assert!(s.containing(0x1000).is_some());
    assert!(s.containing(0x9000).is_none());
    let mut bad = good.to_vec();
    bad.extend(b"3800-4800 rw-p 0 00:00 0\n");
    bad_maps(&bad, 3, 2);
}
#[test]
fn ported_map_index_rejects_file_offset_overflow() {
    bad_maps(
        b"1000-1002 r-xp ffffffffffffffff 08:01 7 /opt/provider.so\n",
        1,
        0,
    );
    let s = parse_maps(
        b"1000-1002 r-xp fffffffffffffffe 08:01 7 /opt/provider.so\n",
        L,
    )
    .unwrap();
    assert_eq!(
        s.containing(0x1001).unwrap().file_offset_at(0x1001),
        Some(u64::MAX)
    );
    assert!(parse_maps(
        b"1000-1001 r-xp ffffffffffffffff 08:01 7 /opt/provider.so\n",
        L
    )
    .is_ok());
}
#[test]
fn ported_map_index_resolves_gaps_adjacency_and_exclusive_ends() {
    let s=parse_maps(b"1000-2000 r-xp 0 08:02 173521 /usr/bin/dbus-daemon\n2000-3000 r-xp 0 08:02 173521 /usr/bin/dbus-daemon\n4000-5000 r-xp 0 08:02 173521 /usr/bin/dbus-daemon\n",L).unwrap();
    for (a, w) in [
        (0x1000, Some(0x1000)),
        (0x1fff, Some(0x1000)),
        (0x2000, Some(0x2000)),
        (0x3000, None),
        (0x3fff, None),
        (0x4000, Some(0x4000)),
        (0x5000, None),
    ] {
        assert_eq!(s.containing(a).map(|e| e.start()), w);
    }
}
#[test]
fn ported_probed_maps_line_parses_hex_devices_and_decimal_inodes() {
    for(b,w)in[(b"7fb053667000-7fb05367c000 r--p 00000000 00:15 712355 /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so\n".as_slice(),(0,21,712355)),(b"1000-2000 r--p 00000000 0A:fF 42 /lib/x.so\n",(10,255,42))]{let s=parse_maps(b,L).unwrap();let k=s.entries().next().unwrap().file_key();assert_eq!((k.device_major(),k.device_minor(),k.inode()),w);}
}
#[test]
fn ported_probed_maps_line_matches_only_its_own_range() {
    let s = parse_maps(b"1000-2000 r--p 00000000 00:15 7 /lib/x.so\n", L).unwrap();
    for (a, w) in [
        (0x1000, true),
        (0x1fff, true),
        (0x2000, false),
        (0xfff, false),
        (0x3000, false),
    ] {
        assert_eq!(s.containing(a).is_some(), w);
    }
}
#[test]
fn ported_malformed_probed_maps_lines_fail_closed() {
    for b in [
        b"\n".as_slice(),
        b"1000-2000 r--p 00000000\n",
        b"1000-2000 r--p 00000000 00:15\n",
        b"1000_2000 r--p 00000000 00:15 7\n",
        b"zz-2000 r--p 00000000 00:15 7\n",
        b"2000-1000 r--p 00000000 00:15 7\n",
        b"1000-1000 r--p 00000000 00:15 7\n",
        b"1000-2000 r--p 00000000 0015 7\n",
        b"1000-2000 r--p 00000000 00:zz 7\n",
        b"1000-2000 r--p 00000000 00:15 xx\n",
        b"1000-2000 r--p 00000000 00:15 0x10\n",
        b"1000-2000 r--p 00000000 00:15 18446744073709551616\n",
    ] {
        bad_maps(b, 1, 0);
    }
    assert!(parse_maps(b"", L).unwrap().is_empty());
}
#[test]
fn table_local_numbers_preserve_device() {
    let a = parse_mountinfo(MOUNT, L).unwrap();
    let b = parse_mountinfo(b"17 1 9:2 / /b rw - ext4 /dev/b rw\n", L).unwrap();
    let x = a.entry_by_number(17).unwrap();
    let y = b.entry_by_number(17).unwrap();
    assert_eq!((x.device().major(), x.device().minor()), (8, 1));
    assert_eq!((y.device().major(), y.device().minor()), (9, 2));
    assert_eq!(x.id(), a.entries().next().unwrap().id());
    assert_ne!(x.id(), y.id());
    assert_eq!(x.parent_id().number(), 1);
    assert!(a.entry_by_number(0).is_none());
    assert!(a.entry_by_number(999999).is_none());
    let identical = parse_mountinfo(MOUNT, L).unwrap();
    assert_ne!(x.id(), identical.entry_by_number(17).unwrap().id());
}
#[test]
fn limits_exact_boundaries() {
    for mounts in [false, true] {
        let b = if mounts { MOUNT } else { ONE };
        let parse = |b: &[u8], l| {
            if mounts {
                parse_mountinfo(b, l).map(|s| s.charges())
            } else {
                parse_maps(b, l).map(|s| s.charges())
            }
        };
        let exact = ParseLimits {
            max_bytes: b.len(),
            max_entries: 1,
            max_line_bytes: b.len() - 1,
        };
        assert_eq!(parse(b, exact).unwrap().entries_validated(), 1);
        for (l, k, line) in [
            (
                ParseLimits {
                    max_bytes: b.len() - 1,
                    ..exact
                },
                LimitKind::InputBytes,
                None,
            ),
            (
                ParseLimits {
                    max_line_bytes: b.len() - 2,
                    ..exact
                },
                LimitKind::LineBytes,
                Some(1),
            ),
        ] {
            let e = parse(b, l).unwrap_err();
            assert_eq!(e.reason(), Reason::LimitExceeded(k));
            assert_eq!(e.parse_line(), line);
            assert_eq!(e.charges().parse().unwrap().allocation_attempts(), 0);
        }
        let two = [b, b].concat();
        let e = parse(
            &two,
            ParseLimits {
                max_bytes: two.len(),
                ..exact
            },
        )
        .unwrap_err();
        assert_eq!(e.reason(), Reason::LimitExceeded(LimitKind::Entries));
        assert_eq!(e.parse_line(), Some(2));
        for l in [
            ParseLimits { max_bytes: 0, ..L },
            ParseLimits {
                max_entries: 0,
                ..L
            },
            ParseLimits {
                max_line_bytes: 0,
                ..L
            },
        ] {
            let e = parse(b, l).unwrap_err();
            assert_eq!(e.reason(), Reason::InvalidInput);
            assert_eq!(e.charges().parse().unwrap().input_bytes(), b.len());
        }
        assert!(parse(
            b,
            ParseLimits {
                max_bytes: usize::MAX,
                max_entries: usize::MAX,
                max_line_bytes: usize::MAX
            }
        )
        .is_ok());
    }
}
#[test]
fn complete_absence_and_unterminated_are_distinct() {
    for b in [b"\n".as_slice(), b" \n", b"\t\n", b"\r\n"] {
        bad_maps(b, 1, 0);
        bad_mount(b, 1, 0);
    }
    for b in [ONE, MOUNT] {
        let tail = &b[..b.len() - 1];
        if b == ONE {
            bad_maps(tail, 1, 0)
        } else {
            bad_mount(tail, 1, 0)
        }
    }
    assert_eq!(
        parse_maps(b"", L).unwrap().charges().allocation_attempts(),
        0
    );
    assert_eq!(
        parse_mountinfo(b"", L)
            .unwrap()
            .charges()
            .allocation_attempts(),
        0
    );
}
#[test]
fn numeric_grammar_and_full_range_overflow() {
    for b in [
        b"+1000-2000 r-xp 0 0:0 0\n".as_slice(),
        b"1000-2000 r-xp +0 0:0 0\n",
        b"1000-2000 r-xp 0 +0:0 0\n",
        b"1000-2000 r-xp 0 0:0 +0\n",
        b"1000-2000 r-xp 0 0:0 18446744073709551616\n",
        b"1000-2000 r-xp 10000000000000000 0:0 0\n",
        b"1000-1002 r-xp ffffffffffffffff 0:0 0\n",
        b"1000-1002 r-xp ffffffffffffffff 0:0 0 [stack]\n",
    ] {
        bad_maps(b, 1, 0);
    }
    for b in [
        b"0 1 0:0 / / rw - x x x\n".as_slice(),
        b"1 0 0:0 / / rw - x x x\n",
        b"+1 1 0:0 / / rw - x x x\n",
        b"1 1 0:0 / / rw shared:0 - x x x\n",
        b"1 1 0:0 / / rw shared:+1 - x x x\n",
        b"18446744073709551616 1 0:0 / / rw - x x x\n",
    ] {
        bad_mount(b, 1, 0);
    }
    let s=parse_maps(b"fffffffffffffffe-ffffffffffffffff r-xs ffffffffffffffff ffffffffffffffff:ffffffffffffffff 18446744073709551615\n",L).unwrap();
    assert_eq!(s.entries().next().unwrap().file_key().inode(), u64::MAX);
    let t=parse_mountinfo(b"18446744073709551615 18446744073709551615 18446744073709551615:18446744073709551615 / / rw shared:18446744073709551615 - x x x\n",L).unwrap();
    assert_eq!(t.entries().next().unwrap().id().number(), u64::MAX);
}
#[test]
fn mount_escapes_are_single_pass_raw_and_decoded() {
    let b=b"17 1 0:42 / /mnt rw - fuse.demo\\043tag source\\043tag rw\n18 1 0:43 / /merged rw - overlay overlay rw,lowerdir=/lower\\054part\n19 1 0:44 / /mnt rw - tmpfs none rw,key\\075part=value\n";
    let t = parse_mountinfo(b, L).unwrap();
    let e = t.entries().next().unwrap();
    assert_eq!(e.filesystem_type().raw(), b"fuse.demo\\043tag");
    assert_eq!(e.filesystem_type().decoded(), b"fuse.demo#tag");
    assert_eq!(e.source().decoded(), b"source#tag");
    assert_eq!(
        t.entries().nth(1).unwrap().super_options().decoded(),
        b"rw,lowerdir=/lower,part"
    );
    assert_eq!(
        t.entries().nth(2).unwrap().super_options().decoded(),
        b"rw,key=part=value"
    );
    for (raw, decoded) in [
        (b"\\001".as_slice(), b"\x01".as_slice()),
        (b"\\011", b"\t"),
        (b"\\012", b"\n"),
        (b"\\040", b" "),
        (b"\\043", b"#"),
        (b"\\054", b","),
        (b"\\075", b"="),
        (b"\\134", b"\\"),
        (b"\\377", b"\xff"),
        (b"\\134043", b"\\043"),
        (b"\\134040", b"\\040"),
        (b"\\0437", b"#7"),
    ] {
        for slot in 0..8 {
            let mut fields: Vec<Vec<u8>> = [
                b"/".as_slice(),
                b"/",
                b"rw",
                b"x:a",
                b"y:b",
                b"fs",
                b"source",
                b"super",
            ]
            .iter()
            .map(|s| s.to_vec())
            .collect();
            let prefix = if slot < 2 {
                b"/".as_slice()
            } else if slot == 3 || slot == 4 {
                b"x:".as_slice()
            } else {
                b"".as_slice()
            };
            fields[slot] = [prefix, raw].concat();
            let row = [
                b"23 1 0:1 ".as_slice(),
                &fields[0],
                b" ",
                &fields[1],
                b" ",
                &fields[2],
                b" ",
                &fields[3],
                b" ",
                &fields[4],
                b" - ",
                &fields[5],
                b" ",
                &fields[6],
                b" ",
                &fields[7],
                b"\n",
            ]
            .concat();
            let t = parse_mountinfo(&row, L).unwrap();
            let e = t.entries().next().unwrap();
            let got = match slot {
                0 => e.root(),
                1 => e.mount_point(),
                2 => e.mount_options(),
                3 => e.optional_fields().next().unwrap().field(),
                4 => e.optional_fields().nth(1).unwrap().field(),
                5 => e.filesystem_type(),
                6 => e.source(),
                _ => e.super_options(),
            };
            assert_eq!(got.raw(), [prefix, raw].concat());
            assert_eq!(got.decoded(), [prefix, decoded].concat());
            assert_eq!(reference::decode(got.raw()).unwrap(), got.decoded());
        }
    }
    for raw in [
        b"\\000".as_slice(),
        b"\\400",
        b"\\777",
        b"\\099",
        b"\\04",
        b"\\",
    ] {
        let row = [b"23 1 0:1 / / rw - fs ".as_slice(), raw, b" rw\n"].concat();
        bad_mount(&row, 1, 0);
        bad_mount(&[MOUNT, &row].concat(), 2, 1);
    }
}
#[test]
fn mount_optional_known_unknown_and_fixed_tail() {
    let s=parse_mountinfo(b"17 17 0:1 / / rw shared:2 master:3 propagate_from:4 unbindable xyz xyz x:\\377 - fs - rw\n",L).unwrap();
    let e = s.entries().next().unwrap();
    assert_eq!(e.source().decoded(), b"-");
    let kinds: Vec<_> = e.optional_fields().map(|f| f.kind()).collect();
    assert_eq!(
        kinds,
        vec![
            MountOptionalKind::Shared(2),
            MountOptionalKind::Master(3),
            MountOptionalKind::PropagateFrom(4),
            MountOptionalKind::Unbindable,
            MountOptionalKind::Unknown,
            MountOptionalKind::Unknown,
            MountOptionalKind::Unknown
        ]
    );
    for optional in [
        "shared",
        "master",
        "propagate_from",
        "shared:",
        "shared:1:2",
        "unbindable:x",
        "shared:1 shared:01",
        "shared:1 sh\\141red:2",
        "master:1 master:2",
        "propagate_from:1 propagate_from:2",
        "unbindable unbindable",
    ] {
        bad_mount(
            format!("17 1 0:1 / / rw {optional} - fs s rw\n").as_bytes(),
            1,
            0,
        );
    }
    for b in [
        b"17 1 0:1 / / rw - fs s\n".as_slice(),
        b"17 1 0:1 / / rw - fs s rw extra\n",
        b"17 1 0:1 / / rw - - fs s rw\n",
        b"17 1 0:1 / / rw fs s rw\n",
        b" 17 1 0:1 / / rw - fs s rw\n",
        b"17 1 0:1 / / rw - fs s rw \n",
        b"17\t1 0:1 / / rw - fs s rw\n",
        b"17 1 0:1 relative / rw - fs s rw\n",
    ] {
        bad_mount(b, 1, 0);
    }
    assert!(parse_mountinfo(b"17 99 0:1 / / rw - - - -\n", L).is_ok());
}
#[test]
fn mount_duplicate_ids_and_input_order() {
    for (ids, line, count) in [("9,17,017,9", 4, 4), ("17,2,017,3,0017", 3, 5)] {
        let row = ids
            .split(',')
            .map(|id| format!("{id} 1 0:42 / /m rw - tmpfs none rw\n"))
            .collect::<String>();
        bad_mount(row.as_bytes(), line, count);
        let nums: Vec<_> = ids
            .split(',')
            .map(|id| id.parse::<u64>().unwrap())
            .collect();
        assert_eq!(reference::duplicate_line(&nums), Some(line));
    }
    for nums in [vec![9, 17, 18, 10], vec![17, 2, 18, 3, 19]] {
        let b = nums
            .iter()
            .map(|id| format!("{id} 1 0:42 / /m rw - tmpfs none rw\n"))
            .collect::<String>();
        let t = parse_mountinfo(b.as_bytes(), L).unwrap();
        assert_eq!(
            t.entries().map(|e| e.id().number()).collect::<Vec<_>>(),
            nums
        );
        for n in nums {
            assert_eq!(t.entry_by_number(n).unwrap().id().number(), n);
        }
    }
}
#[test]
fn maps_path_evidence_is_not_resolution() {
    for (raw, kind, deleted, escape) in [
        (b"/a  \t\r".as_slice(), MapsPathKind::Absolute, false, false),
        (b"[stack]", MapsPathKind::Other, false, false),
        (b"relative\\999", MapsPathKind::Other, false, false),
        (b"/literal (deleted)", MapsPathKind::Absolute, true, false),
        (b"/literal (deleted) ", MapsPathKind::Absolute, false, false),
        (b"/x\\012", MapsPathKind::Absolute, false, true),
        (b"/\xff", MapsPathKind::Absolute, false, false),
    ] {
        let b = [b"1-2 r-xp 0 0:0 0 \t ".as_slice(), raw, b"\n"].concat();
        let s = parse_maps(&b, L).unwrap();
        let e = s.entries().next().unwrap();
        assert_eq!(e.raw_path(), Some(raw));
        assert_eq!(e.path_kind(), kind);
        assert_eq!(e.path_evidence().has_deleted_suffix(), deleted);
        assert_eq!(e.path_evidence().has_escaped_newline(), escape);
    }
    let s = parse_maps(b"1-2 ---- 0 0:0 0\n", L);
    assert!(s.is_err());
    let s = parse_maps(b" \t1-2 ---s 0 0:0 0 \t\n", L).unwrap();
    let e = s.entries().next().unwrap();
    assert_eq!(e.raw_path(), None);
    assert!(e.path_evidence().is_utf8());
}
#[test]
fn all_parser_errors_are_effect_free_and_bounded() {
    for e in [
        parse_maps(b"malicious-\xff-SECRET\n", L).unwrap_err(),
        parse_mountinfo(b"malicious-\xff-SECRET\n", L).unwrap_err(),
        parse_maps(ONE, ParseLimits { max_bytes: 1, ..L }).unwrap_err(),
    ] {
        assert!(matches!(e.stage(), Stage::ParseMaps | Stage::ParseMounts));
        assert!(e.source().is_none());
        assert_eq!(
            (
                e.effect().attempted_operations(),
                e.effect().completed_operations(),
                e.effect().target_mappings_created(),
                e.effect().target_mappings_retired()
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(e.effect().cleanup(), CleanupDisposition::NotNeeded);
        assert_eq!(
            e.effect().descriptor_flags(),
            DescriptorFlagEffect::NotAttempted
        );
        assert_eq!(
            (
                e.charges().syscall_attempts(),
                e.charges().fd_acquisitions(),
                e.charges().peak_new_fds()
            ),
            (0, 0, 0)
        );
        assert!(e.charges().read().is_none());
        assert!(e.charges().parse().is_some());
        for s in [format!("{e}"), format!("{e:?}"), format!("{e:#?}")] {
            assert!(s.len() <= 256);
            assert!(s.bytes().all(|b| (32..127).contains(&b)));
            assert!(!s.contains("SECRET"));
        }
    }
}
#[test]
fn parser_public_domain_and_ownership_refusals() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<MapsSnapshot>();
    send_sync::<MountTableSnapshot>();
    let a = parse_maps(ONE, L).unwrap();
    let e = a.entries().next().unwrap();
    assert_eq!(format!("{e:?}"), "MapsEntry");
    let b = parse_mountinfo(MOUNT, L).unwrap();
    assert_eq!(
        format!("{:?}", b.entries().next().unwrap().id()),
        "ParsedMountId"
    ); /* Exact downstream UI diagnostics are run by the delivered helper. */
}
#[test]
fn reference_population_generated_independently() {
    let good=b"1000-1800 r-xp 20 0b:02 91 /alpha\n1800-2400 rw-p 40 0b:02 91 /alpha\n2400-2800 r--s 60 0b:02 91 /alpha\n";
    let expected = reference::maps(good, L).unwrap();
    let s = parse_maps(good, L).unwrap();
    assert_eq!(s.len(), expected.len());
    for (e, w) in s.entries().zip(&expected) {
        assert_eq!(
            (
                e.start(),
                e.end(),
                e.file_offset(),
                e.file_key().device_major(),
                e.file_key().device_minor(),
                e.file_key().inode()
            ),
            (w.start, w.end, w.offset, w.major, w.minor, w.inode)
        );
    }
    for (a, w) in [
        (0x1000, Some(0x20)),
        (0x17ff, Some(0x81f)),
        (0x1800, Some(0x40)),
        (0x2400, Some(0x60)),
        (0x2800, None),
    ] {
        assert_eq!(s.containing(a).and_then(|e| e.file_offset_at(a)), w);
        assert_eq!(reference::offset_at(&expected, a), w);
    }
    for b in [
        b"1000-2000 r-xp 0 0b:02 91 /alpha\n1800-2400 rw-p 0 0b:02 91 /alpha\n".as_slice(),
        b"1000-1800 r-xp 0 0b:zz 91 /alpha\n",
    ] {
        assert!(reference::maps(b, L).is_err());
        assert!(parse_maps(b, L).is_err());
    }
}
#[test]
fn refuses_mixed_valid_and_malformed() {
    // Separate generic mixed-row population retained from the first candidate.
    let good=b"1200-1600 r-xp 0010 0b:02 91 /fixtures/alpha/one\n1600-1a00 rw-p 0050 0b:03 92 /fixtures/alpha/two\n2100-2500 r--s 0090 0b:04 93 /fixtures/alpha/three\n";
    assert_eq!(parse_maps(good, L).unwrap().len(), 3);
    let b = [good.as_slice(), b"broken-tail\n"].concat();
    bad_maps(&b, 4, 3);
}
#[test]
fn a3_exact_prefix_and_whole_snapshot_refusal() {
    // Independently authored A3 bytes from the frozen plan; no O literal copied.
    let good = include_bytes!("fixtures/procfs/maps_a3_valid.bin");
    let bad = include_bytes!("fixtures/procfs/maps_a3_invalid.bin");
    assert_eq!(
        good.as_slice(),
        b"1000-1800 r--p 0000 0b:02 91 /fixtures/alpha\n\
          1800-2400 r-xp 0800 0b:02 91 /fixtures/alpha\n\
          2400-2800 rw-p 1400 0b:02 91 /fixtures/alpha\n"
    );
    assert_eq!(bad.as_slice(), [good.as_slice(), b"broken\n"].concat());

    let expected = [
        (
            0x1000,
            0x1800,
            *b"r--p",
            0,
            11,
            2,
            91,
            b"/fixtures/alpha".as_slice(),
        ),
        (
            0x1800,
            0x2400,
            *b"r-xp",
            0x800,
            11,
            2,
            91,
            b"/fixtures/alpha".as_slice(),
        ),
        (
            0x2400,
            0x2800,
            *b"rw-p",
            0x1400,
            11,
            2,
            91,
            b"/fixtures/alpha".as_slice(),
        ),
    ];
    let independent = reference::maps(good, L).expect("A3 oracle positive prefix");
    assert_eq!(independent.len(), 3);
    let snapshot = parse_maps(good, L).expect("A3 positive prefix");
    assert_eq!(snapshot.len(), 3);
    for ((entry, oracle), facts) in snapshot.entries().zip(&independent).zip(expected) {
        let got = (
            entry.start(),
            entry.end(),
            entry.permissions(),
            entry.file_offset(),
            entry.file_key().device_major(),
            entry.file_key().device_minor(),
            entry.file_key().inode(),
            entry.raw_path().unwrap(),
        );
        assert_eq!(got, facts);
        assert_eq!(
            (
                oracle.start,
                oracle.end,
                oracle.permissions,
                oracle.offset,
                oracle.major,
                oracle.minor,
                oracle.inode,
                oracle.path.as_deref().unwrap()
            ),
            facts
        );
    }
    for (address, offset) in [
        (0x1000, Some(0)),
        (0x17ff, Some(0x7ff)),
        (0x1800, Some(0x800)),
        (0x23ff, Some(0x13ff)),
        (0x2400, Some(0x1400)),
        (0x27ff, Some(0x17ff)),
        (0x2800, None),
    ] {
        assert_eq!(
            snapshot
                .containing(address)
                .and_then(|e| e.file_offset_at(address)),
            offset
        );
        assert_eq!(reference::offset_at(&independent, address), offset);
    }

    let refused = reference::maps(bad, L).expect_err("A3 oracle whole-input refusal");
    assert_eq!((refused.reason, refused.line), (Reason::Malformed, Some(4)));
    assert!(
        parse_maps(bad, L).is_err(),
        "A3 whole-input refusal after three valid rows"
    );
    let error = parse_maps(bad, L).unwrap_err();
    assert_eq!(
        (error.stage(), error.reason(), error.parse_line()),
        (Stage::ParseMaps, Reason::Malformed, Some(4))
    );
    assert_eq!(error.charges().parse().unwrap().entries_validated(), 3);
    assert_eq!(
        (
            error.effect().attempted_operations(),
            error.effect().completed_operations()
        ),
        (0, 0)
    );
    assert_eq!(
        (
            error.charges().syscall_attempts(),
            error.charges().fd_acquisitions(),
            error.charges().peak_new_fds()
        ),
        (0, 0, 0)
    );
    assert_eq!(
        (
            error.effect().target_mappings_created(),
            error.effect().target_mappings_retired()
        ),
        (0, 0)
    );
    assert_eq!(error.effect().cleanup(), CleanupDisposition::NotNeeded);
    assert_eq!(
        error.effect().descriptor_flags(),
        DescriptorFlagEffect::NotAttempted
    );
    assert!(error.source().is_none());
}
#[test]
fn shape_precedence_and_refused_row_prefix() {
    let l = ParseLimits {
        max_bytes: 4096,
        max_entries: 1,
        max_line_bytes: 30,
    };
    let b = b"bad\n1234567890123456789012345678901";
    let e = parse_maps(b, l).unwrap_err();
    assert_eq!(e.reason(), Reason::LimitExceeded(LimitKind::LineBytes));
    assert_eq!(e.parse_line(), Some(2));
    assert_eq!(e.charges().parse().unwrap().entries_validated(), 0);
    let e = parse_maps(b"bad\n\n", l).unwrap_err();
    assert_eq!(e.reason(), Reason::LimitExceeded(LimitKind::Entries));
    assert_eq!(e.parse_line(), Some(2));
    let e = parse_maps(b"bad\n\n", L).unwrap_err();
    assert_eq!(e.parse_line(), Some(2));
    assert_eq!(e.charges().parse().unwrap().allocation_attempts(), 0);
}

#[test]
fn independent_reference_covers_delivered_fields_and_refusals() {
    for bytes in [
        include_bytes!("fixtures/procfs/maps_valid.bin").as_slice(),
        include_bytes!("fixtures/procfs/maps_invalid.bin"),
        include_bytes!("fixtures/procfs/maps_a3_valid.bin"),
        include_bytes!("fixtures/procfs/maps_a3_invalid.bin"),
        b"1-2 r-xp 0 0:0 0\n\n",
        b"1-2 r-xp 0 0:0 0",
    ] {
        match (reference::maps(bytes, L), parse_maps(bytes, L)) {
            (Ok(w), Ok(s)) => {
                for (e, w) in s.entries().zip(w) {
                    assert_eq!(
                        (
                            e.start(),
                            e.end(),
                            e.file_offset(),
                            e.permissions(),
                            e.file_key().device_major(),
                            e.file_key().device_minor(),
                            e.file_key().inode(),
                            e.raw_path()
                        ),
                        (
                            w.start,
                            w.end,
                            w.offset,
                            w.permissions,
                            w.major,
                            w.minor,
                            w.inode,
                            w.path.as_deref()
                        )
                    );
                }
            }
            (Err(w), Err(e)) => {
                assert_eq!((e.reason(), e.parse_line()), (w.reason, w.line));
            }
            _ => panic!("maps reference mismatch"),
        }
    }
    for bytes in [
        include_bytes!("fixtures/procfs/mountinfo_valid.bin").as_slice(),
        include_bytes!("fixtures/procfs/mountinfo_invalid.bin"),
        b"1 1 0:0 / / rw - x x x\n\n",
        b"1 1 0:0 / / rw - x x x",
    ] {
        match (reference::mounts(bytes, L), parse_mountinfo(bytes, L)) {
            (Ok(w), Ok(s)) => {
                assert_eq!(w.len(), s.len());
                for (e, w) in s.entries().zip(w) {
                    assert_eq!(
                        (
                            e.id().number(),
                            e.parent_id().number(),
                            e.device().major(),
                            e.device().minor()
                        ),
                        (w.id, w.parent, w.major, w.minor)
                    );
                    for (f, w) in [
                        e.root(),
                        e.mount_point(),
                        e.mount_options(),
                        e.filesystem_type(),
                        e.source(),
                        e.super_options(),
                    ]
                    .into_iter()
                    .zip(w.fields)
                    {
                        assert_eq!(
                            (f.raw(), f.decoded()),
                            (w.raw.as_slice(), w.decoded.as_slice())
                        );
                    }
                    let got: Vec<_> = e.optional_fields().collect();
                    assert_eq!(got.len(), w.optional.len());
                    for (f, (w, k)) in got.into_iter().zip(w.optional) {
                        assert_eq!(
                            (f.field().raw(), f.field().decoded()),
                            (w.raw.as_slice(), w.decoded.as_slice())
                        );
                        assert_eq!(
                            f.kind(),
                            match k {
                                reference::Optional::Shared(n) => MountOptionalKind::Shared(n),
                                reference::Optional::Master(n) => MountOptionalKind::Master(n),
                                reference::Optional::PropagateFrom(n) =>
                                    MountOptionalKind::PropagateFrom(n),
                                reference::Optional::Unbindable => MountOptionalKind::Unbindable,
                                reference::Optional::Unknown => MountOptionalKind::Unknown,
                            }
                        );
                    }
                }
            }
            (Err(w), Err(e)) => assert_eq!((e.reason(), e.parse_line()), (w.reason, w.line)),
            _ => panic!("mount reference mismatch"),
        }
    }
}
#[test]
fn numeric_domains_each_reject_sign_prefix_and_overflow() {
    for index in 0..6 {
        for bad in ["+1", "-1", "0x1", "10000000000000000"] {
            let mut f = ["1", "2", "0", "0", "0", "0"];
            f[index] = bad;
            let b = format!(
                "{}-{} r-xp {} {}:{} {}\n",
                f[0], f[1], f[2], f[3], f[4], f[5]
            );
            if index == 5 && bad == "10000000000000000" {
                continue;
            }
            assert!(parse_maps(b.as_bytes(), L).is_err());
        }
    }
    for index in 0..5 {
        for bad in ["+1", "-1", "0x1", "18446744073709551616"] {
            let mut f = ["1", "1", "0", "0", "1"];
            f[index] = bad;
            let b = format!(
                "{} {} {}:{} / / rw shared:{} - fs source rw\n",
                f[0], f[1], f[2], f[3], f[4]
            );
            bad_mount(b.as_bytes(), 1, 0);
        }
    }
    for b in [
        b"1-2 r-xp 0 0:0 18446744073709551616\n".as_slice(),
        b"1-2 rx-p 0 0:0 1\n",
        b"1-2 r-xpp 0 0:0 1\n",
        b"1-2-3 r-xp 0 0:0 1\n",
        b"1-2 r-xp 0 0:0:0 1\n",
    ] {
        bad_maps(b, 1, 0);
    }
}
#[test]
fn raw_nul_refuses_before_allocations_in_every_text_slot() {
    for slot in 0..8 {
        let mut f = [
            b"/".to_vec(),
            b"/".to_vec(),
            b"rw".to_vec(),
            b"x:one".to_vec(),
            b"x:two".to_vec(),
            b"fs".to_vec(),
            b"source".to_vec(),
            b"super".to_vec(),
        ];
        f[slot].push(0);
        let b = [
            b"1 1 0:0 ".as_slice(),
            &f[0],
            b" ",
            &f[1],
            b" ",
            &f[2],
            b" ",
            &f[3],
            b" ",
            &f[4],
            b" - ",
            &f[5],
            b" ",
            &f[6],
            b" ",
            &f[7],
            b"\n",
        ]
        .concat();
        let e = parse_mountinfo(&b, L).unwrap_err();
        assert_eq!(e.parse_line(), Some(1));
        assert_eq!(e.charges().parse().unwrap().allocation_attempts(), 0);
    }
}
