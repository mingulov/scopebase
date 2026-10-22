// SPDX-License-Identifier: Apache-2.0
use super::*;
const L: ParseLimits = ParseLimits {
    max_bytes: 4096,
    max_entries: 64,
    max_line_bytes: 512,
};
const MAP: &[u8] = b"1-2 r-xp 0 0:0 1 /a\n";
const MOUNT: &[u8] = b"17 1 8:1 / /a rw - ext4 /dev/a rw\n";
#[test]
fn parse_capacity_and_allocation_accounting() {
    for mount in [false, true] {
        let b = if mount { MOUNT } else { MAP };
        let parse = |mode| {
            if mount {
                mountinfo::parse_inner(b, L, mode).map(|s| s.charges())
            } else {
                maps::parse_inner(b, L, mode).map(|s| s.charges())
            }
        };
        let n = if mount { 4 } else { 2 };
        let good = parse(ReserveMode::Normal).unwrap();
        assert_eq!(good.allocation_attempts(), n);
        assert_eq!(
            good.peak_buffer_capacity_bytes(),
            b.len() * if mount { 2 } else { 1 }
        );
        let metadata = if mount {
            size_of::<mountinfo::MountRecord>() + size_of::<(u64, usize)>()
        } else {
            size_of::<maps::MapRecord>()
        };
        assert_eq!(good.peak_metadata_capacity_bytes(), metadata);
        for pos in 1..=n {
            let e = parse(ReserveMode::Fail(pos)).unwrap_err();
            assert_eq!(e.reason(), Reason::Allocation);
            assert_eq!(e.parse_line(), None);
            let c = e.charges().parse().unwrap();
            assert_eq!(c.allocation_attempts(), pos);
            assert_eq!(c.entries_validated(), 0);
            let buffers = if mount {
                pos.saturating_sub(1).min(2)
            } else {
                pos - 1
            };
            assert_eq!(c.peak_buffer_capacity_bytes(), b.len() * buffers as usize);
            let prior = if mount && pos == 4 {
                size_of::<mountinfo::MountRecord>()
            } else {
                0
            };
            assert_eq!(c.peak_metadata_capacity_bytes(), prior);
            let e = parse(ReserveMode::Overgrant(pos)).unwrap_err();
            assert_eq!(e.reason(), Reason::LimitExceeded(LimitKind::BufferCapacity));
            assert_eq!(e.parse_line(), None);
            let c = e.charges().parse().unwrap();
            assert_eq!(c.allocation_attempts(), pos);
            assert_eq!(c.entries_validated(), 0);
            if pos <= if mount { 2 } else { 1 } {
                assert_eq!(c.peak_buffer_capacity_bytes(), b.len() * pos as usize + 1)
            } else {
                let expected = if !mount {
                    2 * size_of::<maps::MapRecord>()
                } else if pos == 3 {
                    2 * size_of::<mountinfo::MountRecord>()
                } else {
                    size_of::<mountinfo::MountRecord>() + 2 * size_of::<(u64, usize)>()
                };
                assert_eq!(c.peak_metadata_capacity_bytes(), expected);
            }
        }
    }
}
#[test]
fn capacity_arithmetic_refuses_without_allocating() {
    for mount in [false, true] {
        assert!(capacity_request(usize::MAX, 1, mount).is_none());
        assert!(capacity_request(1, usize::MAX, mount).is_none());
    }
    let mut c = ParseCharges::new(0);
    let mut v = Vec::<u64>::new();
    assert!(reserve(
        &mut v,
        usize::MAX,
        false,
        &mut c,
        Stage::ParseMaps,
        ReserveMode::Normal
    )
    .is_err());
    assert_eq!(c.allocation_attempts(), 1);
}
#[test]
fn no_allocation_for_absence_or_shape() {
    for mode in [ReserveMode::Fail(1), ReserveMode::Overgrant(1)] {
        assert_eq!(
            maps::parse_inner(b"", L, mode)
                .unwrap()
                .charges()
                .allocation_attempts(),
            0
        );
        assert_eq!(
            mountinfo::parse_inner(b"", L, mode)
                .unwrap()
                .charges()
                .allocation_attempts(),
            0
        );
        let e = maps::parse_inner(b"\n", L, mode).unwrap_err();
        assert_eq!(e.charges().parse().unwrap().allocation_attempts(), 0);
    }
}
#[test]
fn old_control_errors_have_no_parser_charges() {
    let e = crate::control::MonotonicDeadline::after(std::time::Duration::MAX).unwrap_err();
    assert_eq!(e.charges().parse(), None);
    assert_eq!(e.parse_line(), None);
}
