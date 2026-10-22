// SPDX-License-Identifier: Apache-2.0
// ADAPT frozen KryProbe mapops + libbpf-mojo generic_maps; exact origins in port receipt.
use scopebase_bpf::{CpuTopology, ErrorKind, PerCpuGeometry, Stage};
fn parse(s: &[u8]) -> Result<CpuTopology, scopebase_bpf::OperationError> {
    CpuTopology::parse_possible(s, 65535, 65536)
}
#[test]
fn stride_1_7_8_9_13() {
    for (v, s) in [(1, 8), (7, 8), (8, 8), (9, 16), (13, 16)] {
        for n in [1, 3, 9] {
            let g = PerCpuGeometry::checked(v, n, 144).unwrap();
            assert_eq!(g.stride(), s, "rounded stride");
            assert_eq!(g.buffer_len(), s * n, "possible extent");
        }
    }
}
#[test]
fn sparse_offline_possible() {
    let t = parse(b"0,2,7-8").unwrap();
    assert_eq!(t.ids(), &[0, 2, 7, 8]);
    assert_eq!(
        PerCpuGeometry::checked(13, t.count(), 64)
            .unwrap()
            .buffer_len(),
        64
    );
    for (s, n) in [
        ("0\n", 1),
        ("0-11\n", 12),
        ("0-3,8-11", 8),
        ("0,2", 2),
        ("  0-1 , 4  \n", 3),
        ("7-7", 1),
        ("000,002", 2),
        ("65535", 1),
    ] {
        assert_eq!(parse(s.as_bytes()).unwrap().count(), n);
    }
}
#[test]
fn overlap_missing_and_overflow_refuse() {
    for s in [
        "", " \n", "garbage", "0,,1", ",0", "0,", "-1", "0-", "-0", "3-0", "1-2-3", "0x10", "+1",
        "0,0", "0-3,2-4", "4,0-3", "1 2", "\u{a0}0", "０",
    ] {
        assert_eq!(
            parse(s.as_bytes()).unwrap_err().kind(),
            ErrorKind::Malformed,
            "{s:?}"
        );
    }
    for (s, k) in [
        ("0-99999999999", ErrorKind::Overflow),
        ("0-100000", ErrorKind::LimitExceeded),
        ("65536", ErrorKind::LimitExceeded),
        ("4294967296x", ErrorKind::Malformed),
        ("4294967296", ErrorKind::Overflow),
        ("65536,x", ErrorKind::LimitExceeded),
        ("0,0,x", ErrorKind::Malformed),
    ] {
        let e = parse(s.as_bytes()).unwrap_err();
        assert_eq!(e.kind(), k, "{s}");
        assert_eq!(e.stage(), Stage::Admission);
    }
    assert!(CpuTopology::parse_possible(b"0", 0, 1).is_ok());
    assert_eq!(
        CpuTopology::parse_possible(b"0", 0, 0).unwrap_err().kind(),
        ErrorKind::LimitExceeded
    );
    let mut max = vec![b' '; 65535];
    max.push(b'0');
    assert_eq!(parse(&max).unwrap().ids(), &[0]);
    max.push(b'x');
    assert_eq!(parse(&max).unwrap_err().kind(), ErrorKind::LimitExceeded);
    assert_eq!(parse(b"0-65535").unwrap().count(), 65536);
}
#[test]
fn geometry_error_precedence() {
    for (v, n, cap, k) in [
        (0, usize::MAX, 0, ErrorKind::InvalidInput),
        (usize::MAX, 0, 0, ErrorKind::InvalidInput),
        (usize::MAX, 1, 0, ErrorKind::Overflow),
        (8, usize::MAX, usize::MAX, ErrorKind::Overflow),
        (13, 3, 47, ErrorKind::LimitExceeded),
    ] {
        let e = PerCpuGeometry::checked(v, n, cap).unwrap_err();
        assert_eq!(e.kind(), k);
        assert_eq!(e.stage(), Stage::Admission);
    }
    assert_eq!(PerCpuGeometry::checked(13, 3, 48).unwrap().buffer_len(), 48);
    assert!(PerCpuGeometry::checked(8, usize::MAX / 8, usize::MAX).is_ok());
}
