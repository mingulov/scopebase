// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::{
    ErrorKind, Limits, LiveCpuTopology, MapExpectation, Stage, ValidatedMap, ValueLayout,
};
fn limits() -> Limits {
    Limits {
        input_bytes: 1 << 20,
        retained_bytes: 1 << 22,
        work_steps: 1 << 26,
        sites: 0,
        live_links: 0,
        pending_retirements: 0,
    }
}
#[test]
fn budget_zero_exact_overflow_and_capacity() {
    let mut l = limits();
    l.input_bytes = 4095;
    let e = match LiveCpuTopology::acquire(&l) {
        Err(e) => e,
        Ok(_) => panic!("insufficient window accepted"),
    };
    assert_eq!(
        (e.kind(), e.stage()),
        (ErrorKind::LimitExceeded, Stage::Admission)
    );
    l = limits();
    l.work_steps = 0;
    let e = match LiveCpuTopology::acquire(&l) {
        Err(e) => e,
        Ok(_) => panic!("zero work accepted"),
    };
    assert_eq!(e.kind(), ErrorKind::LimitExceeded);
}
#[test]
fn map_metadata_kind_and_extent() {
    for (ty, key, value, alignment, max, flags, kind) in [
        (30, 4, 8, 8, 1, 0, ErrorKind::Unsupported),
        (6, 0, 8, 8, 1, 0, ErrorKind::InvalidInput),
        (6, 4, 0, 8, 1, 0, ErrorKind::InvalidInput),
        (6, 4, 8, 3, 1, 0, ErrorKind::InvalidInput),
        (6, 4, 8, 8, 0, 0, ErrorKind::InvalidInput),
        (6, 4, 8, 8, 1, 1, ErrorKind::Unsupported),
    ] {
        let fd = std::fs::File::open("/dev/null").unwrap().into();
        let expected = MapExpectation {
            map_type: ty,
            key_size: key,
            value: ValueLayout {
                size: value,
                alignment,
                schema: [0; 32],
            },
            max_entries: max,
            required_flags: flags,
            btf: None,
        };
        let e = match ValidatedMap::from_owned_fd(fd, &expected, &limits()) {
            Err(e) => e,
            Ok(_) => panic!("invalid expectation accepted"),
        };
        assert_eq!((e.kind(), e.stage()), (kind, Stage::Admission));
    }
}
