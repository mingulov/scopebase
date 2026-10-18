// SPDX-License-Identifier: Apache-2.0
use scopebase_bpf::{ErrorKind, Limits, OperationError, Stage};
use std::{error::Error, io};
fn main() {
    let source = Box::new(io::Error::from_raw_os_error(524));
    let pointer = &*source as *const io::Error;
    let error = OperationError::new(ErrorKind::Backend, Stage::Execute, Some(13), Some(source))
        .with_required_size(0)
        .with_required_size(usize::MAX);
    assert_eq!(
        (
            error.kind(),
            error.stage(),
            error.raw_os_error(),
            error.required_size()
        ),
        (
            ErrorKind::Backend,
            Stage::Execute,
            Some(13),
            Some(usize::MAX)
        )
    );
    let original = error.source().unwrap().downcast_ref::<io::Error>().unwrap();
    assert_eq!(original as *const io::Error, pointer);
    assert_eq!(original.raw_os_error(), Some(524));
    let text = format!("{error:#?}");
    assert!(text.is_ascii() && text.len() <= 256);
    let disabled = Limits {
        input_bytes: 0,
        retained_bytes: 0,
        work_steps: 0,
        sites: 0,
        live_links: 0,
        pending_retirements: 0,
    };
    let unrelated = Limits {
        input_bytes: 1,
        retained_bytes: usize::MAX,
        work_steps: u64::MAX,
        sites: usize::MAX,
        live_links: 0,
        pending_retirements: usize::MAX,
    };
    assert!(disabled.validate().is_ok());
    assert!(unrelated.validate().is_ok());
    assert_eq!(unrelated.live_links, 0);
    assert_eq!(unrelated.retained_bytes, usize::MAX);
    println!("BP01 archive boundary contracts passed");
}
