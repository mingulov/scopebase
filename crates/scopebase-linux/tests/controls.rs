// SPDX-License-Identifier: Apache-2.0
use scopebase_linux::{
    control::{CancelToken, MonotonicDeadline, OperationControl},
    error::{CleanupDisposition, DescriptorFlagEffect, Reason, Stage},
};
use std::time::Duration;

#[test]
fn deadline_overflow_is_invalid_input() {
    let error = MonotonicDeadline::after(Duration::MAX).unwrap_err();
    assert_eq!(error.stage(), Stage::ConfigureControl);
    assert_eq!(error.reason(), Reason::InvalidInput);
    assert!(error.source().is_none());
    assert_eq!(error.effect().attempted_operations(), 0);
    assert_eq!(error.effect().completed_operations(), 0);
    assert_eq!(error.effect().target_mappings_created(), 0);
    assert_eq!(error.effect().target_mappings_retired(), 0);
    assert_eq!(error.effect().cleanup(), CleanupDisposition::NotNeeded);
    assert_eq!(
        error.effect().descriptor_flags(),
        DescriptorFlagEffect::NotAttempted
    );
    assert_eq!(error.charges().syscall_attempts(), 0);
    assert_eq!(error.charges().fd_acquisitions(), 0);
    assert_eq!(error.charges().peak_new_fds(), 0);
    assert!(MonotonicDeadline::after(Duration::ZERO).is_ok());
    assert!(MonotonicDeadline::after(Duration::from_secs(1)).is_ok());
}

#[test]
fn controls_have_declared_traits_and_bounded_debug() {
    fn shared<T: Send + Sync + Clone>() {}
    fn copy<T: Copy>() {}
    shared::<CancelToken>();
    shared::<OperationControl>();
    shared::<MonotonicDeadline>();
    copy::<MonotonicDeadline>();
    let token = CancelToken::new();
    let thread_token = token.clone();
    std::thread::spawn(move || thread_token.cancel())
        .join()
        .unwrap();
    let deadline = MonotonicDeadline::after(Duration::from_secs(1)).unwrap();
    let control = OperationControl::new(Some(deadline), token);
    for label in [
        format!("{control:?}"),
        format!("{deadline:#?}"),
        format!("{:?}", CancelToken::new()),
    ] {
        assert!(label.is_ascii() && label.len() < 64);
        assert!(!label.contains('{'));
    }
    assert_eq!(
        format!("{:?}", OperationControl::unlimited()),
        "OperationControl"
    );
}
