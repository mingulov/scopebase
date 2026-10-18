// SPDX-License-Identifier: Apache-2.0
use scopebase_linux as _;

#[test]
fn declared_feature_implications_hold() {
    assert!(
        !cfg!(feature = "mapping") || cfg!(feature = "process"),
        "mapping requires process"
    );
    assert!(
        !cfg!(feature = "supervision") || cfg!(feature = "process"),
        "supervision requires process"
    );
}

#[test]
fn owners_and_observations_are_send_sync() {
    fn check<T: Send + Sync>() {}
    check::<scopebase_linux::file::HeldFile>();
    check::<scopebase_linux::file::ProcFdResolver>();
    check::<scopebase_linux::identity::StatFileKey>();
    check::<scopebase_linux::identity::StatObservation>();
}
