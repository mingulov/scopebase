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
