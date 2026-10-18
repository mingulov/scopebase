// SPDX-License-Identifier: Apache-2.0
fn main() {
    assert_eq!(sb02_feature_subject::decimal_len(0), 1);
    assert_eq!(sb02_feature_subject::decimal_len(u64::MAX), 20);
    println!("decimal assertions executed");
}
