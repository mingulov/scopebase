// SPDX-License-Identifier: Apache-2.0
fn main() {
    assert_eq!(sb02_feature_subject::parse_u64("18446744073709551615").unwrap(), u64::MAX);
    for input in ["18446744073709551616", "true", "-1"] {
        assert!(sb02_feature_subject::parse_u64(input).is_err());
    }
    println!("json assertions executed");
}
