// SPDX-License-Identifier: Apache-2.0
//! Optional JSON mechanics; duplicate-key/limit gaps do not certify strict replay.
#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Sample {
        count: u64,
    }
    #[test]
    fn derive_and_exact_integer_literals() {
        for (literal, value) in [
            ("9007199254740993", 9_007_199_254_740_993),
            ("18446744073709551615", u64::MAX),
        ] {
            assert_eq!(serde_json::from_str::<u64>(literal).unwrap(), value);
            let sample = Sample { count: value };
            let encoded = serde_json::to_string(&sample).unwrap();
            assert_eq!(encoded, format!("{{\"count\":{literal}}}"));
            assert_eq!(serde_json::from_str::<Sample>(&encoded).unwrap(), sample);
        }
    }
    #[test]
    fn refuses_non_u64_values() {
        assert_eq!(
            serde_json::from_str::<u64>("18446744073709551615").unwrap(),
            u64::MAX
        );
        for bad in ["18446744073709551616", "true", "-1"] {
            assert!(serde_json::from_str::<u64>(bad).is_err(), "reject {bad}");
        }
    }
    #[test]
    fn duplicate_member_gap_and_control() {
        let value: serde_json::Value = serde_json::from_str(r#"{"count":1,"count":2}"#).unwrap();
        assert_eq!(value["count"], 2);
        let refused =
            serde_json::from_str::<serde_json::Value>(r#"{"count":1,"count":2}"#).is_err();
        assert!(std::panic::catch_unwind(|| assert!(
            refused,
            "GAP: strict replay must refuse duplicate members"
        ))
        .is_err());
    }
    #[test]
    fn wrong_f64_control() {
        let literal = "9007199254740993";
        let expected = 9_007_199_254_740_993u64;
        assert_eq!(serde_json::from_str::<u64>(literal).unwrap(), expected);
        let rounded = serde_json::from_str::<f64>(literal).unwrap() as u64;
        assert_eq!(rounded, 9_007_199_254_740_992);
        assert!(std::panic::catch_unwind(|| assert_eq!(
            rounded, expected,
            "counter must not pass through f64"
        ))
        .is_err());
    }
}
