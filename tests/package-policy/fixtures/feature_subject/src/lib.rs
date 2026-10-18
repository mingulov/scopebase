// SPDX-License-Identifier: Apache-2.0
//! Executable checker fixture, not a ScopeBase API.
//! ```
//! assert_eq!(sb02_feature_subject::decimal_len(10), 2);
//! ```

pub fn decimal_len(value: u64) -> usize {
    value.to_string().len()
}

#[cfg(feature = "json")]
pub fn parse_u64(input: &str) -> Result<u64, serde_json::Error> {
    serde_json::from_str::<u64>(input)
}

#[cfg(test)]
mod tests {
    #[test]
    fn decimal_boundary() {
        assert_eq!(super::decimal_len(0), 1);
        assert_eq!(super::decimal_len(u64::MAX), 20);
    }
}
