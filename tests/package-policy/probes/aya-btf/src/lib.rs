// SPDX-License-Identifier: Apache-2.0
//! Public host BTF parsing only; arbitrary exact-ID queries remain private.
#[cfg(test)]
mod tests {
    include!("btf_fixture.rs");
    use aya_obj::btf::{Btf, BtfKind};
    use object::Endianness;
    #[test]
    fn public_parse_and_query() {
        let btf = Btf::parse(&base_bytes(), Endianness::Little).unwrap();
        assert_eq!(btf.id_by_type_name_kind("dup", BtfKind::Int).unwrap(), 1);
        assert!(btf.id_by_type_name_kind("absent", BtfKind::Int).is_err());
        assert!(btf.id_by_type_name_kind("dup", BtfKind::Ptr).is_err());
    }
    #[test]
    fn malformed_btf_refusals() {
        let good = base_bytes();
        assert!(Btf::parse(&good, Endianness::Little).is_ok());
        assert!(Btf::parse(&good[..12], Endianness::Little).is_err());
    }
    #[test]
    fn first_match_observation_and_control() {
        let btf = Btf::parse(&base_bytes(), Endianness::Little).unwrap();
        let actual = vec![btf.id_by_type_name_kind("dup", BtfKind::Int).unwrap()];
        assert_eq!(actual, vec![1]);
        assert!(std::panic::catch_unwind(|| assert_eq!(
            actual,
            vec![1, 2],
            "GAP: first-match query cannot expose all rival IDs"
        ))
        .is_err());
    }
}
