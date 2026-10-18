// SPDX-License-Identifier: Apache-2.0
//! Byte API comparator. Missing caller limits remain BP09 work, not implemented here.
#[cfg(test)]
mod tests {
    include!("btf_fixture.rs");
    use btf_rs::{Btf, Type};
    fn ids(btf: &Btf) -> Vec<u32> {
        let mut ids = btf.resolve_ids_by_name("dup").unwrap();
        ids.sort();
        ids
    }
    #[test]
    fn base_names_ids_chain() {
        let btf = Btf::from_bytes(&base_bytes()).unwrap();
        assert_eq!(ids(&btf), vec![1, 2]);
        assert_eq!(btf.resolve_types_by_name("dup").unwrap().len(), 2);
        match btf.resolve_type_by_id(1).unwrap() {
            Type::Int(i) => {
                assert_eq!(i.size(), 4);
                assert_eq!(btf.resolve_name(&i).unwrap(), "dup");
            }
            _ => panic!("ID1 int"),
        }
        match btf.resolve_type_by_id(3).unwrap() {
            Type::Ptr(ptr) => {
                match btf.resolve_chained_type(&ptr).unwrap() {
                    Type::Int(i) => assert_eq!(i.size(), 4),
                    _ => panic!("pointer must resolve to ID1 int"),
                }
                let chain: Vec<_> = btf.chained_type_iter(&ptr).take(4).collect();
                assert_eq!(chain.len(), 1);
                assert!(matches!(&chain[0], Type::Int(i) if i.size() == 4));
            }
            _ => panic!("ID3 pointer"),
        }
        assert!(btf.split().is_none());
    }
    #[test]
    fn split_domain_and_refusals() {
        let base = Btf::from_bytes(&base_bytes()).unwrap();
        let split = Btf::from_split_bytes(&split_bytes(), &base).unwrap();
        assert!(split.split().is_some());
        assert_eq!(ids(&split), vec![1, 2]);
        assert_eq!(split.resolve_ids_by_name("split").unwrap(), vec![4]);
        assert!(base.resolve_type_by_id(4).is_err());
        match split.resolve_type_by_id(4).unwrap() {
            Type::Int(i) => {
                assert_eq!(i.size(), 8);
                assert_eq!(split.resolve_name(&i).unwrap(), "split");
            }
            _ => panic!("split ID4 int"),
        }
        match split.resolve_type_by_id(1).unwrap() {
            Type::Int(i) => assert_eq!(split.resolve_name(&i).unwrap(), "dup"),
            _ => panic!("base ID1 int"),
        }
        assert!(Btf::from_split_bytes(&split_bytes(), &split).is_err());
    }
    #[test]
    fn truncated_and_invalid_id() {
        let bytes = base_bytes();
        assert!(Btf::from_bytes(&bytes).is_ok());
        assert!(Btf::from_bytes(&bytes[..12]).is_err());
        assert!(Btf::from_bytes(&bytes)
            .unwrap()
            .resolve_type_by_id(99)
            .is_err());
    }
    #[test]
    fn wrong_first_match_control() {
        let btf = Btf::from_bytes(&base_bytes()).unwrap();
        let all = ids(&btf);
        assert_eq!(all, vec![1, 2]);
        let collapsed = vec![all[0]];
        assert!(std::panic::catch_unwind(|| assert_eq!(
            collapsed,
            vec![1, 2],
            "all rival type IDs must remain visible"
        ))
        .is_err());
    }
    #[test]
    fn wrong_domain_control() {
        let base = Btf::from_bytes(&base_bytes()).unwrap();
        let split = Btf::from_split_bytes(&split_bytes(), &base).unwrap();
        let actual = match split.resolve_type_by_id(4).unwrap() {
            Type::Int(i) => split.resolve_name(&i).unwrap(),
            _ => panic!("split int"),
        };
        assert_eq!(actual, "split");
        let wrong = match base.resolve_type_by_id(1).unwrap() {
            Type::Int(i) => base.resolve_name(&i).unwrap(),
            _ => panic!("base int"),
        };
        assert!(std::panic::catch_unwind(|| assert_eq!(
            wrong, "split",
            "base ID reused as split domain"
        ))
        .is_err());
    }
}
