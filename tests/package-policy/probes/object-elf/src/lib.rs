// SPDX-License-Identifier: Apache-2.0
//! Public ELF APIs only. No mapped-image resolver or donor regression is ported.
#[cfg(test)]
mod tests {
    include!("elf_fixture.rs");
    use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol};
    fn assert_layout(bytes: &[u8], offset: u64) {
        let file = object::File::parse(bytes).unwrap();
        assert_eq!(file.is_little_endian(), true);
        let segments: Vec<_> = file.segments().collect();
        assert_eq!(segments.len(), 1);
        let segment = &segments[0];
        assert_eq!(segment.address(), 0x400000);
        assert_eq!(segment.file_range(), (offset, 8));
        assert_eq!(segment.size(), 8);
        assert!(
            matches!(segment.flags(), object::SegmentFlags::Elf { p_flags: 5 }),
            "expected RX flags"
        );
        assert_eq!(segment.data().unwrap(), b"fixture!");
        assert_eq!(file.build_id().unwrap(), None);
        assert_eq!(file.dynamic_symbols().count(), 0);
        for symbol in file.dynamic_symbols() {
            let _ = (symbol.address(), symbol.is_definition());
        }
        assert_eq!(file.sections().count(), 0);
        for section in file.sections() {
            let _ = (section.address(), section.relocations().count());
        }
    }
    #[test]
    fn elf32_layout() {
        assert_layout(&elf(32, true), 84);
    }
    #[test]
    fn elf64_layout() {
        assert_layout(&elf(64, true), 120);
    }
    #[test]
    fn truncated_and_invalid_headers() {
        for bits in [32, 64] {
            let good = elf(bits, true);
            assert!(object::File::parse(good.as_slice()).is_ok());
            assert!(object::File::parse(&good[..12]).is_err());
            let mut bad = good;
            bad[0] = 0;
            assert!(object::File::parse(bad.as_slice()).is_err());
        }
    }
    #[test]
    fn wrong_flags_control() {
        let wrong = elf(64, false);
        assert!(object::File::parse(wrong.as_slice()).is_ok());
        assert!(std::panic::catch_unwind(|| assert_layout(&wrong, 120)).is_err());
    }
}
