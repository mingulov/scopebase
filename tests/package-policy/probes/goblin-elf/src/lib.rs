// SPDX-License-Identifier: Apache-2.0
//! Comparator uses independently encoded ELF bytes, with no resolver implementation.
#[cfg(test)]
mod tests {
    include!("elf_fixture.rs");
    fn assert_layout(bytes: &[u8], offset: u64) {
        let file = goblin::elf::Elf::parse(bytes).unwrap();
        assert_eq!(file.little_endian, true);
        assert_eq!(file.program_headers.len(), 1);
        let segment = &file.program_headers[0];
        assert_eq!(segment.p_type, 1);
        assert_eq!(segment.p_flags, 5, "expected RX flags");
        assert_eq!(segment.p_vaddr, 0x400000);
        assert_eq!((segment.p_offset, segment.p_filesz), (offset, 8));
        assert_eq!(segment.p_memsz, 8);
        assert_eq!(&bytes[offset as usize..offset as usize + 8], b"fixture!");
        assert_eq!(file.dynsyms.len(), 0);
        for symbol in file.dynsyms.iter() {
            let _ = (symbol.st_value, symbol.st_shndx);
        }
        assert_eq!(file.section_headers.len(), 0);
        assert_eq!(file.dynrels.len(), 0);
        assert_eq!(file.dynrelas.len(), 0);
        for (_, relocations) in &file.shdr_relocs {
            for relocation in relocations.iter() {
                let _ = (relocation.r_offset, relocation.r_sym, relocation.r_type);
            }
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
            assert!(goblin::elf::Elf::parse(&good).is_ok());
            assert!(goblin::elf::Elf::parse(&good[..12]).is_err());
            let mut bad = good;
            bad[0] = 0;
            assert!(goblin::elf::Elf::parse(&bad).is_err());
        }
    }
    #[test]
    fn wrong_flags_control() {
        let wrong = elf(64, false);
        assert!(goblin::elf::Elf::parse(&wrong).is_ok());
        assert!(std::panic::catch_unwind(|| assert_layout(&wrong, 120)).is_err());
    }
}
