// SPDX-License-Identifier: Apache-2.0
// Independent little-endian ELF fixture, encoded from ELF header layouts.
// One PT_LOAD: RX, vaddr 0x400000, eight file bytes, no section/symbol tables.
fn elf(bits: u8, executable: bool) -> Vec<u8> {
    let (header, phdr) = if bits == 64 {
        (64usize, 56usize)
    } else {
        (52, 32)
    };
    let mut b = vec![0; header + phdr + 8];
    b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', if bits == 64 { 2 } else { 1 }, 1, 1]);
    fn u16at(b: &mut [u8], p: usize, n: u16) {
        b[p..p + 2].copy_from_slice(&n.to_le_bytes());
    }
    fn u32at(b: &mut [u8], p: usize, n: u32) {
        b[p..p + 4].copy_from_slice(&n.to_le_bytes());
    }
    fn u64at(b: &mut [u8], p: usize, n: u64) {
        b[p..p + 8].copy_from_slice(&n.to_le_bytes());
    }
    u16at(&mut b, 16, 2);
    u16at(&mut b, 18, if bits == 64 { 62 } else { 3 });
    u32at(&mut b, 20, 1);
    let flags = if executable { 5 } else { 4 };
    if bits == 64 {
        u64at(&mut b, 32, header as u64);
        u16at(&mut b, 52, header as u16);
        u16at(&mut b, 54, phdr as u16);
        u16at(&mut b, 56, 1);
        u16at(&mut b, 58, 64);
        u32at(&mut b, 64, 1);
        u32at(&mut b, 68, flags);
        u64at(&mut b, 72, 120);
        u64at(&mut b, 80, 0x400000);
        u64at(&mut b, 88, 0x400000);
        u64at(&mut b, 96, 8);
        u64at(&mut b, 104, 8);
        u64at(&mut b, 112, 1);
    } else {
        u32at(&mut b, 28, header as u32);
        u16at(&mut b, 40, header as u16);
        u16at(&mut b, 42, phdr as u16);
        u16at(&mut b, 44, 1);
        u16at(&mut b, 46, 40);
        u32at(&mut b, 52, 1);
        u32at(&mut b, 56, 84);
        u32at(&mut b, 60, 0x400000);
        u32at(&mut b, 64, 0x400000);
        u32at(&mut b, 68, 8);
        u32at(&mut b, 72, 8);
        u32at(&mut b, 76, flags);
        u32at(&mut b, 80, 1);
    }
    b[header + phdr..].copy_from_slice(b"fixture!");
    b
}
