// SPDX-License-Identifier: Apache-2.0
// Independent BTF v1: two rival ints named dup (IDs 1/2), pointer ID3 -> ID1.
fn btf(types: &[u32], strings: &[u8]) -> Vec<u8> {
    let mut b = vec![0x9f, 0xeb, 1, 0];
    for n in [
        24,
        0,
        (types.len() * 4) as u32,
        (types.len() * 4) as u32,
        strings.len() as u32,
    ] {
        b.extend(n.to_le_bytes());
    }
    for n in types {
        b.extend(n.to_le_bytes());
    }
    b.extend(strings);
    b
}
fn base_bytes() -> Vec<u8> {
    btf(
        &[1, 1 << 24, 4, 32, 1, 1 << 24, 8, 64, 0, 2 << 24, 1],
        b"\0dup\0",
    )
}
fn split_bytes() -> Vec<u8> {
    btf(&[5, 1 << 24, 8, 64], b"split\0")
}
