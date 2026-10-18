# LX02 preservation through LX03 read charges

Held-file acquisition adds only `read: None` to its existing ResourceCharges constructor. Original acquisition/control flow, FD_TABLE coordination and test assertions are unchanged.

This successor preserves the complete source admission, source ranges and destination symbols of the [prior receipt](LX02-20261018-fd-alias-followup.json); only changed destination file hashes and this preservation note advance. The original receipt remains immutable. Current candidate is `f11fed73c0fb86d49c8f40eccd4e8dc8b3c0cb66`; its independent review and final affected checks are separate acceptance gates.

Changed destination files: `crates/scopebase-linux/src/file/held.rs`. No donor refresh, expanded source grant, product migration or new runtime capability is implied.
