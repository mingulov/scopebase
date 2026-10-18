# LX02 held-file test-alias preservation

This note accompanies receipt `LX02-20261018-fd-alias-followup`, which supersedes the immutable original receipt `docs/provenance/ports/LX02-20261018-initial.json` (SHA256 `58344283b677dba86b9cf36de75d5302fba47877176409cedfdeb18ea2091cd4`). It retains the original admission binding, every `file_id`, exact `source_scope`, source identity, and symbol list. All destination hashes are identical to the original except `crates/scopebase-linux/src/file/held.rs`, now bound to candidate SHA256 `992fe7c0e3b6686f362fc13f33d00e9366a71041db296f7b4c289138a0ab0449`.

The complete observed diff against the original held-file destination is one line in the `#[cfg(test)]` fixture module: its local `FD_TABLE` static becomes `use crate::FD_TABLE;`. The shared test mutex is already defined at crate scope and is used to coordinate FD-bearing fixtures. This changes test coordination only. The held-file production logic and the existing LX02 assertions remain byte-for-byte the same; no new LX02 source range, production mechanism, assertion, or donor port is introduced.

This receipt records provenance, with controller acceptance and runtime qualification assessed separately. It binds the held-file destination bytes in the reviewed candidate at `ab2ba7cfad02e0f14e4298142d35936e95f7276f`. The selected-port validator checks these final integrated bytes.
