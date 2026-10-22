# LX04 parser-accounting binding followup

This successor preserves the source grants, mapping scopes and symbols of docs/provenance/ports/LX04-20261018-read-charges-followup.json. Original receipts and preservation records remain unchanged.

LX05 adds parser diagnostic/accounting fields to LinuxError/ResourceCharges. Existing error constructors initialize these fields to None; identity.rs adds separate lexical maps and mount-device types. This document binds the delivered bytes while retaining the original mechanisms and original regression owners.

Predecessor preservation record: docs/provenance/ports/LX04-read-charges-preservation-20261018.md, SHA256 d7b67c3b722a25729bce5aa0b6be0188fdefb18698eae60f910438271a5a8955.

Changed bound files: crates/scopebase-linux/src/control.rs, crates/scopebase-linux/src/control/tests.rs.

Qualification and acceptance remain separate: this generated record asserts no new test pass or task promotion. Root must inspect the delta, bind the final qualification receipts and validate this successor before integration acceptance.
