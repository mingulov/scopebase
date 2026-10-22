# LX03 parser-accounting binding followup

This successor preserves the source grants, mapping scopes and symbols of docs/provenance/ports/LX03-20261018-reads.json. Original receipts and preservation records remain unchanged.

LX05 adds parser diagnostic/accounting fields to LinuxError/ResourceCharges. Existing error constructors initialize these fields to None; identity.rs adds separate lexical maps and mount-device types. This document binds the delivered bytes while retaining the original mechanisms and original regression owners.

Predecessor preservation record: docs/provenance/ports/LX03-preservation-20261018.md, SHA256 3a4757dc906dba7377bcf6cbc1a28da4e0322d70a923d4dbca42f63debd6e66a.

Changed bound files: crates/scopebase-linux/src/file/read.rs.

Qualification and acceptance remain separate: this generated record asserts no new test pass or task promotion. Root must inspect the delta, bind the final qualification receipts and validate this successor before integration acceptance.
