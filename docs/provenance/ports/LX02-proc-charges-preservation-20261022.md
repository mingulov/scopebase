# LX02 parser-accounting binding followup

This successor preserves the source grants, mapping scopes and symbols of docs/provenance/ports/LX02-20261018-read-charges-followup.json. Original receipts and preservation records remain unchanged.

LX05 adds parser diagnostic/accounting fields to LinuxError/ResourceCharges. Existing error constructors initialize these fields to None; identity.rs adds separate lexical maps and mount-device types. This document binds the delivered bytes while retaining the original mechanisms and original regression owners.

Predecessor preservation record: docs/provenance/ports/LX02-read-charges-preservation-20261018.md, SHA256 f35b8e6f9efce3a56c7c437c76b3d8ef9258e84b0966879b0938c7102efae4f8.

Changed bound files: crates/scopebase-linux/src/file/held.rs, crates/scopebase-linux/src/identity.rs.

Qualification and acceptance remain separate: this generated record asserts no new test pass or task promotion. Root must inspect the delta, bind the final qualification receipts and validate this successor before integration acceptance.
