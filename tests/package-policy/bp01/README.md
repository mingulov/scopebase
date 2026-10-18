# BP01 integration handoff

`member-policy.json` is the exact proposed new product member. Root installs the
independent `bpf-contracts.rs` boundary client at
`tests/package-policy/clients/bpf-contracts.rs`, then applies `integration.json`
to root-owned manifests/policy/contracts/status after review. These fragments do
not register a workspace member or accept BP01 themselves. The member advertises
four cells (minimal/default × Rust 1.88.0/1.98.1), one honest foundation client,
no union, no dependency and exactly 15 normalized archive files.

The shared schema's one-client/no-union amendment requires a separately accepted
controller binding. Do not add an unused second client or feature. Existing
product members, grants, inventories and historical matrix denominator remain
intact. Worker validation may execute a clearly labeled BP01-only gate within
that full projection; it cannot claim a fresh complete combined-root matrix.
