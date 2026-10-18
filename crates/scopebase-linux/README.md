# scopebase-linux

ScopeBase's Linux-only Rust package boundary, version 0.1.0. This increment
exports no modules, types, constants or functions. File and process authority,
reads, mapping proofs, supervision and traversal are future implementation work.

The default feature set is empty. Additive features are `process`,
`mapping = ["process"]`, `supervision = ["process"]` and `walk`. They currently
enable no runtime functionality. The package has no dependencies or build script;
import, test and documentation builds need no BPF tools or application workspace.

Edition 2021, prospective MSRV 1.88.0; boundary build checks target
`x86_64-unknown-linux-gnu` with Rust 1.88.0 and 1.98.1. Other targets remain
unsupported. These checks do not establish a supported kernel floor, runtime
capability, installed conformance, useful independent clients or package readiness.
All five planned profiles (`held-file-v1`, `mapped-image-v1`,
`process-observation-v1`, `owned-child-v1`, `bounded-walk-v1`) remain unimplemented
and unqualified. No tools are installed and no host policy changes implicitly.

LX02 introduces real file authority; LX03 bounded positional reads; LX04 controls;
LX05 strict proc parsing; LX06/LX07 mapping proofs and filesystem qualification;
LX08 process observation; LX09 supervision; LX10 traversal; LX11/LX12 real
consumers and conformance; LX13 migration handoff. These names are work ownership,
not existing APIs. The package's import-only doctest runs with `cargo test --doc`.

New user-owned host source uses provisional Apache-2.0 terms. See the included
LICENSE-APACHE and THIRD-PARTY-NOTICES.md. No donor or third-party source is bundled.
The package is unpublished (`publish = false`); its name is not reserved.
