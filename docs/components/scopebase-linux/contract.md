# scopebase-linux LX01 boundary contract

Version 0.1.0 is a Linux-only package boundary with no runtime exports or
production/development dependencies. Default features are empty; `process`,
`mapping = ["process"]`, `supervision = ["process"]` and `walk` are additive
boundary declarations only. No placeholder modules or HeldFile are exported.
Public authority appears with real implementation/tests at LX02 and later.

Explicit package values follow accepted workspace policy: Rust edition 2021,
prospective MSRV 1.88.0, Apache-2.0, `publish = false`, `build = false`.
The compiler/build target for boundary qualification is
`x86_64-unknown-linux-gnu` on Rust 1.88.0 and 1.98.1; other targets remain
unsupported. The conditional compile error rejects non-Linux targets. No alternate
target was installed or qualified. Compiler checks prove package/import/features,
not a kernel floor or runtime support.

The [source register](source-register.md) preserves selected frozen donor bytes,
original regressions, oracles, bad controls, licensing and later ownership. No
source adoption, behavior port or donor test run occurs in LX01. The planned
[Linux design](../../superpowers/specs/2026-10-17-scopebase-linux-design.md) governs
future behavior. Held-file, mapped-image, process-observation, owned-child and
bounded-walk profiles are all unimplemented and unqualified. No operator conformance
route or independently useful behavioral consumer exists in this boundary increment.

`package-policy.json` at repository root declares the genuine product member,
zero allowed dependencies and build approvals, both exact compilers, source-input
inventory, two independently wired import-only clients, three configurations and
an exact eight-file archive allowlist. Minimal/default builds import with empty
feature sets. The union combines mapping/process/supervision/walk; separate
single-feature trait tests and removed-edge mutants exercise each implicit process
edge. One executable import-only doctest runs in every compiler/configuration.
The two-client wiring proves boundary isolation; LX11 still owes actual independent
behavioral consumers and LX12 distributed conformance.

Actual product-root metadata uses offline, locked, full metadata filtered to
`x86_64-unknown-linux-gnu`; missing/stale locks refuse unchanged. The root lock is
created only by explicit owned integration, not repaired by the checker. Before
and after source/lock hashes accompany success and refusal. Existing fixtures use
their own explicit empty workspace; actual product membership remains exact.

Each staged product subject and unpacked archive has one generated containing
resolver-2 workspace and an isolated workspace lock. Subject Cargo.toml bytes stay
unchanged. Generated package locks mirror the isolated workspace lock explicitly;
archive mapping compares exact lock and original-manifest bytes. The generated
workspace/lock mapping is evidence, not source-manifest normalization. No subject
shares a staging resolution workspace with another subject. Removing that boundary
reproduces Cargo's enclosing-workspace refusal in the declared job output tree.

New host source uses provisional Apache-2.0 terms with exact included license text
and product-role dependency notices. There is no BPF target/input, MIT project
option or bundled donor/third-party source. Process observation/control, birth/exec,
file identity/content and cleanup custody remain distinct future contracts.

LX01 requires no privileges, BPF/native compiler discovery, acquisition or host
policy changes. All Cargo work uses the cooperative build lease, reconstructed
accepted offline inputs and private targets/evidence. Ordinary compiler/test child
completion is checked; no product syscall interruption or runtime cleanup guarantee
is advertised. Package readiness, real conformance/consumers, migrations and external
publication retain their later gates and independent review.
