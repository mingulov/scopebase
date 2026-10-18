# TT02 SHA-256 dependency prerequisite

Date: 2026-10-18. The bounded SB02 maintenance prerequisite is accepted at
`26b4d24892fe6240ed5b927943b931129a2d77da`, preserving the seven probe files from
reviewed candidate `1e92c3d97e6fca718dcc42659bef1e23c1aa008a`. This does not add an
accepted product task or complete TT02.

The probe selects `sha2 = { version = "=0.11.0", default-features = false }`.
Its actual x86_64 host closure contains eight exact packages and no build script
or procedural macro. Apache-2.0 is selected while original third-party license
options and notices remain. CPU dispatch is unchanged; other targets and forced
backends were not qualified.

Twelve fixed digest literals match independently generated Python hashlib
values. One-shot and incremental tests cover empty updates and block/padding
boundaries. A compiled mutant removes the actual chunk update, reaches the
intended `SHA256_DIGEST_MISMATCH` assertion, and fails; each restored twin passes.
Both Rust 1.88.0 and 1.98.1 were exercised.

| Evidence | Scope | SHA256 |
|---|---|---|
| Sol independent review | Source/vendor/license/oracle bindings; fresh 18-stage positive and 17-stage mutant/twin checks | `35e489804b1c2a4e1366367bf147d6e3e9a2ed8f4e32d5637507157479577ab3` |
| Root focused probe | 18 PASS rows, 17 selected required stages, two of 24 declared cells | `c0cf4a618c160f3b0821c2b9453760d311cfe9a3ec4372c07acf3f45b2d6aa05` |
| Final source inventory | Original 46 records, bundles and locks preserved; seven additions, 53 records total | `f069051c436afb9c21a1dfd6d92426f404b7a53280e0ac79d627d3661717d16f` |
| Controller acceptance | Exact integrated probe/matrix binding, 24 log records and eight unchanged locked commands | `35f4909df66d7fab3fce955a5eb0767dfee2e58d1290230731cf1b76c79dd6b2` |

The matrix now has eleven probes, including the original separate Aya refusal
cells. Root ran only `--case sha2-sha256`; 106 unchanged required stages remain
explicitly omitted. Historical whole-matrix counts are not extended by adding
these focused results. Three actual tests run per compiler; the doc-test command
has zero examples.

Cargo's all-target lock retains previously admitted libc 0.2.191 only for
non-host declarations. This creates no new libc host or target execution grant.
The initial unbuilt 0.2.190 selection and failed input-config attempt remain
retained separately. No old probe campaign or donor investigation was repeated.

Evidence and immutable inputs remain under
`.scopebase/jobs/tt02-sha256-admission-20261018/`; root acceptance remains under
`.scopebase/controller/sha256-integration-20261018/`. Job ownership is reconciled.
TT02 must still bind its own actual dependency, features, executable and objects.
An artifact digest is not physical-file or runtime authority. Cryptographic
certification, runtime/conformance profiles and installed delivery remain outside
this prerequisite.
