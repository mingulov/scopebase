# SHA-256 dependency/API admission probe

This standalone, unpublished host probe selects `sha2 = { version = "=0.11.0", default-features = false }`.
It exercises `Sha256::digest` plus `Digest::new/update/finalize`, including conversion to `[u8; 32]`.
It supplies dependency/API evidence for TT02 byte measurements; it does not implement TT02 or qualify a cryptographic algorithm, runtime package, backend or conformance profile.

`src/lib.rs` fixes 12 independently expected SHA-256 digests: empty, abc, the 56-byte standard vector and deterministic byte sequences at 55/56/63/64/65/127/128/129/1024 bytes. Each boundary sequence runs one-shot and incremental hashing at nine chunk sizes, with empty updates and nonempty byte activity. `reference_vectors.py` retains a Python stdlib `hashlib` recipe independent of the Rust implementation and prints the expected digests. The omitted-update control requires the intended digest assertion panic and then a restored passing twin.

The private gate additionally removes the actual boundary-loop update in an isolated copied probe, checks a semantic test failure after successful Cargo admission/setup on both pinned compilers, restores the exact original source, and reruns that same test successfully. The original and every attempt remain retained.

The exact Cargo-generated lock includes the eight host packages plus libc 0.2.191 for cpufeatures' non-host target declarations. The controller authorized that already admitted lock-only record; filtered x86_64 metadata must contain exactly the eight selected packages, with no build scripts or proc macros. This does not grant another target or permit a libc build in this probe.

With already admitted offline Cargo sources, run `cargo test --offline --locked --manifest-path Cargo.toml` and `python3 reference_vectors.py`. In this repository, all Cargo commands must use `bin/scopebase-build`; qualification uses the accepted `tools/build/dependency_probe.py` with the controller-integrated case and exact private source inventory. The root integration owner adds the case and inventory reference after independent review. The current probe is not automatically selected by the root matrix until then.

The probe is Apache-2.0. Dependency notices retain the original dual-license expressions and exact license-text hashes while selecting the available Apache-2.0 option. Dependencies are referenced, not bundled here; the separate standard Cargo vendor retains their complete original notices.
