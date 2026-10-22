ScopeBase package dependency notices. Dependency references are not bundled unless explicitly marked.
```json
[{"bundled":false,"files":[{"path":"LICENSE-APACHE","sha256":"62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a"},{"path":"LICENSE-MIT","sha256":"23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3"}],"license_expression":"MIT OR Apache-2.0","name":"itoa","selected_option":"Apache-2.0","source":"registry+https://github.com/rust-lang/crates.io-index","version":"1.0.18"},{"bundled":false,"files":[{"path":"COPYING","sha256":"01c266bced4a434da0051174d6bee16a4c82cf634e2679b6155d40d75012390f"},{"path":"LICENSE-MIT","sha256":"0f96a83840e146e43c0ec96a22ec1f392e0680e6c1226e6f3ba87e0740af850f"}],"license_expression":"Unlicense OR MIT","name":"memchr","selected_option":"MIT","source":"registry+https://github.com/rust-lang/crates.io-index","version":"2.8.3"},{"bundled":false,"files":[{"path":"LICENSE-APACHE","sha256":"62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a"},{"path":"LICENSE-MIT","sha256":"23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3"}],"license_expression":"MIT OR Apache-2.0","name":"proc-macro2","selected_option":"Apache-2.0","source":"registry+https://github.com/rust-lang/crates.io-index","version":"1.0.107"},{"bundled":false,"files":[{"path":"LICENSE-APACHE","sha256":"62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a"},{"path":"LICENSE-MIT","sha256":"23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3"}],"license_expression":"MIT OR Apache-2.0","name":"quote","selected_option":"Apache-2.0","source":"registry+https://github.com/rust-lang/crates.io-index","version":"1.0.47"},{"bundled":false,"files":[{"path":"LICENSE-APACHE","sha256":"62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a"},{"path":"LICENSE-MIT","sha256":"23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3"}],"license_expression":"MIT OR Apache-2.0","name":"serde","selected_option":"Apache-2.0","source":"registry+https://github.com/rust-lang/crates.io-index","version":"1.0.229"},{"bundled":false,"files":[{"path":"LICENSE-APACHE","sha256":"62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a"},{"path":"LICENSE-MIT","sha256":"23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3"}],"license_expression":"MIT OR Apache-2.0","name":"serde_core","selected_option":"Apache-2.0","source":"registry+https://github.com/rust-lang/crates.io-index","version":"1.0.229"},{"bundled":false,"files":[{"path":"LICENSE-APACHE","sha256":"62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a"},{"path":"LICENSE-MIT","sha256":"23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3"}],"license_expression":"MIT OR Apache-2.0","name":"serde_derive","selected_option":"Apache-2.0","source":"registry+https://github.com/rust-lang/crates.io-index","version":"1.0.229"},{"bundled":false,"files":[{"path":"LICENSE-APACHE","sha256":"62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a"},{"path":"LICENSE-MIT","sha256":"23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3"}],"license_expression":"MIT OR Apache-2.0","name":"serde_json","selected_option":"Apache-2.0","source":"registry+https://github.com/rust-lang/crates.io-index","version":"1.0.151"},{"bundled":false,"files":[{"path":"LICENSE-APACHE","sha256":"62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a"},{"path":"LICENSE-MIT","sha256":"23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3"}],"license_expression":"MIT OR Apache-2.0","name":"syn","selected_option":"Apache-2.0","source":"registry+https://github.com/rust-lang/crates.io-index","version":"3.0.9"},{"bundled":false,"files":[{"path":"LICENSE-APACHE","sha256":"62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a"},{"path":"LICENSE-MIT","sha256":"23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3"},{"path":"LICENSE-UNICODE","sha256":"f7db81051789b729fea528a63ec4c938fdcb93d9d61d97dc8cc2e9df6d47f2a1"}],"license_expression":"(MIT OR Apache-2.0) AND Unicode-3.0","name":"unicode-ident","selected_option":"(Apache-2.0) AND Unicode-3.0","source":"registry+https://github.com/rust-lang/crates.io-index","version":"1.0.27"},{"bundled":false,"files":[{"path":"LICENSE-MIT","sha256":"23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3"}],"license_expression":"MIT","name":"zmij","selected_option":"MIT","source":"registry+https://github.com/rust-lang/crates.io-index","version":"1.0.23"}]
```

CP05 owner-authorized adaptations and normalized vectors:

- KryProbe pin `d153f3aaf9a3931337b47c9e1b046c692da55083`,
  `crates/kryprobe-privilege/src/kcrypto_lifecycle/tfm.rs` narrow selected ranges:
  563–576, 586–595, 636–640, 660–670, 963–1006, 1013–1022, 1057–1061,
  1138–1154, 1215–1254, 1297–1313, 1349–1367. Test-local K policy preserves
  submit-bound stable identity, separate count bounds, forced ambiguous boundaries
  and retired-only compaction. Twelve selected assertion subsets from
  `crates/kryprobe-privilege/tests/kcrypto_tfm_lifecycle.rs` are normalized into
  named tests, with requested-name/type/mask/driver literals retained as data.
- MemVeil pin `8307a17d4c1d01d2e6fa66679f0e7bed113fa416`,
  `src/memveil/model/identity.mojo` 38–42/121–150 supplies structured identity
  fields and a local positive-generation fixture only; checked/render/imported
  text validators are not ported. `src/memveil/analysis/mappings.mojo`
  490–510/536–548/663–680 supplies separate identity-present/retired-ring policies;
  `src/memveil/capture/reader.mojo` 401–409 supplies the known-only duplicate gate.
  Five selected assertion subsets from `tests/unit/test_{identity,mappings,reader}.mojo`
  are normalized scripted tests, without copying reader session archives.

Historical source labels are GPL-3.0-or-later. The author's separate
`OWNER-2026-10-18` authorization selects Apache-2.0 for these project-owned
host/test/data destinations; source labels are not rewritten into a third-party
grant. No third-party block was identified in the admitted scopes. Exact frozen
full-file/slice hashes, original ranges and copied subsets are recorded in the
repository's CP05 issue/preservation record and root-owned selected-port receipt.
No ungranted K first-seen/configuration body, M validator body, reference-only
workload/request file, BPF source or native bridge is copied by this increment.

CP05's `tests/support/cp05_bounded_process.py` reuses the already accepted
ScopeBase testkit `tests/fixtures/fixture-access/bounded_process.py` unchanged
under Apache-2.0. Its exact common.py-excerpt provenance and SHA256 are stated
in the package README; it adds no third-party dependency or donor grant.
