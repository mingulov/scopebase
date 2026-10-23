# Packaged fixture closures (TT07)

The reference installed closure lives at
`crates/scopebase-conformance/delivery/` so that it ships inside the
packaged crate file set (`cargo package --list`). Its manifest,
`delivery/fixture-manifest.json`, pins every byte the operator route may
read: the catalog, the contract template, the vectors, the registered
sources and the H33 notices.

There is intentionally one canonical copy: a second manifest under
`packaging/` would drift from the shipped bytes. Installers copy
`delivery/` to the target prefix (read-only is fine) and pass it as
`--fixture-root`; see `docs/install.md`. `tools/qualification/test_installed.py`
qualifies that installed layout end to end.
