# Installing the ScopeBase operator (TT07)

## Prerequisites

- Rust 1.88+ with Cargo (see `rust-toolchain.toml`).
- The ScopeBase source tree **or** the packaged crate file sets (see below).
- No network access is required: every step below runs with `--offline`.

## Install from source

```sh
cargo install --offline --locked \
  --path crates/scopebase-conformance \
  --root "$HOME/.local"
```

This installs `scopebase-conformance` to `$HOME/.local/bin`. `--locked`
pins the workspace dependency closure; `--offline` forbids network access.

## Install from the packaged file sets

`cargo package` tarballs are not produced for this workspace because the
sibling path dependencies are not on any index (ScopeBase crates are not
published). The equivalent packaged file sets are exactly the
`cargo package --list` contents of `scopebase-conformance` and
`scopebase-testkit`:

```sh
for crate in scopebase-conformance scopebase-testkit; do
  dest="vendor/$crate"
  mkdir -p "$dest"
  cargo package --offline --locked --list --allow-dirty -p "$crate" \
    | while read -r file; do
        case "$file" in
          .cargo_vcs_info.json|Cargo.toml.orig|Cargo.lock) continue;;
        esac
        mkdir -p "$dest/$(dirname "$file")"
        cp "crates/$crate/$file" "$dest/$file"
      done
done
cargo install --offline --locked \
  --path vendor/scopebase-conformance \
  --root "$HOME/.local"
```

The two vendor directories must stay siblings: the packaged conformance
manifest resolves `scopebase-testkit` through its relative path dependency.

## Fixture closure

The operator reads its offline inputs from a fixture root. The reference
closure ships inside the packaged crate at `delivery/`; copy it wherever
fits (a read-only prefix works, since runs never write there):

```sh
cp -r vendor/scopebase-conformance/delivery /opt/scopebase/closure
chmod -R a-w /opt/scopebase/closure
scopebase-conformance run \
  --catalog /opt/scopebase/closure/catalog.json \
  --profile operator-delivery-v1 \
  --fixture-root /opt/scopebase/closure \
  --output ./run-out
```

## Downstream crates

A downstream crate depends on the packaged crates with its own manifest and
embeds the operator library with its own adapter; see
`tests/downstream/conformance-client/` for the reference consumer,
runnable with:

```sh
cargo test --offline --locked \
  --manifest-path tests/downstream/conformance-client/Cargo.toml
```

Set `CONFORMANCE_FIXTURE_ROOT` to point the consumer at any installed
closure copy.

## Qualification

`tools/qualification/test_installed.py` replays this whole page from a
clean work directory: packaged sets, downstream consumer, install, and the
installed positive plus refusal matrix. Run it with:

```sh
python3 tools/qualification/test_installed.py --output /tmp/tt07-report.json
```
