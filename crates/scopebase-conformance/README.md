# scopebase-conformance

TT07 installed operator command and downstream package delivery.

The `scopebase-conformance` binary runs versioned conformance profiles from
explicit offline inputs. See [docs/conformance.md](../../docs/conformance.md),
[docs/install.md](../../docs/install.md) and
[docs/troubleshooting.md](../../docs/troubleshooting.md).

## Layout

- `src/`: operator library plus the `scopebase-conformance` binary.
- `delivery/`: the frozen installed closure for `operator-delivery-v1`
  (catalog, contract template, vectors, registered sources, H33 notices).
  The closure manifest pins every byte; see `delivery/fixture-manifest.json`.
- `tests/`: operator suite (typed refusals, read-only prefix, receipts).

## Reproducing a run

```sh
cargo run --offline --locked -p scopebase-conformance -- \
  run --catalog crates/scopebase-conformance/delivery/catalog.json \
  --profile operator-delivery-v1 \
  --fixture-root crates/scopebase-conformance/delivery \
  --output /tmp/tt07-run
```

Installed-route qualification lives in
`tools/qualification/test_installed.py`.
