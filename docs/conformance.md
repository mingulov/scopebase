# ScopeBase conformance operator (TT07)

The `scopebase-conformance` command runs versioned conformance profiles from
explicit offline inputs. It is the installed operator route: no repository
checkout, no network and no compiler toolchain are required at run time.

## Commands

All paths are explicit; there are no repo-relative defaults.

```sh
scopebase-conformance describe --catalog PATH
scopebase-conformance plan --catalog PATH --profile ID --fixture-root PATH \
  [--mapping-policy POLICY]
scopebase-conformance run --catalog PATH --profile ID --fixture-root PATH \
  --output PATH [--fixture-manifest PATH] [--contract-template PATH] \
  [--mapping-policy POLICY]
scopebase-conformance verify-receipt PATH [--catalog PATH]
scopebase-conformance cleanup --run PATH [--expect-run-id ID]
```

- `describe` lists the profiles and cases in a catalog. Pure: reads only the
  catalog bytes and creates no files. Its JSON carries
  `"qualification": "not_evaluated"`: describing claims no support.
- `plan` expands a profile selection and accounts the fixture-root closure
  (present, missing and mismatched files). It performs no active setup and
  its effects list is always empty; an incomplete closure is reported, not
  executed. Its JSON likewise carries `"qualification": "not_evaluated".
- `run` verifies the closure, checks the linked subject against the frozen
  template coordinates, binds a fresh run contract plus vector manifest, and
  executes the profile through the testkit engine. Output goes only to
  `--output` (receipt, run manifest, staged contract/bundle). The fixture
  root is never written, so it may live on a read-only prefix.
- `verify-receipt` checks a receipt envelope (schema, seal, bindings,
  verdict shape). With `--catalog` it additionally re-admits the embedded
  report against the staged contract through the engine.
- `cleanup` removes a run directory only after its run manifest checks out;
  anything else (or a wrong `--expect-run-id`) is refused without deletion.

## Exit codes

| Exit | Meaning |
|---|---|
| 0 | success: describe/plan emitted, run qualified, receipt valid, cleanup done |
| 1 | verdict failure: cases failed, or a receipt is invalid or tampered |
| 2 | usage error: bad argv, unknown option or mapping policy |
| 3 | incomplete: missing input, unknown profile, no bound adapter, refused cleanup |
| 64 | broken package: tampered closure, missing notices, mismatched subject |

## Offline inputs

A run needs three explicit inputs:

1. A versioned case catalog (`--catalog`).
2. A fixture root (`--fixture-root`) carrying `fixture-manifest.json`, which
   pins every readable file by relative path, length and sha256, including
   the H33 notices. Missing files are incomplete (exit 3); wrong bytes or
   missing notices are a broken package (exit 64).
3. A writable output directory (`--output`).

`--fixture-manifest` and `--contract-template` default into the fixture root
and are the only path defaults. No input is ever resolved against a source
checkout, and the route performs no downloads or compiler installs.

## Binding rules

- The operator regenerates the run contract on every invocation from the
  verified template plus the linked adapter's measured subject. A
  differently resolved library (different package, version, source or
  consumer) is refused before execution: a standalone result never silently
  qualifies another application's embedded version.
- Downstream consumers embed the `scopebase-conformance` library with their
  own adapters and their own templates pinning their own coordinates; see
  `tests/downstream/conformance-client/`.
- `--mapping-policy` accepts `no-new-target-mappings` (default) and
  `allow-private-calibration`; the choice is recorded in the plan and the
  receipt. Unknown policies are usage errors.

## Receipts

Every run writes `receipt.json`: the engine report sealed with a sha256 over
the envelope, the measured subject, the selection, the fixture-manifest
digest and the mapping policy. Each receipt carries
`"runtime_authority": false` plus an explicit statement: a receipt records
observed historical evidence only and certifies no other build, version or
embedding.
