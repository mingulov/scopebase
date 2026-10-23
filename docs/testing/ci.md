# SPDX-License-Identifier: Apache-2.0
# TT08 causal CI

One coordinator runs affected-check selection and gates both on GitHub
Actions ([ci.yml](../../.github/workflows/ci.yml)) and locally
([ci_local.sh](../../tools/qualification/ci_local.sh)). The workflow invokes
the same script, so CI and local runs share selection, gates and verdicts by
construction; there is no second implementation to drift.

## Runners and secrets

- Runners: `ubuntu-latest` hosted runners only. No self-hosted or privileged
  runners, no containers, no kernel/BPF privileges. Every gate runs
  unprivileged; BPF live cells stay out of CI scope.
- Secrets: no secrets are required. The workflow references no
  `secrets.*` context. Cargo runs fully offline (`--offline`,
  `CARGO_NET_OFFLINE=1`); on GitHub a lockfile-keyed registry cache supplies
  the pinned dependencies, and a cache miss fails honestly instead of
  reaching the network.
- Coordination: one job per ref (`concurrency: tt08-${{ github.ref }}`).
  Cargo work serializes on the cooperative build slot via
  `bin/scopebase-build` with an explicit `--lock-root`; Cargo outputs land in
  a private run root (`CARGO_TARGET_DIR`), and no shared manifest is edited.

## Running locally

```sh
tools/qualification/ci_local.sh --changed-from HEAD --lock-root /tmp/scopebase-ci-lock
tools/qualification/ci_local.sh --changed-file changed.txt --lock-root /tmp/scopebase-ci-lock
tools/qualification/ci_local.sh --full --run-root target/tt08-full --lock-root /tmp/scopebase-ci-lock
```

`--changed-from` takes a git range (tracked diff plus untracked files);
`--full` revalidates the whole request (scheduled weekly on CI). `--lock-root`
must be an explicit absolute path. A recorded local run lives in
[ci-local-20261023.log](ci-local-20261023.log).

## Selection flow

1. `scopebase-select manifest` maps changed paths to a `ChangeManifest`
   through [impact-v1.json](../../profiles/impact-v1.json). Unmatched paths
   broaden to the whole request; they never vanish.
2. `scopebase-select select` runs `select_affected` over
   [cases-v1.json](../../profiles/cases-v1.json) and enforces
   selector/oracle agreement before writing the plan.
3. `scopebase-select resolve` maps selected cells to runnable gates or to
   explicit unavailable entries, and affected profiles to profile gates.
4. The script runs fast gates plus every affected profile gate and runnable
   cell gate to completion, recording pass/fail per gate.
5. `scopebase-select account` derives executed-vs-plan accounting from the
   actual selection; `scopebase-select gate` evaluates the retry gate over
   this run's own outcome.

Exit codes: `0` full matrix attested; `1` usage, tool or gate failure; `3`
incomplete with no failures (required checks unavailable or unexecuted).
A green run with unavailable required checks exits `3`: the verdict is
reported as incomplete, never as a quiet pass.

Exit `3` with zero gate failures is the intended narrowed-complete signal,
not an error: every runnable gate passed, but `full_matrix_complete` is
false (unavailable required checks or unexecuted cells, e.g. the SKIPped
`h33-license-admission` cell or any narrowed selection). Callers must treat
`3` as "no failures, qualification still open" — retrying the same selection
cannot turn it green, and only exit `0` attests the full matrix. Three H33
cells execute since the TT10 license-boundary lane; see
[h33-bindings.md](h33-bindings.md) for the per-cell audit.

## Impact map maintenance

When a case gains an executable registration, add `path_rules` entries for
its executable, fixture, oracle and bad-control sources, or those paths fall
through to the default unknown broadening (safe direction: full revalidation
plus an incomplete verdict until bindings exist). The H33 registration paths
keep that fallback deliberately: the checker/oracle are shared across three
cases and one changed path yields one change, so exact rules would
under-select. Profile gates run the
closest implemented package suite as regression signal; they do not attest
profile qualification and never mark cells executed. Only an explicit
`cell_bindings` command evidences a cell.

## Still planned

Parallel gate fan-out across runners, inherited prior-receipt evidence (the
`inherited` set is always empty in v1), multi-run retry chains (the gate
evaluates this run's outcome only), leased live cells, and the remaining
`h33-license-admission` live-kernel binding (TT05 lease). Until that lands,
any selection touching the admission cell reports incomplete; the other
three H33 cells execute.
