# TT02 archive execution

The task driver builds both original TT01 client sources and both TT02 sources
explicitly against the delivered source and archive, under Rust 1.88.0/1.98.1 and
minimal/default. The common helper's first-client route alone cannot prove these
four executions. `tt02-run` drives real vector/session/adapter/oracle APIs with a
wrong-value control. `tt02-receipt` imports separately authored failure receipts
and rejects a false-green terminal; it does not call the report producer.

Both TT02 binaries accept a corpus directory followed optionally by independent
expected and actual generated measurement files. Those arguments are compared by
the same linked executable that the post-build binder measured. T0 model checks
and actual host executable measurement remain separate evidence tiers.

The host manifest names the actual binary target's inline case, oracle and active
control source as separate measured roles. For the receipt client these are the
import/check/false-green assertions in its own main source; they do not replace
the imported producer binding. Its fixture artifact is the literal failed
receipt; the runner's is the exact bundle manifest used by its corpus argument.
The binder compares each selected source path with the actual Cargo binary
target, and the driver freezes source hashes before building and verifies them
afterward. A separately compiled valid receipt implementation cannot substitute
for the runner's selected case or oracle while retaining the same executable.

Expected resolved features are a finite literal derived from the admitted Cargo
manifest declarations in `expected-features.json`. The build's metadata supplies
the observed records; it does not supply those expected feature sets. Actual
same-version source/archive and minimal/json controls remain separate checks.

New staging runs use the job's root-ratified `source-copy-bound-20261018`
`run-with-admitted-helper.py` launcher, retaining its exact helper/launcher hashes.
The absolute controller `--build-wrapper` remains required for every Cargo
command; the launcher acquires no build lease.
