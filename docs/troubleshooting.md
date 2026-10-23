# Operator troubleshooting (TT07)

## Exit 3: `ClosureIncomplete` / `MissingInput`

A required input is absent. Check that `--catalog`, `--fixture-root` and
`--output`'s parent exist, then run `plan`: it lists exactly which closure
files are missing without executing anything. A refused run writes no
receipt; fix the inputs and rerun.

## Exit 64: `BrokenPackage`

Closure bytes do not match `fixture-manifest.json`, an H33 notice is
missing, or the linked subject differs from the template coordinates.
Re-copy the closure from the packaged crate instead of hand-editing it:
every byte is pinned. If the error names the subject, the binary was built
from different sources than the template pins — rebuild the operator and
the closure from the same tree, or, for a downstream adapter, author a
template pinning that adapter's own coordinates (see
`tests/downstream/conformance-client/`).

## Exit 64 on `cargo package` for the workspace

Full `cargo package` tarballs fail because sibling path dependencies
(`scopebase-bpf`, `scopebase-linux`) are not on any index. This is a
standing workspace property, not an operator defect: qualify the packaged
file sets with `tools/qualification/test_installed.py` instead.

## Exit 1: `ReceiptInvalid`

The receipt was modified after the run, or it belongs to a different
report than its seal covers. Re-run to produce a fresh receipt; never
hand-edit `receipt.json`. `verify-receipt --catalog PATH` additionally
re-admits the report through the engine and names the failing layer.

## `cleanup` refuses with exit 3

The target is not an operator run directory (no `run-manifest.json`) or
`--expect-run-id` names a different run. Nothing was deleted. Point
`cleanup` at the exact `--output` directory of a run.

## Permission errors on a read-only prefix

Runs never write to the fixture root, but the closure files must be
readable and `--output` must be writable. Keep the closure read-only and
pass a scratch output directory.

## The run qualifies but my application is not certified

Correct: a standalone operator result qualifies only its compiled subject.
Application embeddings must run the profile through their own adapter and
resolved versions. A receipt is historical evidence, never runtime
authority.
