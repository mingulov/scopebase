# BP03 descriptive host model checks

This delivered route builds and runs two independent consumers against the
explicit BPF and testkit package roots. It runs supplied T0 models. Its results
confer no native BPF capability, probe execution, kernel support or operator
profile support. An imported record retains its claimed origin separately from
its local `Imported` origin.

Invoke `run_consumers.py` with `--package` (the BPF root),
`--testkit-package`, a fresh absolute `--out` outside the package roots,
`--toolchain` (`1.88.0` or `1.98.1`), its absolute `--toolchain-root`, and the
absolute `--cargo-home` and `--cargo-config`. Each toolchain root must contain
`bin/cargo`, `bin/rustc` and `bin/rustdoc`. No tool or dependency is installed or
fetched. The offline config must select the explicit checksummed vendor tree;
all source file checksums and each generated lock closure are checked.

For controller use, supply the explicit absolute `--build-wrapper`. The helper
wraps each child once. When an operator explicitly wraps the whole helper,
omit this argument so children use that one inherited lease. Targets, temporary
files, source copies, logs, immutable checkpoints, metadata and executables
remain in the fresh output directory. The child environment uses
`CARGO_INCREMENTAL=0`. Effective Cargo configs are checked for each child cwd.

| Mode | Direct BPF raw features | Testkit raw features | Client raw features |
|---|---|---|---|
| core-default | default | bpf-host, default | none |
| core-minimal | none | bpf-host | none |
| json-union | json | bpf-host, bpf-host-json | json |

Both client templates declare the literal empty `json` feature and retain the
same source bytes in all modes. The cache consumer checks exact contexts,
receiving profile domains, imported getters and canonical encoding. The
population consumer uses the public registry, plan, contract, bundle, fixture,
adapter, oracle, runner and report APIs, with 38 fixed input populations per
mode. Its JSON mode additionally executes context/origin/description/strict
codec cases and imports the resulting report. The oracle reads independent
literal expected bytes; it never calls the subject to compute an expectation.

`catalog-core.json` and `catalog-json.json` register the finite model subsets.
The helper binds their selected source, fixture, oracle and control bytes to
actual copied package files before execution. `bundle-template.json` records
the binding recipe; generated bundles contain actual byte lengths and hashes.
Primary model inputs and expected values are read from the BPF package's
`fixtures/capability-v1` directory. No expected population is regenerated from a
subject API.

A bounded completion witness is checked against an external required group
list. JSON dependencies with the client's own JSON feature omitted must refuse
`BP03_CLIENT_JSON_COVERAGE_MISSING` with no accepted groups. Activating that
feature in a core mode refuses `BP03_CLIENT_JSON_MODE_MISMATCH` before Cargo.
Actual command success without the required completion groups is incomplete.

The standalone BPF package's `tests/support/check_bp03_controls.py` checks its
public API boundaries and semantic mutants. The repository driver
`tests/package-policy/bp03/controls.py` also exercises adapter controls, measured
joint allocation bounds and the real foreign-path binding negative. These
routes retain wrong and restored sources, executed binaries and bounded logs.
The embedded process collector is byte-identical to accepted TT02 collector
SHA256 `81e371cec788e07df9139695f8f52b07fa653b1b93d36bbf8fd41ce2d8ef5bdd`;
its pre-reserved structured-row wrapper follows the CP05 custody repair.

Evidence uses immutable schema 2 command lifecycle events and finite sidecars.
Static source/tool/offline/environment bindings and all fixed obligations are
sealed after staging and final workspace preparation, before the first child.
Every serial request has a durable `reserved` event; a returned collector result
is attached unchanged and published as `collected` before lease or semantic
processing. `complete` references that exact result. Dynamic source snapshots,
validated locks, graph projections and retained executable hashes remain bound
to the actual command. Wrong, source-restored and restored-positive result
phases remain separate.

A reservation's null process group describes only its creation instant.
Interruption before collection returns leaves unknown execution custody and
cannot authorize automatic retry or ownership release. Publication or later
processing failures permanently stop dispatch; the first full in-memory child
custody survives in the raised failure. Primary collector facts and wrapper
errors remain separate.

`receipt.json` contains the full aggregate once. File/directory durability and
actual successful producer return are required for parent acceptance: a visible
`PASS` receipt alone is insufficient. An uncertain final publication cannot be
retried or converted to a successful result. No event is replaced or deleted.
Source/archive campaign admission and strict response-F remain separate gates.
