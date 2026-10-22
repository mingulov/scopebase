# TT03 developer delivery, paths and concrete recipes

**PROPOSED narrow delivery amendment / unavailable today / NOT_RUN.**
The unchanged driver/binder/native rules below retain r4 predecessor scope.
New materialization/source selection is specified in
[materializer-contract.md](materializer-contract.md),
[closed field contract](materializer-contract.json),
[command DAG](materializer-command-dag.json),
[controls](materializer-controls.json) and
[source selection](materializer-source-selection.json). These are exact future file
and command interfaces; actual C7 product binding remains UNBOUND. They do not claim delivered
binaries, features, a registered profile or an executed package test. Bind actual
manifests/locks/artifact hashes before dispatch; commands must never silently
substitute a different testkit or Linux library.

Canonical shipped files are under `crates/scopebase-testkit/tests/fixtures/linux/`
(the include glob does not prove actual archive membership):

```text
README.md
worker/Cargo.toml.in
worker/LICENSE-APACHE
worker/THIRD-PARTY-NOTICES.md
worker/Cargo.lock
worker/src/main.rs
worker/src/lib.rs
worker/src/protocol.rs
worker/src/bin/image_b.rs
driver/Cargo.toml.in
driver/LICENSE-APACHE
driver/THIRD-PARTY-NOTICES.md
driver/Cargo.lock
driver/src/main.rs
materialize.py
test_materialize.py
bind_run.py
oracle.py
test_oracle.py
corpus/{header,body,invocation,handover,raw,snapshot,outer,input,controls}/*.json
catalog/core-v1.json
```

The archive has no actual nested Cargo.toml. The external inventory companion
and its caller-supplied digest ship beside the archive. Strict materialization
copies the whole verified package to OUTPUT/subject-testkit and creates only the
two literal manifests there; every frozen lock remains required and unchanged.
The generated tree is not repackaged as the original archive.

Worker is a standalone explicitly built package with bins
`scopebase-fixture-a` and `scopebase-fixture-b`, distinct compiled image markers
and distinct post-build artifact measurements. Its own `[workspace]` prevents
accidental root workspace resolution. Root-only `fixtures/linux/worker/Cargo.toml`
may point at those canonical source files; it has no separate implementation and
must not be needed by an extracted archive. No build.rs, PATH compiler search,
download or automatic helper build occurs on library use/native run.

Driver is separately locked, with testkit path `../../../..` from driver/ to
the extracted testkit crate, feature linux-fixtures explicitly selected and its
own `[workspace]`. Bin `scopebase-linux-fixture-check` exercises only the marked
`tt03.harness.core-v1` catalog. It implements the actual accepted ConformanceAdapter
in its executable, lending actual Files/process phase endpoints; it never
reports a separately resolved production library as the user's actual library.
It compares raw fixture/oracle, error/retirement/protocol behavior and emits the
ordinary actual RunReport plus separate native ledgers. It is a maintainer/
developer route, not an installed runtime conformance claim.

`bind_run.py` is a standard-library-only offline binder with exactly:

```text
bind_run.py --catalog ABS/catalog/core-v1.json --image-a ABS/scopebase-fixture-a
  --image-b ABS/scopebase-fixture-b --consumer ABS/scopebase-linux-fixture-check
  --fixture-inputs ABS/population-inputs.json --output ABS/new-bindings
```

It reads only the explicit files, rejects nonempty output, measures actual final
executables/canonical inputs, and writes fixture-manifest.json first, then
contract.json binding that manifest and actual consumer/images/oracle/catalog.
No self-hash cycle, candidate discovery or environment capability selection.
population-inputs.json uses the exact invocations/control/byte population selected
before discovery. Every invocation has driver_schedule=null or the exact
runner_deadline_after_ack schedule (exec-aba/s06-a2/30000ms execution, <=31000ms
hold, <=120000ms fixed outer allowance). It never becomes a worker control/action.
Binder checks full canonical InvocationKey/metadata/Hello/handover sizes and
population-specific terminal-envelope capacity before emitting contracts. The binder emits deterministic manifest/contract bytes for a
caller-supplied actual RunId; its RunId argument comes from fixture-inputs.json,
not an ambient timestamp fallback. Fixtures do not compile in this step.

Driver CLI is exactly:

```text
scopebase-linux-fixture-check --catalog ABS/catalog/core-v1.json
  --contract ABS/contract.json --fixture-manifest ABS/fixture-manifest.json
  --image-a ABS/scopebase-fixture-a --image-b ABS/scopebase-fixture-b
  --fixture-root ABS/exclusive-existing-root --output ABS/new-evidence
  --execution-ms POSITIVE_DECIMAL
```

The driver owns a bounded original asset guard before opening/moving the two
explicit image Files and caller root. Constructor Err restores the exact three
Files/paths and contract into that guard and separately returns opaque original
auxiliary custody. The driver invokes its close-only one-shot mutable finalizer,
then combines that AdmissionCleanupReport/ConstructorLedger with its own three
supplied-File close outcomes in AssetGuardReport. It never claims session finalization
or reconstructs an auxiliary owner from a report. Missing/low-budget auxiliary
cleanup preserves Unresolved. The same reserved 1MiB library slot moves exclusively
to success or failure custody; a second slot is not allocated. A successful
constructor moves those originals into the one LinuxFixtureSession. After every
normal runner Ok or Err return, end all access/resource/raw borrows and call its
mutable `finalize` exactly once with the prebound fixed outer budget. Repeated
calls can only retrieve its immutable report. Live context authentication is first
counted read-only campaign work; a guard failure seals Unresolved without cleanup.

Driver freezes/writes/hashes the current raw snapshots after the actual runner
returns and ends every borrow before mutable finalization. After finalization,
raw_ledger can only read existing seals or None. Driver output contains the actual unchanged RunReport (or original runner error),
immutable per-invocation Snapshot bytes and separate OuterReport. Constructor
failure instead has AssetGuardReport. The separate DriverHoldReport appears only
for the reached-runner-deadline schedule. Old snapshot/report bytes are hashed
before/after finalization to prove no mutation; descriptive copies never create
owners or transitions. A driver owns its fixed131072-byte storage separately
from the session retention cap, plus explicit output-byte/time allowances. It
must not exit clean while unresolved originals remain; the same session/guard or
failed-shutdown anchor retains them under the actual outer resource owner.

Driver's normal fixed outer cleanup budget is max_native_attempts=16384,
max_records=16384,max_retained_bytes=1048576 and an actual first-call absolute
deadline with remaining<=the contract retirement duration. It can choose smaller
prebound test allowances; these are not refreshed after failure. `deadline` must
be a checked Instant in the executing context, not reconstructed authority from
a receipt. End-to-end outer run deadline/wait allowance is separately fixed at
binding; the reached30s runner route's <=120s driver outer deadline cannot reset
TT02's execution/retirement clock. Every normal constructor/runner/error route
collects original cleanup truth before semantic assertions.

From an **extracted delivered testkit archive**, independently verify the
actual archive/companion bindings, provision the offline closure separately and
retain exclusive source/output ownership. Run the strict explicit materializer
before any archive worker/driver build:

```sh
python3 "$tt03_extracted/tests/fixtures/linux/materialize.py" --package-root "$tt03_extracted" --inventory "$tt03_inventory" --inventory-sha256 "$tt03_inventory_sha256" --output "$tt03_materialized_root"
```

Require normal zero completion, COMPLETE at
`$tt03_materialized_root/materialize-report.json`, its externally recorded digest
and independent immediate full map/template/lock recheck. Define `tt03_subject`
as exactly `$tt03_materialized_root/subject-testkit`. Then:

```sh
cargo +1.88.0 build --locked --offline --manifest-path "$tt03_subject/tests/fixtures/linux/worker/Cargo.toml" --release --bins --target-dir "$tt03_worker_target"
cargo +1.88.0 build --locked --offline --manifest-path "$tt03_subject/tests/fixtures/linux/driver/Cargo.toml" --release --bin scopebase-linux-fixture-check --target-dir "$tt03_driver_target"
python3 -m unittest discover -s "$tt03_subject/tests/fixtures/linux" -p test_oracle.py -v
python3 "$tt03_subject/tests/fixtures/linux/bind_run.py" --catalog "$tt03_catalog" --image-a "$tt03_image_a" --image-b "$tt03_image_b" --consumer "$tt03_driver" --fixture-inputs "$tt03_inputs" --output "$tt03_binding_root"
"$tt03_driver" --catalog "$tt03_catalog" --contract "$tt03_contract" --fixture-manifest "$tt03_manifest" --image-a "$tt03_image_a" --image-b "$tt03_image_b" --fixture-root "$tt03_fixture_root" --output "$tt03_output" --execution-ms "$tt03_execution_ms"
```

Repeat locked metadata/builds on 1.98.1 with separate target/result roots and the
same reviewed frozen workspace locks. Independent consumer keeps the original
sealed `U/materialized-testkit` unchanged and uses the distinct sibling
`U/consumer-assembly/{consumer,subject-linux,consumer-assembly-report.json}`.
Its own manifest uses `../../materialized-testkit/subject-testkit` and
`../subject-linux`; the delivered closed `verify-consumer` mode checks original
materialization identities plus the real consumer/Linux descriptor and receipt.
The exact CLI, shared bounds and first-lock presence/absence maps are in
materializer-contract.md/json. No unknown siblings enter the sealed root.
The complete bootstrap/package/inventory/materialize/control/recheck/build/native
order is frozen in materializer-command-dag.json; these examples are not that
execution manifest. First locks are generated only by the separate root-owned
source bootstrap, never by a delivered missing-lock exception.

Every variable must be explicit and nonempty; paths are absolute. Actual source,
archive, companion, tools/cache, locks, outputs/resources and bindings remain
UNBOUND; none of these absent commands can execute in this checkout today. On
the shared maintainer host each Cargo/resolver/native command uses the frozen
absolute wrapper
`/home/user/src/m/bpfscope/.scopebase/controller/build-routing-20261018/scopebase-build`
and common explicit lease, pinned absolute tools, fresh outside-worktree targets/
results and separately admitted native resources. Portable users declare their
own isolated resources; no maintainer wrapper path is a shipped dependency.

Actual source gates are proposed `cargo test --locked -p scopebase-testkit
--features linux-fixtures --test fixture_protocol` and the separately authored
packaged oracle tests. Run on both 1.88.0/1.98.1, default/no-default and relevant
archive feature unions after candidate/C7 binding. Optional dependencies/features
must remain absent from default host-only testkit resolution. Required affected
source/archive cells, MSRV, notices and exact runtime interpreter/library closure
must be recorded; an ELF digest alone does not freeze loaded runtime libraries.

A second independently locked external consumer uses its **actual**
scopebase-linux archive/version/features and implements its own actual adapter
for accepted HeldFile/read/control/parser operations over borrowed fixtures.
It is not another wrapper around the driver's mocked return values. LX08 process
operations join this consumer only once its real implementation/final contract
exists. Actual consumer manifest/lock/binary/API bindings remain UNBOUND. Bind
wrong-copy, wrong feature, wrong helper-digest and reopened-path active controls.
Dependency tests are not automatically run by ordinary downstream cargo test;
the explicit delivered command must be tested outside the checkout.

TT07 later supplies the existing installed interface:

```text
scopebase-conformance run --profile process-observation-v1
  --fixture-root PATH --output PATH [--fixture-manifest PATH]
```

Do not register the harness catalog as this capability profile. Source-free,
offline, read-only-prefix operation with prebuilt selected helpers, independent
actual consumer binding and full required native cells is a distinct unimplemented
delivery gate. No report, successful load, fixture harness result or donor test
constructs runtime observation/control authority.
