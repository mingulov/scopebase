# scopebase-capture

ScopeBase's pure Rust foundations for explicit capture/producer/binding/clock
domains, epochs and source provenance, same-unit checked counts, optional bounds,
checked partitions/conservation, and half-open time intervals. Fields are private;
constructors preserve the stated invariants. Errors are structured
`ContractError` variants without observation payloads.

```rust
use scopebase_capture::quantity::{Count, Events};
let events = Count::<Events>::new(2).checked_add(Count::new(3)).unwrap();
assert_eq!(events.get(), 5);
```

Caller-supplied opaque IDs reject the all-zero absent marker; numeric IDs and
epoch ordinal zero are valid. IDs name asserted domains and do not prove
uniqueness, loaded bytes or live authority. `Origin` retains an adapter's label.
Epoch exhaustion refuses instead of wrapping. Debug redacts opaque ID bytes,
including in nested values.

Counts range from zero through `u64::MAX`. Arithmetic refuses overflow/underflow;
parts overflow is checked before total mismatch. Conservation checks explicit
arithmetic: callers must establish disjointness, completeness and shared physical
provenance. Bounds with upper `None` remain unknown, distinct from `Some(0)`.

Timestamp ticks are **caller-supplied nanoseconds** in the named clock domain.
Intervals are half-open `[start,end)`, allow equal endpoints, check clock mismatch
before reversed endpoints and retain both endpoints. The library does not read
clocks, convert units/domains or infer suspend/time-namespace policy. The KryProbe
donor's inclusive intervals are deliberately distinct; no inclusive converter is
exported.

Fixed-size operations use O(1) work/storage; IDs scan 16 or 32 bytes.
`check_conservation` uses O(n) work over the supplied slice and O(1) extra storage.
These are not absolute elapsed-time, retained-byte, RSS, cancellation or cleanup
guarantees. There are no syscalls, runtime owners, logging, global state or
application dependencies in these APIs.

The default feature set is empty. Optional `json` enables exactly pinned `serde`
and `serde_json` for later replay work; it adds no serialization or replay API
here and does not change core semantics. There is no package build script. The
admitted optional closure may execute ordinary Rust dependency build scripts.
The initial compiler cells are Rust 1.88.0 and 1.98.1 on
`x86_64-unknown-linux-gnu`; other targets are not qualified by these cells.

From the extracted package, explicitly run the delivered development tests:

```sh
cargo test --offline --locked --no-default-features
cargo test --offline --locked --no-default-features --features json
cargo test --offline --locked --no-default-features --release --test domain_quantity
```

Each full command runs `domain_quantity`, `time_domains`, `counter_deltas`,
`loss_units`, `insertion_provenance`, `full_map_loss_contract`, `package_boundary` and
the successful/compile-fail doctests. Offline execution requires the exact locked
dependency sources prepared by the caller. Boundary tests require **Python 3.11+**
on PATH, with standard-library `tomllib`; Python is not a library runtime
dependency. Their helper parses manifests and refuses forbidden dependency/build
inputs without resolving or compiling them. Archive/source/notice admission is a
separate repository check.

`tests/ui/` ships a same-unit positive source and three external-client negative
sources: mixed units, sealed-unit implementation and private ID construction.
They are fixtures for an external Cargo client, not automatically executed as
integration targets. Ordinary downstream `cargo test` does not run a dependency's
tests or doctests; explicitly run the unpacked subject's commands above. Complete
installed operator qualification remains later work.

The tests preserve KryProbe `d153f3a` partition and reversed-interval vectors,
MemVeil `8307a17` mapped/copy byte-overflow vectors, OSSLscope `4bcb24c` seven/zero
bounds representations and two separately named libbpf-mojo `ff6ea50` conservation
vectors. The first three donors' historical GPL-3.0-or-later source labels are
separate from the author's authorized provisional Apache-2.0 userspace destination
grant. The libbpf-mojo source retains its Apache-2.0 WITH LLVM-exception terms;
only literal arithmetic vectors are selected here, without bridge implementation.
Exact source/range mappings and broader original regressions remain in the
repository's `docs/issues/capture/` register. These representation tests do not run
the donors' reducers, validated wire decoding or native adapters.

CP06–CP13 still own reducer/replay behavior, real reference
applications and the installed conformance route. This pure foundation does not
qualify complete capture profiles, live/native behavior, product migration or
publication. THIRD-PARTY-NOTICES.md retains the distinct optional dependency terms.

CP03 adds the pure `counter` and `loss` modules. `Sample` retains the full source
(including origin), channel, declared policy, clock, read interval and same-unit
count. Construction refuses invalid maxima, widths and out-of-range values.
Comparison refuses context replacement and reversed reads before arithmetic;
overlapping read windows yield `PartialRead`. Monotonic decreases are
`ResetOrWrap`. Saturating arrival at cap yields `AtLeast`; two observations
already at cap yield `Saturated`, while a decrease from cap stays `ResetOrWrap`.

Modulo observations require `AdvanceBound::new(&baseline, &current, maximum)`:
the caller explicitly asserts **no reset and at most that independently justified
advance for this exact immutable pair**. The constructor owns checked sample
clones and keeps the supplied maximum unchanged. It admits overlap and
contradictory/insufficient bounds; comparison handles those after pair/time
checks. Do not derive the bound from the observed residue, a library delta or
elapsed time alone. Bound construction cannot verify a real producer. Equal
sample values may reuse evidence; distinguishing identical-looking real
observations remains the adapter's responsibility. Missing explicit baseline
stays `MissingBaseline`, even with a matching bound. A strict bound below
`2^width` admits the unique residue only if it is within the bound; a conflicting
bound refuses, and a bound at/above the modulus remains `UnboundedWrap`.
Width64 arithmetic uses `u128` for the modulus.

`LossFact<U>` keeps source/channel/kind and `Exact`, `AtLeast` or `Unknown` in its
sealed unit. Every checked kind/unit combination is accepted; classification is
caller policy. Activity counts remain separate. `CappedLossSignal` keeps its
nonzero cap and observed byte. `fold_capped_signals` sums independent pre-capped
lanes with saturation and validates every lane, including after reaching cap.
A diagnostic255 has no conversion to255 omitted events. No total across units,
delta-to-loss conversion, rollup or report completeness policy is supplied.
Sample/bound/delta/fact traits work under only `U: Unit`, and nested Debug retains
ID redaction. Counter operations use fixed storage and O(1) work; signal folding
uses O(n) work and O(1) extra storage over the caller-admitted input slice.

Run the additional packaged tests and independent examples explicitly:

```sh
cargo test --offline --locked --no-default-features --test counter_deltas --test loss_units
cargo test --offline --locked --doc --no-default-features
cargo run --offline --locked --no-default-features --example counter_windows
cargo run --offline --locked --no-default-features --example diagnostic_lanes
```

Repeat with defaults and with `--no-default-features --features json` to check the
same contracts in each declared form. The two examples consume real APIs through
distinct paths; they are synthetic standalone users, not CP11's application
adapters. `counter_deltas` independently enumerates 4352 mathematical and 4352
literal-transition bounded cases plus 256 unbounded pairs. `loss_units` checks all
5,625,215 valid diagnostic pairs and invalid late lanes. CP03 UI fixtures add
mixed counter units and diagnostic-as-event-loss refusals, plus a generic
positive twin; they require an explicit external client diagnostic check.

The shipped Python3.11+ runner mutates disposable copies of production source,
checks semantic assertion failures and restored passing twins, and retains JSON,
diffs, compiler identities, hashes and raw logs. Existing output directories and
donor-snapshot inputs are refused. It requires the caller's prepared offline
`CARGO_HOME` and the common cooperative build wrapper; do not take an outer
build lease around this command:

```sh
SCOPEBASE_BUILD_WRAPPER=/absolute/path/to/bin/scopebase-build \
python3 tests/support/check_cp03_controls.py \
  --source-root /absolute/path/to/scopebase-capture-0.1.0 \
  --cargo /absolute/toolchain/bin/cargo --rustc /absolute/toolchain/bin/rustc \
  --feature-set no-default --output-dir /new/private/output
```

Use `default` and `json` for the other feature forms. Each command has a 120-second
execution limit, retains process-group retirement status and treats compile,
setup or timeout failure as `INVALID_CONTROL`. Initial offline lock generation
occurs only in the disposable copy; subsequent builds use `--locked --offline`.
The caller owns these explicit filesystem/process verification effects. Ordinary
downstream dependency tests still do not execute any of these package tests.

The K capped-fold and saturation vectors and O missing-baseline/source/unit
semantics are preserved in this increment under the admitted owned-source
Apache-2.0 destination grant, independently of their historical GPL labels.
Full identity-map storage, producer baseline acquisition/order and live behavior
have CP04 host models below and retain BP07 live obligations; persistent per-claim rollup remains CP06; replay remains CP10;
real application consumers and installed operator conformance remain CP11/CP13.
No capture-runtime profile, product migration or publication follows from CP03.

CP04 supplies `provenance::{ObservedIdentity, IdentityUnknown, LaneIdentity,
ProvenanceLane, InsertionFold, fold_insertion_identity}`. Exactly one explicit
insertion owner supplies identity, including genuine numeric zero. Every exact
lane contributes its count, including secondary lanes and a zero-count owner.
`ProvenanceLane::new` admits exact `u64::MAX`; `saturated` records a nonexact
count and refuses folding. A raw donor MAX must be converted explicitly to the
latter by its adapter. Missing/conflicting ownership precedes arithmetic. With a
unique owner, the first saturated lane or overflowing exact prefix in slice
order wins. Result refusals return no partial fold.

Constructors move payloads. Folding performs at most two passes, O(n) library
work/O(1) auxiliary storage, then clones the unique identity once on success;
it never calls payload Eq. Generic traits impose no additional Unit marker
bounds, and Debug never formats identity payloads. The caller's Clone can
allocate, block, mutate interior state or panic. ScopeBase does not mutate the
borrowed slice, wrapper fields or count states, but cannot undo caller Clone
effects. No payload immutability, retained-byte, elapsed-time, interruptibility,
Send/Sync or extra unwind guarantee follows.

```sh
cargo test --offline --locked --no-default-features --test insertion_provenance --test full_map_loss_contract
cargo run --offline --locked --no-default-features --example insertion_journal
cargo run --offline --locked --no-default-features --example cache_attribution
```

These shipped host tests preserve all seven KryProbe migration/race/zero shapes,
full gate256/attribution2048 plus a failed key, and below-capacity128 populations.
An independent finite owner/u128 oracle supplements them. The bounded test-only
models adapt selected KryProbe `d153f3aaf9a3931337b47c9e1b046c692da55083`
PcpuWho/Sim* source; the production fold preserves its unique-owner scan,
ordered count refusal and owner selection. Generic wrappers, typed saturation,
oracles and runner are new mechanisms. Historical GPL-3.0-or-later labels remain
separate from OWNER-2026-10-18's Apache-2.0 host/test/data authorization. No BPF
source, layout or third-party grant is added; exact ranges and final bindings are
in the repository's CP04 selected-port/preservation records.

The authoritative `fixtures/insertion-v1.json` is a bounded schema1
`cp04-host-vectors` corpus, separate from future replay. The delivered Python
3.11+ helper reads at most65537 bytes and rejects input above65536 bytes,
duplicate/unknown fields, incorrect scalar kinds/ranges, noncanonical integers,
missing required populations and count limits before generating any Rust. It
then compiles and executes literal corpus assertions against the actual selected
package, plus semantic mutations/restored twins in disposable copies. Models
admit at most4 CPUs,2 diagnostic slots and2048 table entries; fixed scripts have
at most2049 operations. These cardinalities are not heap-byte bounds.

Regenerate/check the source checkout's compatibility mirror from its sole
package authority:

```sh
python3 crates/scopebase-capture/tests/support/check_cp04_controls.py sync-mirror --source-root "$PWD/crates/scopebase-capture" --root-mirror "$PWD/fixtures/capture/insertion-v1.json"
python3 crates/scopebase-capture/tests/support/check_cp04_controls.py check-fixture --source-root "$PWD/crates/scopebase-capture" --root-mirror "$PWD/fixtures/capture/insertion-v1.json"
```

From an extracted package, run the source-free helper with explicitly prepared
offline dependency inputs and pinned installed tools:

```sh
CARGO_HOME=/absolute/prepared/offline-home \
python3 tests/support/check_cp04_controls.py run \
  --source-root /absolute/path/to/scopebase-capture-0.1.0 \
  --cargo /absolute/toolchain/bin/cargo --rustc /absolute/toolchain/bin/rustc \
  --feature-set no-default --output-dir /new/private/output
```

`check-fixture` supplies parsing/custody evidence only; `run` executes tests.
Repeat `run` with `default` and `json` for the other forms. The default route is
direct Cargo: inherited `SCOPEBASE_BUILD_WRAPPER` is ignored. In a coordinated
repository campaign, pass `--build-wrapper /absolute/path/to/bin/scopebase-build`
explicitly for per-Cargo leases, without an enclosing lease. Standalone callers
own their scheduling; the helper neither acquires nor verifies an outer lease.
`CARGO_HOME/config.toml` must explicitly refer to already prepared offline
sources. No dependencies or tools are installed; source trees/archives remain
unchanged. Fresh outputs contain copies, targets, generated tests, locks, diffs,
identity/config hashes, argv/environment and child-group retirement records.
Timeouts (120 seconds per command), setup/compiler errors or incomplete cleanup
(10 seconds retirement allowance) are INVALID_CONTROL, never semantic kills.

The two examples are distinct actual but bounded consumers: tuple/Events
insertion journal and String/Objects cache accounting. They do not complete CP11
application reducers or CP13 installed conformance. Independent capped loss
storage is required of a real producer; these full-table models cannot prove
kernel insertion/migration, actual wire stride, writer partition/reentry, attach
cleanup or live support. BP02/BP07, CP05/CP06/CP10/CP11/CP13 and MG03 retain those
obligations; no runtime profile or product migration is qualified here. The
preexisting CP03 helper's explicit-wrapper portability limitation remains later
TT07/CP13 work; CP04 does not change that accepted helper or its receipts.

CP05 adds `generation::{ObjectKey, require_generation}`. Construction moves a
complete caller-supplied epoch, raw identity and generation; raw zero and supplied
generation zero/MAX are valid. `next_generation` refuses MAX with
`ArithmeticOverflow` before invoking the payload's Clone, and clones exactly once
on success. A caller's Clone result is retained without an equality check.
Matching compares the complete epoch, object generation and complete raw identity
in that order. Metadata mismatch invokes no raw equality; otherwise PartialEq,
`matches` and `require_generation` each invoke it exactly once. Every false
`require_generation` relation returns `GenerationMismatch`.

Put all necessary raw identity domains in `K`: device, namespace and token, for
example. ScopeBase adds no process birth, filesystem, BTF, source binding,
configuration revision or identity authority. Unknown observations keep separate
event IDs outside the known-key registry. A generic constructor cannot recognize
an arbitrary caller-supplied unknown sentinel. Two equal Unknown reasons must not
be converted into one shared object key.

Clone/PartialEq/Eq require only their corresponding payload trait; Debug requires
no payload Debug and never formats the raw value. Send/Sync follow the fields.
The wrapper adds fixed metadata work and no syscalls or lifecycle effects.
Caller Eq/Clone may allocate, block, panic or mutate shared interior state; those
effects cannot be undone. Borrowed wrapper fields remain in place on refusal or
unwind. There is no payload-byte, callback-time, OOM or native cleanup bound.

From the extracted package, run CP05 explicitly with the prepared offline inputs:

```sh
cargo test --offline --locked --no-default-features --test generation_histories
cargo run --offline --locked --no-default-features --example transform_generations
cargo run --offline --locked --no-default-features --example mapping_generations
CARGO_HOME=/absolute/prepared/offline-home \
python3 tests/support/check_cp05_controls.py run \
  --source-root /absolute/path/to/scopebase-capture-0.1.0 \
  --cargo /absolute/toolchain/bin/cargo --rustc /absolute/toolchain/bin/rustc \
  --feature-set no-default --output-dir /new/private/output
```

Repeat with defaults and `--no-default-features --features json`; the helper's
feature selections are `no-default`, `default` and `json`. The declared compiler
cells are 1.88.0 and 1.98.1. The helper uses direct tools by default. For coordinated
builds, explicitly pass `--build-wrapper /absolute/path/to/scopebase-build`
without holding an outer lease. For the standalone route under an external
lease, omit that option. Every compiler/Cargo/binary child follows the selected
route. The helper rejects existing or unsafe output roots before mutation,
generates offline lockfiles in disposable copies, and records exact source,
changed/restored hashes, diagnostics, commands, tool identities and child-group
retirement. A wrapper refusal is NOT_RUN; setup errors, a wrong compiler site,
timeout or unresolved cleanup never qualify a semantic mutation. Its command
watchdog is 2400 seconds, including wrapper acquisition. The bounded collector
uses a separate two-second direct-child wait and another two-second wait after
an attempted kill; it conservatively retains unresolved group/resource cleanup.
These are harness controls, not product callback bounds.

The delivered `tests/support/cp05_bounded_process.py` is a byte-for-byte copy of
the accepted ScopeBase testkit `tests/fixtures/fixture-access/bounded_process.py`
(SHA256 `81e371cec788e07df9139695f8f52b07fa653b1b93d36bbf8fd41ce2d8ef5bdd`),
itself exact accepted `tools/build/common.py` excerpts. It captures at most
4 MiB per stdout/stderr stream and hashes in fixed-size chunks. The CP05 adapter
reserves and checkpoints a command row before launch, attaches the collector's
PID/primary error/cleanup facts before lease parsing, and refuses incomplete
collection, resource closure or postprocessing. Lease metadata is limited to
16384 bytes. A successful child exit does not erase a collection or cleanup error.
The helper runs twelve delivered failure checks with owned tiny children; run
them separately with a fresh output when diagnosing the harness:

```sh
python3 tests/support/test_cp05_process.py --output-dir /new/private/process-checks
```

These checks inject collection/read/write/wait/close/hash/group/lease errors and
exercise setup, timeout and numeric log bounds. They retain reserved rows, exact
primary/cleanup outcomes and logs. Each external client also has its own target
directory; both compiled executables remain available at distinct recorded paths
with their original hashes after the second client runs.

The delivered target contains ten direct cases, seventeen named normalized donor
subsets and additional literal limits/domain/compaction cases. Its independent
journal compares all 55,987 scripts/324,726 actions at every prefix; each script
has at most six action rows and eighteen facts. K pending/live/retired tables
each have capacity two in that population. Separate longer K/M originals and
multi-raw/capacity/foreign-epoch vectors remain necessary; these count/work bounds
do not bound generic payload bytes or whole-process memory. K submit-bound IDs
survive retired-only storage compaction, forced old boundaries stay ambiguous,
and scripted first-seen unknown creation is counted once at admission. M retains
its own identity-present reader gate and retired ring with sticky uncertainty.

The helper checks nine direct production mutations, separate adapter mutations,
fixed no-Debug/Send compiler controls and restored positives. It also creates two
distinct external packages from the examples, each with its own manifest, lock,
metadata, actual subject version/features and literal journal outcomes. The
transform client owns submit/reuse/config/retire handling; the mapping client
owns structured domains, distinct unknown events and a bounded retired ring.
Neither imports test support or a shared reducer. Ordinary dependency tests do
not run these checks; invoke the unpacked package and helper directly.

These are pure scripted T0/T1 and scoped package/reference-consumer evidence.
The local positive-generation fixture does not restrict generic ObjectKey's
zero/MAX values. K first-seen implementation bodies, wire/refcount handling and
M text validation/rendering are deliberately deferred. CP08 ordering, CP10 replay,
CP11 actual application adapters, CP13/TT07 installed conformance, full profiles,
UC14 and MG runtime/duplicate retirement remain separate gates.
