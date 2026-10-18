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
`loss_units`, `package_boundary` and
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

CP04–CP13 still own lifetime/reducer/replay behavior, real reference
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
remain CP04/BP07; persistent per-claim rollup remains CP06; replay remains CP10;
real application consumers and installed operator conformance remain CP11/CP13.
No capture-runtime profile, product migration or publication follows from CP03.
