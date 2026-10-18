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

Each full command runs `domain_quantity`, `time_domains`, `package_boundary` and
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

CP03–CP13 still own counter/loss/lifetime/reducer/replay behavior, real reference
applications and the installed conformance route. This pure foundation does not
qualify complete capture profiles, live/native behavior, product migration or
publication. THIRD-PARTY-NOTICES.md retains the distinct optional dependency terms.
