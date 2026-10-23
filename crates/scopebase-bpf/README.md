# scopebase-bpf

ScopeBase 0.1.0 provides host error/limit values, bounded descriptive possible-CPU
geometry, and an owned perCPU map reader on x86_64 little-endian GNU Linux.
Default and `--no-default-features` use the same host implementation. Neither
requires a BPF compiler, loader, program, build script, or privileged setup for
ordinary tests. The native target uses exact rustix 1.1.5, libc 0.2.191 and
sha2 0.11.0 dependencies. The supported compiler inputs are 1.88.0 and 1.98.1;
qualification records bind the actual compiler, features, source and environment.

`OperationError` preserves kind, stage, errno, source and optional required bytes
independently. Its bounded formatting never formats its source. `Limits` has six
explicit independent caps; every representable configuration is structurally
valid. Zero/MAX confer no native authority or exception to checked accounting.
Existing BP01 behavior remains unchanged.

The optional `btf` feature adds host-only bounded domain-aware BTF parsing
(`scopebase_bpf::btf`) over the locked btf-rs 2.0.0 parser at revision
`0a5838f8dad54b6da9a7b0539f1e2d7aeeb009a0` with default features off; only
byte-slice constructors are used, never file or mmap inputs. A narrow
preflight enforces caller byte/type/string/work caps and a 16 MiB
initial-profile ceiling before the parser materializes anything, binds the
admitted bytes into a SHA-256 domain id, and fails hostile images typed.
Run its suite explicitly: `cargo test --offline --locked --features btf
--test btf`. The feature keeps no native state and confers no loader,
kernel or runtime authority.

The optional `adapters` feature adds narrow adapters over existing BPF
loaders (`scopebase_bpf::adapters`): Aya, libbpf and bpfman shapes over
the attach seams with `Arc<HeldFile>` authority, plus native configure
and output-span contract vectors (`fixtures/bpf/native/`). The Aya shape
is fully proven over scripted doubles; the real binding over upstream
aya =0.14.0 compiles behind the further `aya` feature. libbpf is
shape-only (`libbpf-rs` was unavailable offline) and bpfman is
shape-only by design. Run each suite explicitly, e.g. `cargo test
--offline --locked --features adapters,json --test aya_adapter`. Live
attach cells need a privileged kernel and stay NOT_RUN here.

`CpuTopology::parse_possible` accepts bounded ASCII kernel CPU lists, preserving
strictly ascending IDs and exact original bytes. It refuses overlap, malformed
input, out-of-range IDs and expansion limits. `PerCpuGeometry::checked` rounds
values to eight bytes and multiplies by possible lanes, including offline lanes.
These pure values cannot authorize a native syscall.

`ValidatedMap::from_owned_fd` consumes an actual owned FD, verifies map metadata
and a real-map/readability witness, optionally compares the SHA-256 of its actual
linked raw BTF image, and acquires its own authentic topology. It supports
perCPU hash/array maps, with explicit metadata and reader-safe flag checks.
Bloom lookup refuses immediately after the metadata query. No producer/object
attachment or semantic BTF layout is inferred from a schema label or image hash.

The reader retains genuine complete sysfs/procfs roots, possible, thread-self
and the original task directory. Native source reads require newline, EOF and
at most 4094 bytes. Each lookup checks context and sources before/after the
kernel copy, including exact original task text and one fresh original-relative
stat byte. Failed revalidation permanently poisons the owner. Recovery requires
a newly acquired owner. Both live owners are move-only, !Send and !Sync, without
raw descriptor access or imported topology constructors.

Native memory safety assumes the documented Linux ABI: the global possible
mask is boot-fixed and agrees with the sysfs attribute and perCPU copy; retained
map/BTF metadata is immutable; kernel pointer extents and root semantics conform.
Source checks detect observed substitution; they do not prove an arbitrarily
changing kernel mask safe. Runtime facilities fail closed. Kernel version text
and qualification reports do not supply native authority.

`lookup` returns packed opaque lane bytes in sorted possible-ID order.
`lookup_into` copies only after successful lookup and postvalidation; a long
output keeps its tail, and absence/error leaves the entire output unchanged.
A short output returns the exact required extent before querying topology.
Lookup is a kernel read, without an atomic snapshot guarantee across producers
or lanes. Dropping the FD does not establish producer/attachment retirement.

The byte, work and retained-capacity bounds are independent. Work charges precede
effects; fallible reservations are checked against observed logical capacities.
Allocator bookkeeping/RSS, compiler stack overhead and syscall wall time are not
bounded. Five FDs are retained by topology and six by a map owner, with twelve
owned at most during validation. Fixed declared native buffers fit 32 KiB.
No retry, host-limit change, namespace mutation, subprocess or map creation is
performed by the production library.

Run delivered ordinary tests from source or an unpacked archive:

```sh
cargo test --offline --locked --all-targets
cargo test --offline --locked --doc
python3 tests/fixtures/bp02/generate_vectors.py --check
```

The package ships independent fixture data, the generator, two standalone
consumer templates (`Cargo.toml.in`, materialized only in private clients), API/UI controls, semantic-mutant drivers, and explicitly
ignored native fixtures. Downstream `cargo test` does not execute dependency
tests. Run both consumer clients and compile controls explicitly, using an
already prepared offline cache and installed compiler root:

```sh
python3 tests/fixtures/bp02/run_consumers.py --package . --out /PRIVATE/consumer-run \
  --toolchain 1.98.1 --toolchain-root /ABSOLUTE/TOOLCHAIN --cargo-home /ABSOLUTE/CACHE
python3 tests/fixtures/bp02/run_mutants.py --package . --out /PRIVATE/mutant-run \
  --toolchain 1.98.1 --toolchain-root /ABSOLUTE/TOOLCHAIN --cargo-home /ABSOLUTE/CACHE
```

Each helper runs default and no-default consumers explicitly. `--build-wrapper
/ABSOLUTE/WRAPPER` optionally wraps heavy children; alternatively wrap the whole
helper once. Never nest the routes. No compiler/cache is discovered through mise,
HOME or PATH. UI positives must compile; negatives require their specific
E0277/E0599/E0308 diagnostics. Existing BP01 UI controls remain shipped.

The mutant driver selects 24 cases per compiler: 12 mutate production-library
source and 12 mutate the delivered `tests/support/who_fixture.rs` model. Across
the two selected compilers this is 24 production-library and 24 test-model
checks. Every Cargo invocation is direct, but that does not make a model
mutation a library check. The three stale-80 variants require their distinct
named rejection assertion to fail; a later valid-input panic is rejected by
the driver. Each case also requires its positive and restored positive run.

`possible_topology` reads a caller CPU-list file and value size. `who_map_reader`
has distinct offline fixture and `--native` modes. WHO88 is fixture/report code,
without a generic public crypto schema. Its decoder/fold preserves unique
insertion provenance, latest-writer fields, zero-valued identity, per-lane MAX
refusal, exact representable final MAX, and whole-report failure on a missing
known row. Producer-side tests are models; native userspace population does not
qualify a BPF winning-inserter race.

Native N1–N9 and original-task cells require explicit owned Linux resources,
BPF/BTF permissions, private mount/PID namespaces, at least two possible CPUs and
an offline lane. Use `run_live.py --help` for direct/prebuilt routes. The helper
never offlines host CPUs or provisions a guest. A missing positive remains
BLOCKED/NOT_RUN, and ignored ordinary tests are no live evidence. Resource
receipts coordinate ownership; the actual library still authenticates sources.
Prebuilt execution binds executable/build inputs and actually runs tests. The
direct route builds both feature modes and all bounded controls. `--prepare-only`
returns PREPARED_NOT_RUN and writes bound prebuilt specifications for explicit
transport; it executes no native acceptance case. Shipped entrypoints suppress
local bytecode caching before sibling imports and preserve the subject files.
The prebuilt route requires `--feature default` or `--feature no-default` and
checks that request, the compiler, package manifest, admitted resource digest
and resource identity against the prepared spec before native execution. The
shipped `tests/fixtures/bp02/payload_run.sh` is the guest payload run template;
`payload_summary.py` checks both source-mode bindings, child reaping and owned
temporary-root cleanup plus both archive native-client modes. A failed setup,
semantic control or cleanup leaves a failed receipt/summary and does not count
as an expected refusal. Payload staging and guest execution remain operator
controlled.

Disposable source fixtures report their exact child-PID temporary path and its
device/inode for corroboration after child exit. Receipts preserve each child,
root cleanup, guarded mapping cleanup and internal fork wait independently.
Missing/mismatched reports and unresolved cleanup fail qualification; a reaped
outer process cannot certify an unresolved internal child. These trusted fixture
checks do not protect against a hostile same-UID path replacer. Ordinary tests
include local after-root failure, identity/refusal, guarded-mapping rollback and
bounded wait controls without creating BPF maps or mount/PID namespaces.

Selected owner-authorized userspace ports are Apache-2.0. Historical donor terms,
source slices, source-to-test mapping and reference-only boundaries are retained
in repository provenance. Dependency notices retain their original options.
No BPF payload or runtime license is emitted. Complete bpf-host-v1, installed
operator/profile delivery, additional kernel matrices, semantic BTF, producer
races/loss, C ABI wrappers, application migrations and publication remain later.

Selected owner-authorized donor host/data fragments are Apache-2.0 under OWNER-2026-10-18. Historical KryProbe source labels GPL-3.0-or-later and libbpf-mojo Apache-2.0 WITH LLVM-exception remain recorded in the selected-port receipt; kernel references and LJ successor ranges are reference-only. No BPF payload is included.
