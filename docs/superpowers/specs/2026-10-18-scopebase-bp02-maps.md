# BP02 checked map geometry and owned native lookup

Date: 2026-10-18. **Status: controller-ratified implementation contract, including independently approved BP02-R1.** This specifies required software and acceptance evidence; it reports no implementation, passing product test, package qualification or kernel support. Exact source/dependency admission and implementation dispatch remain controller-owned.

Read this public/pure contract with the [native algorithm](2026-10-18-scopebase-bp02-native.md), [verification contract](../plans/2026-10-18-scopebase-bp02-verification.md) and [D07](2026-10-18-scopebase-decisions.md#d07--authority-cannot-be-reconstructed-from-reports). These three documents own the BP02 contract; the subsystem specification/plan link them rather than duplicate signatures or competing choices.

## Controller input binding

The controller reports exact source admission at SHA256 `bc5293b72dc53f1e180bc2b289a15cf73c7a595035135d23ae433b560d51547d` (129 rows: 27 ready, 97 pending, 5 reference); the private bound attachment is `/home/user/src/m/bpfscope/.scopebase/controller/bp02-preparation-20261018/controller-admission-draft.json`. This is the controller's selective admission, not completion of pending source obligations. The selected 13-package dependency projection is `/home/user/src/m/bpfscope/.scopebase/controller/bp02-preparation-20261018/controller-dependency-projection.json`, SHA256 `53e935304ac07b1aec951dd0dfb6fd23666074242297c5a075bf86ec34e7c5fc`. The worker supplies the actual resolved delta; root serializes actual Cargo.lock/package-policy activation from that evidence. Actual activation follows the observed resolved delta. Root binds the accepted implementation base and final dispatch packet separately.

## Ratified choices and reasons

**WHAT/WHY:** Preserve the existing donor geometry, scratch-commit and WHO88 mechanisms while adding the missing authentic-source/task authority and real-map/linked-image witnesses. A descriptive parser result or test report cannot bound a lengthless native kernel copy. The following six R1 alternatives are settled controller decisions; their detailed executable rules live in the linked contract sections.

| R1 alternative | Settled choice (WHAT) | Reason and cost (WHY) |
|---|---|---|
| Runtime admission by qualified version/config strings, or executable ABI/source/task preconditions | Use the [native platform and trust preconditions](2026-10-18-scopebase-bp02-native.md#platform-and-trust); keep exact-source/config/build qualification separately mandatory for measured support. | A uname/config/report/caller claim cannot attest the running implementation or authorize copying. The ordinary kernel ABI trust boundary is explicit; a known mutable possible-mask implementation needs a separately reviewed atomic mechanism. |
| Reject every root bind, or admit a whole authentic kernel-filesystem root initially | Admit a complete authentic sysfs/procfs root bind at acquisition; refuse subtree roots, descendant mount crossings and symlink substitution; later changed root mount identity invalidates. | A complete genuine root supplies the same authoritative contents. Banning that bind adds no enforceable safety benefit; constrained descendant traversal still matters. |
| Retain blanket unsafe prohibition, add a loader/sys crate, or isolate the required native syscall code | Use crate-level deny(unsafe_code) and deny(unsafe_op_in_unsafe_fn), with the sole private maps/native.rs allowance and exact libc/rustix boundary. | Actual lengthless kernel copies require one auditable unsafe module. There is no public injection/raw-native API, compulsory loader or extra generic sys crate. |
| Literal bloom refusal before every native call, or permit the actual-FD metadata query needed to learn its kind | Permit one metadata query; actual bloom then refuses before topology, extent arithmetic, allocation, key witness and value lookup. | Caller-supplied kind cannot be authoritative. Zero downstream-operation counters and unchanged output remain required. |
| Keep only allocating lookup and defer shared identity/BTF, or preserve the native scratch and exact-image contract now | Deliver lookup_into/topology accessors, shared ArtifactId in src/artifact.rs and fully implemented optional actual linked-BTF SHA-256 matching. | Scratch commit and sparse lane association are reusable contracts. SHA-256 adds a bounded dependency and explicitly requested BTF queries can require privilege; raw-byte/type-ID equality still has no semantic-layout meaning. BP03 reuses the same ArtifactId; BP09 owns semantic parsing. |
| Leave grammar/error/resource rules implicit, or freeze one executable precedence and accounting contract | Use the exact parser/geometry rules below and [native budgets/resource bounds](2026-10-18-scopebase-bp02-native.md#budgets-resource-bounds-and-errors), including all native cpulist lengths >=4095 refusing on the admitted 4096-page ABI. | Ambiguous bounds/error order permit unsafe undercount and uncharged work. Byte objects, aggregate admitted dynamic capacities, work, fixed storage, FD ownership, allocator overhead and wall time remain separate. |

**BP02-R1 task continuity:** Retain exact authenticated initial namespace-relative thread-self text and require a fresh positive one-byte stat read relative to the original held task directory on acquisition completion and each revalidation. Held inode numbers can collide or wrap; statx/open alone and cached seq output do not prove the original task lives. The [native phase and error table](2026-10-18-scopebase-bp02-native.md#bp02-r1-exact-original-task-continuity-phase) and [focused controls](../plans/2026-10-18-scopebase-bp02-verification.md#bp02-r1-focused-amendment-controls) are authoritative. This establishes continuity at checks and leaves the immutable global possible-mask copy proof unchanged. Live owners are !Send/!Sync; no proc namespace-magiclink attestation or new public authority type is introduced.

**Source authority:** Append the exact selected host/data ranges under existing OWNER-2026-10-18 Apache-2.0 authority, add the missing snapshot_who intake row/group membership and preserve historical SPDX, notices, narrower admissions and third-party options. Controller-owned canonical source admission and selected dependency projection must be bound before dispatch; this design and its private source-selection attachment do not themselves admit or copy source. No BPF payload license changes. A different design needs a coupled proof/test amendment and review before dispatch; no architecture decision is delegated to the implementer.

**Goal:** Deliver bounded pure possible-CPU topology/geometry and actual safe perCPU array/hash lookup from an owned real map FD, authenticated native topology, exact map-linked BTF binding when requested, all affected WHO88 lookup/decode/fold/report regressions, and early bloom refusal.

**Architecture:** Descriptive arithmetic cannot manufacture native authority. The owner retains the actual FD, acquires authentic kernel sources internally and bounds lengthless copies using the reviewed immutable-mask Linux ABI. Source checks detect substitution/change; they are not the memory-safety proof for a kernel that could grow that mask. Generic crypto policy stays in package regression fixtures/consumers. Native methods must be implemented and positively exercised, without a TT05 prerequisite.

## Executor contract

| Field | Ratified contract |
|---|---|
| Task / scope | BP02; BP-R02/BP-R14 and H15/H16/H28 preservation. First checked map-reader increment, not a complete bpf-host-v1 or installed conformance profile. |
| Decisions | D01–D14 as applicable; the ratified choices above, algorithm in [native contract](2026-10-18-scopebase-bp02-native.md) and tests in [verification contract](../plans/2026-10-18-scopebase-bp02-verification.md). Controller ratification includes the BP02-R1 task-text/fresh-stat repair; the worker cannot weaken these choices. |
| Starting bytes | Preparation source context `4c4e170b57b04c918bf84e167695034f0f6233f4` at dispatch-base-4c4e170; accepted BP01 error/limits actual bytes remain in `/home/user/src/m/bpfscope/.scopebase/controller/bp02-preparation-20261018/input-bindings-v2.json`. Controller-reported current integration is `c0cdbd5`; root binds the actual accepted implementation base and source admission and selected dependency projection before dispatch, preserving this contract. CP03 c145e28/record ada46df was reported by root, not independently reinspected by this canonical draft. |
| Frozen donors | K d153f3aaf9a3931337b47c9e1b046c692da55083; L ff6ea5087cb6cab3db51a9ffaf99922f880da8c9; LJ e55ecbef7493714944cf05a2f92f10938ca6c5ed. Exact private paths, whole/slice hashes, symbols and copied/reference classification in `/home/user/src/m/bpfscope/.scopebase/controller/bp02-preparation-20261018/source-selection.json`. No selected WIP; new snapshot_who matches frozen K history. |
| Origins | ADAPT K parser/geometry/raw lookup/WHO and L extent/scratch/bloom mechanisms; NEW authentic-root/task authority because donor plain path reads lack it; NEW generic-map kind witness and linked-BTF digest because donor adapters lack those required contracts; QUALIFY actual source/namespace/native copies. |
| Inputs | BP01 OperationError/Limits signatures unchanged. Edition 2021, rust-version 1.88.0; test 1.88.0 and 1.98.1. Pure functions portable; native compiled only reviewed x86_64 Linux GNU little-endian 64-bit target. Default and no-default features remain host-only. |
| Outputs | APIs below; exact ownership below; shipped fixtures and source/archive consumer route in [verification contract](../plans/2026-10-18-scopebase-bp02-verification.md). No placeholder production methods or generic crypto public type. |
| Preservation | Source-to-destination/test/oracle/control correspondence in `/home/user/src/m/bpfscope/.scopebase/controller/bp02-preparation-20261018/source-selection.json` plus [verification contract](../plans/2026-10-18-scopebase-bp02-verification.md). Include every affected lookup, fold and decoder; a struct-size assertion is insufficient. |
| License | Owner-authorized Apache-2.0 userspace/data; preserve historical K GPL-3.0-or-later and L Apache-2.0 WITH LLVM-exception records/options/notices. Kernel files reference-only. No BPF program/object/runtime license produced by this task's map/BTF fixtures. |
| Effects / bounds | [native contract](2026-10-18-scopebase-bp02-native.md) names every production syscall, attribute layout, error order, source proof, dynamic capacity/work charge and FD bound. Production does not create maps/programs/namespaces or change host state. |
| Resources | One Sol implementer owns listed paths in an isolated checkout/output root. Root serializes shared Cargo.lock/policy/docs and heavy build slot; root admits a concrete owned guest/resource before live execution. Independent Astra review covers unsafe and authority proof. |
| Acceptance | Exact commands/cells in [verification contract](../plans/2026-10-18-scopebase-bp02-verification.md); source/archive and real positive/negative cells required. Missing cell is BLOCKED_ENVIRONMENT/incomplete, never a pass. Immutable selected-port receipt binds final source/destination/test hashes and reviewed candidate. |

## Exact public API

Root exports pure types and ArtifactId; public `maps` exports all map/topology types, with root reexports for those same types. There are no duplicate ArtifactId domains. `ArtifactId` moves forward from BP03 into `src/artifact.rs` now; BP03 reuses it.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ArtifactId(pub [u8; 32]);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuTopology { /* private sorted IDs + exact original source bytes */ }
impl CpuTopology {
    pub fn parse_possible(input: &[u8], max_cpu_id: u32, max_count: usize)
        -> Result<Self, OperationError>;
    pub fn count(&self) -> usize;
    pub fn ids(&self) -> &[u32];
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerCpuGeometry { /* private stride and total extent */ }
impl PerCpuGeometry {
    pub fn checked(value_size: usize, possible_cpus: usize, byte_limit: usize)
        -> Result<Self, OperationError>;
    pub fn stride(&self) -> usize;
    pub fn buffer_len(&self) -> usize;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueLayout { pub size: usize, pub alignment: usize, pub schema: [u8; 32] }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapMetadata {
    pub map_id: u32, pub map_type: u32, pub key_size: u32, pub value_size: u32,
    pub max_entries: u32, pub flags: u32, pub btf_id: u32,
    pub btf_key_type_id: u32, pub btf_value_type_id: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapBtfExpectation {
    pub image: ArtifactId, pub key_type_id: u32, pub value_type_id: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapExpectation {
    pub map_type: u32, pub key_size: u32, pub value: ValueLayout,
    pub max_entries: u32, pub required_flags: u32,
    pub btf: Option<MapBtfExpectation>,
}
// These owners/impls are exported only on the admitted native cfg.
pub struct LiveCpuTopology { /* private; !Send, !Sync; no Clone/Debug/serde */ }
impl LiveCpuTopology {
    pub fn acquire(limits: &Limits) -> Result<Self, OperationError>;
    pub fn snapshot(&self) -> &CpuTopology;
    pub fn revalidate(&self) -> Result<(), OperationError>;
}
pub struct ValidatedMap { /* private actual FD, metadata, topology, limits */ }
impl ValidatedMap {
    pub fn from_owned_fd(fd: std::os::fd::OwnedFd, expected: &MapExpectation,
        limits: &Limits) -> Result<Self, OperationError>;
    pub fn lookup(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, OperationError>;
    pub fn lookup_into(&mut self, key: &[u8], output: &mut [u8])
        -> Result<bool, OperationError>;
    pub fn metadata(&self) -> &MapMetadata;
    pub fn geometry(&self) -> &PerCpuGeometry;
    pub fn topology(&self) -> &CpuTopology;
}
```

Pure topology Clone is descriptive; fallible allocation is not promised for the standard Clone trait. Explicit parse operations are bounded/fallible. Live owner accessors return descriptive immutable views only. No Default, from_parts, raw FD access, map iteration/update/delete or user-replaceable topology is added. `lookup_into` carries L's scratch-commit preservation contract; `topology()` exposes the actual packed lane-to-sparse-ID association. Neither metadata nor schema/BTF labels promise type-layout meaning or attachment to a producer object.

## Pure parser grammar, bounds and error order

Parse bytes with ASCII whitespace only: space, tab, LF, CR, form-feed and vertical-tab. Grammar is `W item (W ',' W item)* W`, where item is `digits` or `digits W '-' W digits`, and digit strings are nonempty ASCII decimal. Leading zeroes and equal endpoint ranges (`7-7`) are accepted. Whitespace between digits, Unicode whitespace/digits, signs, extra hyphens, empty comma items and trailing garbage refuse. IDs/ranges must already be strictly ascending with no overlap; sorting/deduplication cannot repair input.

First check input.len <=65,536; excess -> LimitExceeded/Admission before syntax. Empty/all-whitespace -> Malformed/Admission. Parse items left-to-right without allocation. Within each item, lexical grammar validity wins first (Malformed/Admission), then decimal conversion in low/high order (checked u32 overflow -> Overflow/Admission), then descending range (Malformed/Admission). Continue scanning an overflowed digit token to recognize malformed suffixes without allocating; for example an overflowing decimal followed by a letter is Malformed, while an all-digit overflow is Overflow. Check high endpoint <=min(max_cpu_id,65535), else LimitExceeded/Admission; then low>previous high, else Malformed/Admission. Checked-add range cardinality to count; arithmetic overflow -> Overflow/Admission; count>min(max_count,65536) -> LimitExceeded/Admission. Thus max_count=0 refuses a nonempty otherwise valid item; max_cpu_id=0 admits CPU 0. The earliest item's error wins over later malformed input. Complete grammar/end validation precedes allocation. Maximum caller caps do not remove hard bounds.

Second pass allocates IDs and source bytes with try_reserve_exact, checks capacity arithmetic and emits exact sorted IDs. Allocation/observed overgrant above hard logical caps -> LimitExceeded/Allocate; the private Limits-aware variant also checks remaining retained/work budgets. Empty topology never succeeds. Preserve original bytes rather than normalizing away a source change. Admitted logical capacities are at most 65,536 source bytes and 65,536 u32 IDs; allocator overhead is separate.

Deliberate tightening: Unicode trim accidentally accepted by donor str::trim is not a kernel cpulist feature. Native sysfs is ASCII; the explicit byte grammar refuses Unicode whitespace. Name this deviation in tests; no selected donor ASCII positive is lost.

## Pure geometry

`checked` uses caller data and grants no native authority. Precedence: zero value_size/count -> InvalidInput/Admission; checked value_size+7 -> Overflow/Admission; `stride=sum & !7`; checked stride*count -> Overflow/Admission; total>byte_limit -> LimitExceeded/Admission; otherwise exact stride/total. Positive total with byte_limit=0 refuses. Pure geometry permits any usize-representable total within its cap and is not limited to parser CPU count. Native additionally checks kernel integer/Vec limits. required_size is absent here. Checked-add overflow deliberately refuses even if another expression could round an already aligned usize maximum neighborhood; this preserves one auditable operation order.

## Dependencies and file ownership

Add exact dependencies only under admitted target cfg: rustix `=1.1.5`, default-features=false, features `std,fs,process,thread,linux_4_11`; libc `=0.2.191`, default-features=false, features `std`; sha2 `=0.11.0`, default-features=false. No loader, build.rs, BPF compiler, proc parser, custom sys crate, path dependency or optional no-op feature. Existing build-script branch grants must cover actual activation; root coordinates Cargo.lock/package-policy with TT02. The sha2 closure is selected elsewhere but this consumer's resolved tree/features still need binding. Attached dependency source inspection is not compilation evidence.

Worker owns:

- `crates/scopebase-bpf/src/{lib.rs,artifact.rs}` and `src/maps/{mod.rs,topology.rs,geometry.rs,handle.rs,provenance.rs,native.rs,budget.rs}`.
- `crates/scopebase-bpf/{Cargo.toml,README.md,THIRD-PARTY-NOTICES.md}`; preserve BP01 behavior/tests.
- Package tests `tests/{maps_pure.rs,maps_contract.rs,maps_live.rs,maps_mounts.rs,who_preservation.rs}`, `tests/support/{native_fixture.rs,who_fixture.rs}`, `tests/ui/maps_*.rs`, `tests/fixtures/bp02/**` and consumer templates `tests/consumers/{topology-cli,who-reader}/**`.
- Package-local test scripts `tests/fixtures/bp02/{generate_vectors.py,run_consumers.py,run_mutants.py,run_live.py}` with interfaces in [verification contract](../plans/2026-10-18-scopebase-bp02-verification.md). These are bounded test drivers, not an orchestration framework.
- `examples/{possible_topology.rs,who_map_reader.rs,bp02_live_fixture.rs}` as independently usable clients. Fixture-only WHO code may be shared through a package-local explicit path; it is not production API.

Expand Cargo include to ship those source/tests/scripts/data and existing BP01 files. Resolve fixtures relative to the installed package, never repository parent/donors. Ordinary cargo test needs no root, BPF toolchain or network. Native tests are explicitly selected; their required run cannot count unavailable environments as passing.

Root owns shared Cargo.lock/package-policy, exact source admissions, canonical docs, traceability/TODO, dispatch and acceptance. Worker supplies shared-path proposals/evidence. No edits to concurrent CP/LX/TT files. Raw helper testing unsafe code stays in private fixture modules with separate review; no production authority-injection feature is shipped.

## Implementation sequence

1. Root binds exact source admission and selected dependency projection, implementation base and private outputs; the worker supplies the actual resolved dependency delta and root serializes actual lock/policy activation; architecture including BP02-R1 is ratified. Recheck only bound inputs; no donor refresh or history survey.
2. Implement pure parser/geometry and ArtifactId with original cases, independent oracles and compile controls.
3. Implement exact private syscall layouts, metadata/witness/BTF, source/task acquisition/revalidation, budgets and real lookup/output commitment. A private model backend may inject failures but cannot route forged geometry into a real value syscall.
4. Adapt every selected WHO consumer/codec/fold test to package fixtures. Add real clients and source/archive routes; bind selected-port correspondence including reference-only paths.
5. Run host/source/archive checks and mutants/restored twins. Independent unsafe/authority review precedes real source-substitution tests. Root admits owned resources; run every minimum live cell and the unpacked-archive native client. Fix actual failures; keep missing cells incomplete.
6. Root accepts only candidate-bound implementation/tests/receipts and required real evidence. Full profile/operator/toolchain/kernel matrix and migrations remain later.

## Definition of done

Every API performs its contract; both map kinds and optional BTF have actual successful native tests; bloom/source substitution/undercount/fork/output negatives fail at intended stages with no forbidden value copy; all selected WHO regressions and consumers are preserved. Source and unpacked archive users can run delivered positive/refusal fixtures and both clients. Both pinned compilers, default/no-default, package policy, meaningful mutants/restored twins and independent review are candidate-bound. No required SKIP/BLOCKED/NOT_RUN closes BP02. Root canonicalization/receipt validation complete bookkeeping. No full selected-kernel support, installed operator profile, producer winning-inserter qualification, migration or publication is implied.

## BP02-R1 amendment acceptance

V2 changes only the private task-continuity predicate and its accounting/tests: exact saved authenticated thread-self text plus a fresh positive one-byte stat read relative to the original held task directory. Holding a numeric proc inode does not reserve uniqueness. The unchanged global perCPU copy bound still relies on the admitted immutable-mask kernel ABI, not this liveness witness. See the exact error/sticky/output/FD/work rules in [native contract](2026-10-18-scopebase-bp02-native.md) and the equal-inode/reused-number/owned-child controls in [verification contract](../plans/2026-10-18-scopebase-bp02-verification.md).

Original `/home/user/src/m/bpfscope/.scopebase/controller/bp02-preparation-20261018/source-selection.json`, its 32 selected slices and all source grants remain unchanged. Additional kernel references are reference-only and bound by hash in `/home/user/src/m/bpfscope/.scopebase/controller/bp02-preparation-20261018/input-bindings-v2.json`; no source refetch or donor survey is permitted. Controller ratification includes the original R1 decision bundle and the independently approved BP02-R1 repair; those are distinct identifiers. Actual source/dependency admission and implementation dispatch remain root-owned. An owned minimum guest is provisioned, with kernel/source approved and a narrow runner-custody repair/final resource admission pending: source implementation need not wait, but resource admission remains required before live execution.

## Evidence and why these choices are needed

### Kernel lengthless-copy invariant

The saved primary Linux v6.12 source binds to commit `adc218676eef25575469234709c2d87185ca223a`. All 27 initially captured architecture-reference tag files were byte-compared with commit-addressed URLs; `/home/user/src/m/bpfscope/.scopebase/controller/bp02-preparation-20261018/upstream/commit-byte-verification.json` records equality. The additional kernel/bpf/btf.c was acquired directly by commit. `/home/user/src/m/bpfscope/.scopebase/controller/bp02-preparation-20261018/upstream/manifest.json` records exact file hashes. Tag signature authenticity was not verified, and this architecture reference is not source acquisition/boot/qualification of selected releases 5.15.223/6.12.113/7.2.11.

Source chain: Documentation/core-api/cpu_hotplug.rst possible-mask boot immutability; drivers/base/cpu.c possible attribute uses __cpu_possible_mask; include/linux/cpumask.h uses that mask; kernel/bpf/syscall.c::bpf_map_value_size rounds to8 and multiplies num_possible_cpus; arraymap.c and hashtab.c perCPU copies iterate for_each_possible_cpu. The source/syscall agreement, not a before/after observation, provides the allocation proof under the admitted kernel ABI. Native i32/u32 extent ceilings account for actual kernel arithmetic/offset types rather than only Rust usize arithmetic.

### Authentic root, complete attribute and task

fs/kernfs/dir.c creates an empty inode IDR, root first at inode 1 on 64-bit; kernfs/inode.c maps that number to the inode; fs/sysfs/mount.c uses the genuine sysfs root. proc root uses PROC_ROOT_INO=1. fstatfs plus inode/type/statx mount identity authenticate a full kernel filesystem root; openat2 atomic constrained traversal prevents mounted/symlink descendants. Opening a held symlink is deliberate only for authenticated proc thread-self, whose kernel get_link uses the current task in the proc mount's PID namespace; it is read, not followed as a magic-link path. Numeric task path resolution remains beneath the genuine root.

lib/bitmap-str.c::bitmap_print_to_pagebuf uses scnprintf with one page, and fs/sysfs/file.c clamps page-sized output. A sufficiently long sparse mask can be cut to a syntactically valid undercount. Requiring length<4095 plus newline+EOF on the admitted 4096-page platform prevents that unsafe promotion. Pure parser acceptance of a prefix cannot bypass live acquisition. Full-root bind is safe; an online leaf bind cannot be confused with possible because NO_XDEV refuses the crossing.

### Generic BPF metadata and linked BTF

OBJ_GET_INFO_BY_FD dispatches map/program/link/BTF object types. A map-shaped prefix is not a map-type witness. GET_NEXT_KEY calls __bpf_map_get before any output; with actual map metadata it supplies its exact immutable key size, while nonmap FDs fail before writing. The private witness therefore closes object-type confusion without a proc fdinfo parser. It is not public iteration and cannot run before bloom refusal.

BTF_GET_FD_BY_ID uses the actual retained map's btf_id. The map keeps BTF alive, so the ID cannot be reused while resolving it. btf_get_info_by_fd bounds copy by supplied size and returns actual object size/id; acquire size, bound allocation, fetch, compare immutable identity/size and digest. Store no unbounded BTF cache. Optional exact-image validation is feasible now without BP09 parsing. The fixture is a 65-byte raw BTF image with u32 key/u64 value types; its literal bytes and independent digest are frozen under `/home/user/src/m/bpfscope/.scopebase/controller/bp02-preparation-20261018/fixtures/`.

### Actual WHO source gap and regression semantics

K kcrypto_snapshot.rs contains120-byte KAGG/KTOT paths; it is not the current WHO lookup. The newly selected frozen `crates/kryprobe-privilege/src/kcrypto_backend/snapshot_who.rs` has SHA256 `e783c48e9378d88f166cdac3db666ed707ffa9656a27b093348041b74bfa05db`, matching explicit frozen K HEAD. Selected lookup/decode/fold statement fragments, coupled 16-byte KWhoKey type/decoder/golden fragment and reference report/diagnostic/iteration scopes are now exact and hashed. A disappeared known WHO key aborts the whole report, and M8 reusable lane storage remains covered. No branch resurvey was performed.

VWho is 88 bytes, not 80. Every direct/cache-shaped lookup, decoder, fold and report fixture must use the new shape. Any lane.calls==u64::MAX refuses even when the final sum could be represented. Conversely [MAX-1,1] may sum exactlyMAX and is accepted; [MAX-1,2] overflows and refuses. Unique marker1 selects insertion identity; latest comm/tid is independent, zero uid/stack is valid, timestamps use min/max and are exempt from counter-sentinel rules. Root specifically required preserving this distinction independently of CP04 generic Count. Original producer models remain models; BP07 owns the actual BPF insertion/loss proof.

## Dependencies and licensing

Exact selected target dependency contract: rustix 1.1.5 (`std,fs,process,thread,linux_4_11`, no defaults), libc 0.2.191 (`std`, no defaults), sha2 0.11.0 (no defaults). linux_4_11 avoids rustix's compatibility statx probe/cache changing effects/errno; unavailable statx now directly refuses. libc's selected x86_64 build-script branch was already admitted by BP01, but BP02 activation must be reflected in the actual lock/policy/consumer feature tree. sha2's selected closure is shared with TT02; root serializes it. No build.rs, BPF compiler, loader, subprocess or target payload dependency is introduced by the production crate.

Historical donor terms and owner authorization remain separate. K selected host/fixture ranges are owner-authorized Apache-2.0 while their historical GPL-3.0-or-later observation is retained. L source retains Apache-2.0 WITH LLVM-exception history/notice and its selected owner contribution authority; LJ identical successor ranges are reference-only. Kernel source files are reference-only and their GPL labels are not copied into host source as implementation. No GPLv2 program, ELF license section or runtime license string is produced by map/BTF fixtures, so host Apache authority is not being used to relicense a payload. This follows the settled licensing choice rather than reopening it.

## Qualification boundary and handoff

Minimum positive denominator is frozen in [verification contract](../plans/2026-10-18-scopebase-bp02-verification.md): one real owned x86_64 GNU SMP build with >=2 possible and at least 1 offline lane, both perCPU map kinds/sizes/flags, actual BTF binding, WHO/report consumers, actual fake/bind/subtree/root/continuity negatives, fork/same-numeric-PID, FD retention and safe canary controls. Root binds the specific existing eligible build/resource/source/config before execution. No report string grants runtime authority. Fixtures ship in the package and archive and require explicit opt-in to owned namespace creation; they never automatically offline host CPUs or alter host sysctls. Owned cleanup and unresolved custody are explicit.

The native implementation must exist and these positive cells must pass before BP02 closes. TT05 is not a prerequisite: raw host map/BTF syscalls and already owned/manual guest setup suffice. Full TT05/TT10 profile delivery, selected-release matrices, installed operator route, BP07 producer behavior, BP09 semantic BTF and migrations remain later. Current artifacts contain no observed product pass.

Historical private preparation verification: JSON parsing, exact selected file/slice hashes, upstream commit-byte comparison, fixed independent fixture lengths/hashes, local attachment references and whitespace are checked by the preparation verifier. This is a read-only/preparation check, not tools/check_planning_docs.py against changed canonical docs, Cargo, archive execution or live-kernel evidence. Root reruns affected canonical checks after canonicalization.

