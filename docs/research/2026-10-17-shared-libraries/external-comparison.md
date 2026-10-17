# Existing libraries and upstream options

Research date: 2026-10-17. This is a source/API comparison, not a benchmark or a tested dependency upgrade. The recommended order is independent Rust libraries, a small application framework later, then C/Mojo interoperability. Upstream default-branch observations are recorded in [external-sources.json](external-sources.json); those commits are research references, not adoption pins. A release must be selected and tested when implementing an adapter.

The BTF comparator is pinned for reproducibility at [btf-rs `0a5838f8dad54b6da9a7b0539f1e2d7aeeb009a0`](https://github.com/retis-org/btf-rs/tree/0a5838f8dad54b6da9a7b0539f1e2d7aeeb009a0), observed 2026-10-17. Its source/API fit still requires B04's malformed/split-BTF corpus trial; the pin does not qualify it as a replacement.

## Main finding

There are good implementations of most low-level operations. The opportunity is to share the contracts around those operations: which process/image a handle belongs to, when attachment remains valid, what a missed event invalidates, and what evidence closes a measurement window. No evaluated project establishes all four applications' domain-specific guarantees. This is a conclusion from the compared interfaces and source, not a claim to have surveyed every library or tested each candidate.

Prefer an existing dependency plus a small adapter and regression suite. Extract a new primitive only when the adapter cannot meet a demonstrated requirement. Do not create another general BPF loader or ELF/BTF parser by default.

## Reuse decisions

| Area | Existing option and primary source | Recommendation | What remains ours |
|---|---|---|---|
| Rust BPF loading/maps/links | [Aya](https://github.com/aya-rs/aya), [API](https://docs.rs/aya/latest/aya/) | Retain the installed architecture; consolidate narrowly justified patches and test upstream replacements. | Cross-operation lifecycle, coverage, semantic policy, and actual emitted-object validation. |
| C BPF with Rust host | [libbpf-rs/libbpf-cargo](https://github.com/libbpf/libbpf-rs), [libbpf](https://github.com/libbpf/libbpf) | Strong alternative backend for a bounded comparison, especially where C CO-RE solves a specific problem. | Do not require a wholesale Aya-to-libbpf migration before library extraction. Native build/link requirements differ. |
| Multi-uprobe attachment | [Aya PR 1417](https://github.com/aya-rs/aya/pull/1417), [libbpf-rs program APIs](https://github.com/libbpf/libbpf-rs/blob/37139b4abe8327c90d8d5d6f56b6a78ffcb347b7/libbpf-rs/src/program.rs#L1094) | Use upstream attachment where the selected release supports the needed behavior; keep a small tested adapter for remaining gaps. | Pinned image lifetime, cookie provenance, partial attachment reporting, bounded failure isolation and rollback. |
| BPF object/BTF relocations | [aya-obj](https://docs.rs/aya-obj/latest/aya_obj/) | Upstream fixes and reuse; avoid promoting the applications' raw loaders into a new universal loader. | Compiler-generated regression inputs, named-map identity checks, versioned patch retirement tests. |
| General BTF queries | [btf-rs](https://github.com/retis-org/btf-rs), [libbpf-rs BTF](https://docs.rs/libbpf-rs/latest/libbpf_rs/btf/index.html), [Aya Btf](https://docs.rs/aya/latest/aya/struct.Btf.html) | Evaluate btf-rs against the projects' malformed and split-BTF corpus; use existing Aya/libbpf parsing when sufficient. | Bounded traversal, evidence provenance, required field/prototype/semantic contracts, clear rejection reasons. |
| BTF for older kernels | [BTFHub and BTFGen](https://github.com/aquasecurity/btfhub/blob/main/docs/btfgen-internals.md) | Optional exact-kernel metadata source. | Metadata provenance and matching; it cannot add absent helpers, hooks, map types, or semantic support. |
| ELF parsing and offsets | [object](https://docs.rs/object/latest/object/), [goblin](https://docs.rs/goblin/latest/goblin/) | Keep the parser already used by a consumer unless a specific gap justifies changing it. Avoid requiring both. | A pinned/owned input boundary, bounded reads, executable-segment checks and mapping generation. |
| Address normalization and symbols | [blazesym normalization](https://docs.rs/blazesym/latest/blazesym/normalize/index.html), [Rust/C APIs](https://github.com/libbpf/blazesym/blob/e325200d384d5a05d50c74ac20fab68526d92d3e/README.md) | Strong candidate for common normalization/symbolization. It already provides Rust and C interfaces. | It does not by itself establish process birth, exec generation, attachment lifetime or PKCS#11/provider attribution. |
| Linux handles/syscalls | [rustix pidfd](https://docs.rs/rustix/latest/rustix/process/fn.pidfd_open.html), [nix](https://docs.rs/nix/latest/nix/) | Prefer existing typed descriptor/syscall APIs; keep current dependencies where suitable. | Consistent acquisition of multiple handles, process-generation checks, finite cleanup and explicit degraded modes. |
| Procfs access/parsing | [procfs Process](https://docs.rs/procfs/latest/procfs/process/struct.Process.html) | Evaluate before extracting a new procfs reader. `Process` already holds an open proc-directory FD to avoid PID-reuse retargeting. | Exec changes, coherent multi-file observations, bounded FD retention and producer-domain identity. Procfs is not an atomic snapshot. |
| Confined path/procfs operations | [libpathrs](https://github.com/cyphar/libpathrs/blob/fbcd2a0b594c546592213d54e3030d6e8319936d/README.md), [feature/fallback table](https://github.com/cyphar/libpathrs/blob/fbcd2a0b594c546592213d54e3030d6e8319936d/docs/kernel-features.md) | Evaluate when resolving names through another process/root/mount namespace. Rust and C-facing APIs already exist. | File content stability and the difference between filesystem identity, mapped device identity and image identity. |
| Directory/fixture capabilities | [cap-std / cap-tempfile](https://github.com/sunfishcode/cap-std/tree/0e476ad94ec98ef65fb236e471e0aaf20b7eb1e9), [tempfile explicit close](https://docs.rs/tempfile/latest/tempfile/struct.TempDir.html#method.close) | Evaluate existing directory-relative capabilities and temporary-fixture primitives before writing another filesystem helper layer. | Mapping identity, per-run authority, budgets and cleanup verdicts still need the shared contract. TempDir Drop ignores cleanup errors; use an explicit checked close when a clean test result depends on removal. |
| Kernel/BPF feature probing | [bpftool](https://github.com/libbpf/bpftool), [libbpf](https://github.com/libbpf/libbpf) | Reuse capability probes as inputs. | A feature being present does not prove a workload is observed correctly. Classify denied/unavailable/unsupported/incompatible/unknown separately. |
| Wire layout and byte parsing | [zerocopy](https://docs.rs/zerocopy/latest/zerocopy/), [bytemuck](https://docs.rs/bytemuck/latest/bytemuck/) | Use established layout checks selectively. | Length/version/endianness/reserved-field validation, semantic contradictions, ABI-vs-report separation. A valid byte cast is not a valid event. |
| Concurrent Rust state machines | [Loom](https://docs.rs/loom/latest/loom/), [Shuttle](https://github.com/awslabs/shuttle) | Use for small userspace ownership/admission/reconciliation models, then test real integration. | Kernel BPF/JIT execution, raw mmap access, FFI, syscalls and hardware ordering are outside an ordinary Loom model. |
| Parser/lifecycle test generation | [Proptest](https://proptest-rs.github.io/proptest/), [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) | Adopt for malformed input and event-order/generation transitions. Preserve minimized failure cases. | Independent semantic oracles and real kernel tests; self-round-trips alone can preserve a shared bug. |
| Native test base | [Linux BPF selftests](https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf) | Reuse upstream scenarios and conventions where applicable; keep small own workloads for product contracts. | Exact consumer behavior and supported artifact/kernel combinations. Passing upstream selftests does not qualify an application. |

The candidate list is intentionally broader than the first dependency set. Most entries are alternatives, not dependencies to add together.

The additional user-run requirement has an established distribution precedent: [kselftest installs standalone tests and a runner](https://docs.kernel.org/dev-tools/kselftest.html#running-installed-selftests), with machine-readable result conventions. Borrow install/list/select/run and explicit missing-prerequisite behavior; do not make all kernel selftests a dependency or treat them as consumer qualification. The proposed Scopebase corpus additionally binds the actual consumer library and filesystem profile; [user conformance](user-conformance.md) specifies those obligations.

## Larger frameworks: useful references, different scope

| Project | What is relevant | Assessment for these workspaces |
|---|---|---|
| [Inspektor Gadget operators](https://inspektor-gadget.io/docs/main/spec/operators/) | Modular loading, enrichment and output pipelines; OCI gadget distribution. | Closest reference for a future common application layer. A full migration would impose its execution and distribution model before the independent libraries are proven. Current operator documentation also places constraints on third-party operator extensibility. |
| [Tetragon process API](https://tetragon.io/docs/reference/grpc-api/) | Explicit exec identity, parent identity and unknown/cache-miss metadata. | Learn from the schema and lifecycle regressions. It is a security-observability/enforcement product, not a drop-in Rust process-generation library for these observers. |
| [Tracee process-tree implementation](https://github.com/aquasecurity/tracee/tree/main/pkg/proctree) | Process/thread tracking and enrichment are useful comparator implementations. | Use as an independent design/reference lane, not as proof of identical process or measurement semantics. Its Go application architecture would add a new runtime boundary. |
| [Retis](https://github.com/retis-org/retis) and [btf-rs](https://github.com/retis-org/btf-rs) | Modular Rust tracing application; btf-rs is explicitly extracted for reuse outside its original packet-tracing tool. | A particularly relevant extraction precedent. Adopt/evaluate the independent library; do not import packet-correlation semantics. |
| [bpfman current source](https://github.com/bpfman/bpfman/tree/bd900e1262c4a5c17e5e614f8e8947e2e198c51c), [go.mod](https://github.com/bpfman/bpfman/blob/bd900e1262c4a5c17e5e614f8e8947e2e198c51c/go.mod) | Persistent BPF program management and deployment. | Optional future integration when long-lived managed programs are desired. The website still describes a Rust/Aya architecture, while the inspected current default branch has a Go module using cilium/ebpf. Do not recommend the historical Rust crate as the unquestioned current architecture. |
| [cilium/ebpf](https://github.com/cilium/ebpf) | Independent loader, link, feature and relocation implementation in Go. | Useful differential/reference implementation. A language change would not eliminate application-specific lifecycle contracts. |
| [BCC and libbpf-tools](https://github.com/iovisor/bcc) | Broad workload examples, probes, diagnostics and compatibility experience. | Good examples and regression inspiration. BCC's runtime compilation model is not a necessary dependency for packaged Rust applications. Distinguish BCC from its libbpf-based tools. |
| [eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf/blob/a5408a8c3614bd4e008c1f999bb4ee9738e2fc41/README.md) | JSON-described loading, generated reporting, OCI/Wasm distribution and polyglot possibilities. | Relevant for a later SDK/distribution prototype. It does not remove the need to establish identity, loss, and finalization semantics for these tools. |

## Findings that change the proposed extraction

### Upstream multi-uprobes already exist

The GitHub API and PR page both report Aya PR 1417 merged on 2026-07-31 at `5c1a79e0bdc36e77b304c1a08ff8b05e6b823108`. p11scope carries a backport. Therefore a new library should concentrate on attachment planning and lifetime policy, while comparing the exact selected upstream API against the backport. A merged PR is not proof that the applications' pinned release contains it or that every local workaround can be removed.

### Rust BTF support needs a precise claim

[Aya issue 349](https://github.com/aya-rs/aya/issues/349) remains open in the API observation. It distinguishes loader support for BTF relocations from producing those relocations for Rust-authored BPF. [bpf-linker](https://github.com/aya-rs/bpf-linker/blob/537997d904d040bb4a751c290f84768f8067529c/README.md) documents BTF generation and compiler/linker constraints. Do not turn either a general CO-RE description or the presence of a `.BTF` section into proof that each needed field/type relocation was emitted. Inspect the actual object and exercise a changed-layout target.

### A compiler-related failure need not be a compiler bug

The p11scope local map-relocation patch resolves a map from a section symbol plus its implicit addend. That form is documented in the [kernel's LLVM relocation specification](https://docs.kernel.org/bpf/llvm_reloc.html). The reusable lesson is loader conformance to emitted objects, not an unqualified assertion that LLVM generated invalid code. Store separate diagnoses for compiler defects, loader defects, verifier limits, kernel behavior, and toolchain incompatibility.

The inspected Aya default-branch `aya-obj/src/relocation.rs` still populates a section-keyed map table and falls back to it; the local exact-definition-boundary patch is not present in that form. The local ring API also has bounded-consumption functions absent from the inspected upstream file. These are static comparison results, not fresh upstream bug reproductions. Re-run the minimal regressions on a selected upstream release before filing or removing patches.

### Existing safe wrappers still need an application contract

`procfs::Process` already pins a process directory. `libpathrs` explicitly documents feature-dependent fallback strength. blazesym normalizes addresses into object offsets and metadata. These capabilities reduce the amount of code to extract, but none makes a pathname an immutable image or proves that multiple observations concern the same execution generation. The proposed identity/image adapters should make those remaining conditions explicit.

### Drain is not settlement

The [kernel ring-buffer documentation](https://docs.kernel.org/bpf/ringbuf.html) describes reservations, busy records, and producer-position snapshots. An empty poll or a sampled producer cursor alone cannot establish the application's complete observation window. Shared code should represent a bounded consumption result; only the relevant producer/lifecycle protocol can establish whether the measurement is settled.

## Proof-of-fit before adopting or replacing a dependency

1. **BTF adapter:** run existing valid/malformed/cyclic/qualified/anonymous/split-type inputs through the candidate. Compare resolved sizes, offsets, prototypes, bounded failure, and unknown-kind behavior. Preserve product-specific required-type contracts above it.
2. **Identity/image adapter:** combine procfs/rustix/pathrs/object or blazesym as needed; reproduce rename, deletion, PID reuse, exec, mmap replacement, mount namespace and Btrfs cases. Verify retained descriptor counts and finite cleanup.
3. **Attachment backend:** compare current Aya/backport and candidate upstream API using identical pinned images, offsets and cookies. Exercise partial failure, wrong attach type, seccomp behavior, unload/reload, classic fallback and ownership rollback.
4. **Compiler/loader pair:** build minimized examples for local-map relocations, BPF-to-BPF calls/callbacks, bounded loops, stack layout and task-storage map metadata. Verify distinct loaded map IDs and actual emitted instructions where the regression depends on code generation.
5. **Quality models:** replay identical fault sequences in both consumers. Preserve separate discovery/transport/identity/window/semantic outcomes and do not sum alternative detail/aggregate observations.
6. **Scope of evidence:** parser tests establish parser behavior; a model test establishes that model; verifier acceptance establishes verifier acceptance. Real collection claims require an independent expected population and the actual consumer artifact on the admitted environment.

Choose dependencies using these results, API fit, maintenance, transitive build cost and per-file licensing. Popularity or a recent commit is insufficient. No upstream issue was filed and no dependency was changed by this study.
