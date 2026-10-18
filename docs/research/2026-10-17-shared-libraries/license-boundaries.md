# Host, BPF and shared-source license boundaries

Added 2026-10-18 during plan repair. This records source inspection and a new planned regression family H33. It is not evidence that a source closure, final object or kernel behavior has been qualified.

## Current author decision

The user identifies themselves as author of the donor contributions. Their current provisional choice is Apache-2.0 for ScopeBase userspace libraries, GPL-v2 for kernel BPF programs and GPL-v3+ for applications; they do not want a project MIT option and may reconsider later. The [decision register](../../superpowers/specs/2026-10-18-scopebase-decisions.md#d03--license-by-code-ownership-and-actual-build-destination) records the operational policy and remaining upstream dependency choice. This does not alter donor files or an unrelated contributor's grant.

Apache documents compatibility with GPLv3 and incompatibility of ordinary Apache-2.0 with GPLv2. Therefore a userspace Apache library consumed by a GPLv3+ application and separately built GPLv2 BPF program is a viable boundary; an Apache-only source fragment compiled into the GPLv2 program is a different case. [Apache compatibility explanation](https://www.apache.org/licenses/GPL-compatibility.html).

Project-owned genuinely shared source can offer `Apache-2.0 OR GPL-2.0-only`, selecting the relevant grant per artifact. Source grants, input notices and the kernel-facing runtime string need separate records. LLVM's [exception](https://llvm.org/LICENSE.txt) changes the terms of the code actually supplied under that exception; using LLVM does not attach it to other source.

## Actual inspected inputs

Selected p11scope worktree: `/home/user/src/m/p11scope-ws/.worktrees/v040-integration`, observed clean at `2c2713e66292b0d2688508a25f79e813ae823d81`.

| Input | Observation |
|---|---|
| `crates/ebpf/Cargo.toml` | GPL-2.0-only; aya-ebpf exactly0.2.1; SHA256 `c3953c92ef4dc10ade46c87d1b74a9006341cd7fb9fe27894f8d26811210c45c` |
| `crates/ebpf/src/main.rs` | GPL-2.0-only; SHA256 `eab693b95783f1a0532910c6fc84b197cd9195a871cd44aba6794f3314cdf097` |
| `crates/ebpf/native/image_identity.c` | GPL-2.0-only, runtime `GPL`; SHA256 `74ae3702153b42cfe7e08b42f9c17554ebe07b14a8c0df4656493576bc0fda3c` |
| `crates/ebpf/native/vma_identity.c` | GPL-2.0-only, runtime `GPL`; SHA256 `c1197dd1e616f1be4bcbf8abf651fd5254e5683f2d652f650187058a7fe31256` |

The locally cached package manifests were inspected, rather than using repository license badges:

| Package | Actual role | Upstream package terms / source revision |
|---|---|---|
| aya-ebpf0.2.1 | BPF target helpers/maps/wrappers | MIT OR Apache-2.0; `773ca715385b97eb0c26a581b53246c0c4306959` |
| aya-ebpf-bindings0.2.0, aya-ebpf-cty0.3.0 | Target helper wrappers and C types | MIT OR Apache-2.0; `302985c72850cd9a8f1d791a11d247a4fbe1c5b1` |
| aya-ebpf-macros0.2.0 | Host proc-macro; emitted wrapper provenance also matters | MIT OR Apache-2.0; `302985c72850cd9a8f1d791a11d247a4fbe1c5b1` |
| aya0.14.0 | Userspace loader/library | MIT OR Apache-2.0; `302985c72850cd9a8f1d791a11d247a4fbe1c5b1` |
| bpf-linker0.10.4 | Host build tool; not automatically target-linked code | MIT OR Apache-2.0; `3558e18082ef8e2596b4600d12b09f782f346715` |

This existing upstream MIT alternative is distinct from licensing ScopeBase-owned source under MIT. Selecting ordinary Apache-only terms for the target crates does not resolve GPLv2 compatibility. SB02/BP01/TC01 must record the actual compatible option and the user's intended scope of the no-MIT preference before that payload is built. This bounded decision must not trigger an Aya rewrite or block an unrelated Apache userspace component.

The cached aya-ebpf, aya-ebpf-bindings and aya-ebpf-macros archives lack standalone license text files. Applicable texts exist at the pinned upstream roots, including [Aya's original texts](https://github.com/aya-rs/aya/tree/773ca715385b97eb0c26a581b53246c0c4306959) and the [bindings/macro revision](https://github.com/aya-rs/aya/tree/302985c72850cd9a8f1d791a11d247a4fbe1c5b1). Delivered bundles must supply the selected required notices; a Cargo license string alone is not delivery of those texts. This inspection did not resolve or audit every future transitive/build-generated input.

## Kernel admission is another boundary

GPL-only helpers, kfuncs and certain program types impose compatible kernel admission. Userspace and BPF programs can be packaged together without making the userspace loader kernel program code. [Kernel documentation](https://docs.kernel.org/bpf/bpf_licensing.html).

The [Linux6.12 predicate](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/linux/license.h) recognizes particular strings; it does not parse arbitrary SPDX expressions. The working GPL-2.0-only program declaration remains runtime `GPL`. An accepted runtime declaration proves neither source ownership nor compatibility of input grants.

H33 separately checks source/selected-option closure, final ELF declaration, actual loader-supplied bytes, a reachable GPL-only helper positive, the otherwise-valid non-GPL refusal, a helper-free non-GPL control where the program type permits it, cause classification, package notices and user delivery. Type/kfunc gates are added only for advertised profiles. Missing privilege, invalid bytecode or absent positive activity cannot stand in for the intended GPL-only rejection.

There is a related existing donor lesson: `SelectionTransport`'s initialized-padding comment in p11scope `crates/ebpf/src/main.rs` records verifier rejection returning EACCES on 5.15/6.2. The BP03 errno-only rule must be corrected. Raw errno, operation, stage and bounded verifier evidence remain separate; ambiguous causes remain unknown.

## Limits

Observed source declarations and chosen options do not prove legal ownership, a resolved dependency closure, emitted object contents or runtime acceptance. The user's stated authorship is used for their contributions; preserve any concretely identified upstream portions independently. No donor mutation, build, kernel load or publication occurred in this investigation.
