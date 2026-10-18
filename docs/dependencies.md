# ScopeBase dependency experiments and build policy

Status: SB02 tooling and package-policy fixtures are implemented for review. The product workspace has zero members. No shared ScopeBase library, supported runtime capability, dependency adoption, package readiness, or donor-patch preservation is established by these fixtures. The [ratified packet](superpowers/plans/2026-10-18-scopebase-sb02-packet.md) defines the experiments and remaining gates; the controller records acceptance separately.

## Toolchain and workspace configuration

The root virtual workspace specifies edition 2021, initial version 0.1.0, proposed MSRV 1.88.0, resolver 2 and the provisional Apache-2.0 userspace default. `rust-toolchain.toml` pins 1.98.1. Both installed compiler roots are explicit matrix inputs; each execution records `rustc -Vv`, Cargo version and compiler/Cargo/rustdoc executable hashes. No command installs or updates a compiler. Empty-root metadata is configuration evidence only. Component owners must add and independently qualify actual members; an unregistered member fails policy.

The provisional GPL-2.0-only BPF and GPL-3.0-or-later application rules remain separate. No BPF target is built here. The outstanding Aya target dependency option is a controller/user decision before that payload. Third-party alternatives and notice material remain intact, including dependencies whose existing option is MIT; this creates no project MIT alternative.

## Candidate decisions awaiting actual probe evidence

These are required experiments, not root dependencies. The policy lane has not run the probe lane's candidate rows. Final primary choices require immutable integrated results and expert rulings; no candidate is selected merely because its archive is available or its crate is used by a checker fixture.

| Area | Required pinned experiment | Selection state and retained contract boundary |
|---|---|---|
| Syscalls | rustix 1.1.5 (`std,fs`; separate `process` compile trial), nix 0.31.3 (`fs,uio`) | Primary pending. Actual fd/flag/cursor/offset tests must inform LX02/LX04; no HeldFile implementation here. |
| ELF | object 0.39.1 (`read_core,elf,std`), goblin 0.10.7 (`std,elf32,elf64,endian_fd`) | Primary pending. A missing export requires an expert ruling; no silent feature expansion or resolver rewrite. |
| procfs | procfs/procfs-core 0.18.0, defaults off | API/parser observations pending. Raw paths, strict ranges/permissions/mount identity and limits remain LX packet decisions. |
| BTF | btf-rs/derive 2.0.0 at `0a5838f8dad54b6da9a7b0539f1e2d7aeeb009a0`, optional ELF/regex features off | Public-query/bounds observations pending. Preserve LGPL-2.1-or-later and original license links/text. Narrow adaptation belongs to BP09. |
| Optional host backend | aya 0.14.0 and aya-obj 0.3.0, defaults off | Host API evaluation pending; loader/attach functions remain typed and uncalled. No claim about unpatched ring/uprobe/relocation behavior. BP05/BP06/BP10 retain original fix/regression obligations. |
| Optional JSON | serde 1.0.229 (`std,derive`), serde_json 1.0.151 (`std`) | Probe evidence and strict-replay decision pending. Fixture JSON parsing does not implement CP10's schema, duplicate handling, canonical representation or bounds. |

Reserve candidates remain reserves. A comparator failure does not authorize raising MSRV, replacing a parser/loader, or adding two compulsory implementations.

## Explicit input and execution authority

The two small Python 3.11+ tools use only the standard library:

```sh
python3 tools/build/dependency_probe.py --matrix MATRIX --output-dir ABSOLUTE_NEW_DIR --report ABSOLUTE_NEW_REPORT
python3 tools/build/check_features.py --manifest Cargo.toml --matrix tests/package-policy/matrix.json --output-dir ABSOLUTE_NEW_DIR --report ABSOLUTE_NEW_REPORT
```

Run Cargo-producing invocations through `bin/scopebase-build -- ...`, with its default shared host/user resource. The tools do not create a competing lease service. Every run owns its output, Cargo home, temporary directory and targets. Reports are exclusive atomic JSON files; logs are bounded private files referenced by hash. Existing results, source-contained outputs, symlink escapes, unknown fields, duplicate JSON keys and unexpected ancestor Cargo configuration refuse. Compiler environment variables are reconstructed from explicit toolchain/output paths; ambient wrappers, flags, runners, linkers, Cargo homes and configuration do not pass through.

Each matrix hashes one immutable source inventory. Acquisition is a separate authorized preparation phase using exact Cargo 1.88 `generate-lockfile`, `fetch --locked`, then `vendor --locked --offline --versioned-dirs`. Execution verifies and copies standard Cargo outputs, archives, locks, checksum maps, license material and the entire vendor tree; it never builds a registry cache, generates checksum maps, learns approvals or goes online. Required missing bytes remain BLOCKED. The fixture matrix's absolute inventory path deliberately identifies this task's retained private acquisition; another environment must prepare a new immutable inventory and deliberately select its hash.

Per-member/case `allowed_dependencies` and top-level `approved_build_inputs` are the sole execution authority. Availability is not permission. All resolved target/dependency kinds are inspected before compilation, including conservative inactive-target over-approximation. Whole immutable package digests bind build-script/proc-macro approvals, including included helpers. Native requirements, forbidden packages, unregistered paths and source overrides refuse before code execution. An unaudited otherwise ordinary Rust build input remains BLOCKED/APPROVAL_REQUIRED. This source-admission policy does not sandbox malicious approved code.

The only acquired BTF exception maps the exact reviewed URL/full revision to its verified selected bundle, plus the frozen btf-rs → btf-rs-derive internal edge. Acquisition lock matching normalizes only that controlled edge and records original/effective manifest hashes. Product package policy never inherits this probe exception.

## Package-policy fixture observations

The unpublished `sb02-feature-subject` is a test fixture with std-only `decimal_len` and optional serde-backed `parse_u64`; neither is a ScopeBase API proposal. Minimal/default external clients have separate roots and independently generated locks. The union contains two distinct binaries referencing one archive-derived subject with additive features; decimal boundaries and exact-u64 JSON positive/negative assertions execute through that same subject. Rust 1.88.0 generates each lock offline; 1.98.1 consumes that exact lock. Separate targets prevent compiler artifacts from substituting for current inputs.

Both compilers have executed the fixture checks, subject unit tests, explicit subject doctests and clients. Both pinned Cargo versions inspect the normalized package list: `Cargo.toml`, `Cargo.toml.orig`, `Cargo.lock`, `src/lib.rs`, `LICENSE-APACHE`, `THIRD-PARTY-NOTICES.md`. Archive creation uses pinned Cargo 1.88; archive-derived downstream compilation independently uses both versions. The fixture archive contains its own byte-checked Apache text and deterministic notice inventory. Third-party source remains in the admitted vendor closure, is marked `bundled:false`, and retains actual original license/notice hashes. A package's `license` metadata cannot substitute for delivered text.

The fixture closure includes exact itoa/memchr/serde/serde_core/serde_json/zmij inputs and Cargo's locked optional derive closure. Each exact transitive package and audited build/proc-macro role has explicit matrix records. These grants apply only to the fixture, not future product dependencies. The retained private acquisition records the actual Cargo resolution, archive and tree hashes; online acquisition did not compile package code.

PP01–PP08 and PP10 controls exercise existing sibling paths across dependency tables/overrides/symlinks, unapproved scripts and helper changes with a capable fake BPF-tool marker, feature leakage/union, explicit failing doctest, selected private archive sentinel, fixed report denominator, current lock/source digests, and delivered license/notice mutations. PP09's real public/private BTF API control belongs to the probe matrix; its actual candidate result remains pending. No real BPF tool is installed or executed. Python source/schema tests, real Cargo controls and actual dependency experiments remain separate evidence tiers.

## Verdicts, bounds and remaining gates

Exit 0 applies to the requested tool scope and expected assertions only. Inspect `scope`, `fit`, `decisions_required` and `product_qualification:false`; selected cases never establish the full required matrix. Required FAIL takes exit 1; malformed input takes 2; required BLOCKED/NOT_RUN or unresolved cleanup takes 3. An observed contract GAP can be executed evidence and still require an expert decision before adoption. No report accepts SB02 or a component.

Per Cargo process tree: 10-minute deadline and separate 4 MiB stdout/stderr limits. Configuration and generated source fixtures are bounded at 1 MiB, matrices at 128 compiler cells and 32 features per cell, reports at 16 MiB. These are work/input/log/elapsed bounds, not proven compiler RSS or syscall-cancellation bounds. Owned process groups are stopped on timeout/interruption and reaped; surviving/unreaped custody is reported unresolved and cannot certify success. No host credentials, limits, signals, namespaces or kernel resources are changed.

Required next gates are integrated candidate × compiler results, real PP09 diagnostic evidence, independent architecture/adversarial review, exact-candidate checks and the expert's primary syscall/ELF choices plus explicit procfs/BTF gap routes. The sole document writer amends these decision rows only from the controller's immutable results and rulings. SB-R15 independent production consumers, original donor regressions, runtime/kernel profiles and product migrations remain with their named owning tasks.
