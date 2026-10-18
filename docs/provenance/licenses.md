# ScopeBase source-license intake

Revision 1, 2026-10-18. Owner: SB01; consuming owners: SB02, LX01, BP01, CP01, TC02 and NX02. This record selects a license-preserving implementation route. It neither changes a donor's grant nor claims that source has been ported or a distributed artifact has been reviewed. The authoritative per-file record is [donors.json](donors.json); [adoption decisions](adoption-decisions.md) explain reuse choices.

## Selected route

Direct ports and adaptations of p11scope, KryProbe, OSSLscope and MemVeil host source and tests retain `GPL-3.0-or-later`, authorship and applicable notices. Packages containing those derivatives must use compatible terms; the proposed permissive default in the initial design does not authorize relabeling them. An improved API does not remove the provenance of ported implementation or tests. This avoids discarding hard-won fixes in an unnecessary rewrite. SB02 must review actual package membership and dependencies before writing manifest license metadata.

The existing libbpf-mojo bridge uses `Apache-2.0 WITH LLVM-exception`. Preserve that exact expression and consume the bridge with narrow adapters. Keep its stable L baseline, LJ integration successor and the revision actually consumed by MemVeil separate. Selected MojoBPF source and tests with this grant retain it; no universal replacement compiler or bridge is proposed.

Keep BPF source with `GPL-2.0-only` separate from host source. Preserve any `GPL-2.0-or-later` shared-definition grant where actually observed; one expression cannot substitute for the other. Directory separation alone does not establish compatibility of a linked or distributed artifact. SPDX headers, license texts, dependency composition, installed fixtures and notices all need review together before distribution.

Actually original code can receive an explicit project license; SB01 introduces no blanket relicensing policy. The metadata validator is original development tooling. No third-party source or test body is copied in this intake; names, hashes, source observations and port obligations are recorded for later work.

## Uncertain selected inputs

`NOASSERTION` means unresolved permission or inheritance. It is an explicit license state, not a missing field. Every such selected input has `REFERENCE_ONLY`, `copy_status: BLOCKED`, no destination license and a reason. Its issue, regression and independent-oracle obligations remain assigned. Resolving the grant requires an evidence update and review before copying.

| Selected inputs | Observed evidence | Required next action |
|---|---|---|
| W private compiler reports, oracle files and linker patch | Seven selected files lack SPDX; no private root license/manifest grant was observed | TC02 resolves ownership, applicable upstream fragments and grants before copying; retain H29–H31 obligations and consumer removal tests |
| P Aya/Aya-obj patch files | Upstream MIT/Apache license texts and reconstruction metadata exist; local patch additions lack an established grant | TC02/BP06 preserve upstream notices and resolve local addition terms before importing any patch text |
| P third-party/sources.json | No per-file grant established by inspection | Keep reference-only until inheritance/provenance terms are resolved |
| M generated corpus and toolchain lock; LJ and J toolchain locks | Missing SPDX and unresolved per-file inheritance | CP10/NX02/TC02 review generator and repository policy evidence before extraction |
| O identity_domain_audit.rs and d_btf_load.rs | No header, but root Cargo declaration and license support GPL-3.0-or-later inheritance | Preserve recorded inheritance evidence and root notices during the selected GPL port |

The source observer mechanically captured a bare quote alongside `Apache-2.0 WITH LLVM-exception` in J `src/mojobpf/inspect.py`. The ledger retains both raw fields, records the correction and uses only the supported exact expression. A bare quote is not an SPDX expression or additional license. This normalization makes no new grant.

P `third-party/README.md` refers to missing `licenses/` and `licenses/sources.json` paths in the selected checkout. The observer hashed existing generated upstream license texts instead. This is an open donor documentation gap; SB01 does not repair or mutate the donor.

## Evidence and copy gate

Each selected file records its full source commit, observed bytes, pinned-tree blob hash, dirty hash where applicable, declared license resolution, relevant license/manifest hashes, adoption choice, intended contract and responsible task. Files lacking a header do not receive an invented SPDX grant. Exact evidence hashes provide byte identity, not authenticity, legal advice or runtime qualification.

Before a production port: recheck the selected bytes and moving-file delta; retain headers and notices; record destination path and package license; carry the original regression, independent oracle and known-bad control; review artifact/dependency compatibility; then run affected checks on actual ScopeBase bytes. Do not use an upstream merge as proof that the selected compiler/backend includes the fix. Unresolved files remain blocked while independent components proceed within their own qualified scope.
