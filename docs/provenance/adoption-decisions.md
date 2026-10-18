# Source adoption decisions

Revision 1, 2026-10-18. Owner: SB01. These are selected implementation dispositions, with production ports still unexecuted. [The ledger](donors.json) preserves all 124 selected observations from eight authorities, both dirty MojoBPF inputs, all 1,529 mechanically extracted symbol candidates and the observer's 389 selected regression candidates. A symbol candidate can be a helper or wrapper; its presence is inspected source evidence, never a passing test or complete coverage claim.

## How to use the ledger

`donors` names project, host, repository/worktree, immutable commit/tree, observed branch label, source-selection authority and policy evidence. `selected_tree_entries` is the observed subset of that tree, not a complete checkout inventory. `files` gives the selected path, full commit, SHA-256 of observed bytes, separate original-tree SHA-256 and optional dirty SHA-256, license evidence, owner, contract and source issue/test names. `source_evidence.original_observation_sha256` binds the original normalized observer record held with private preparation evidence. The preparation artifact itself is bound by `observation.source_inventory_sha256`.

`references` preserves H, G, UC, research TODO and execution-task IDs. `obligation_coverage` assigns all 178 planning source obligations, including unselected future work; attribution does not promote that work into an implementation. `case_family_inputs` retains independent-oracle descriptions, known-bad controls and limits for H01–H32. `port_groups` keeps the defect explanation and named existing regressions with their responsible tasks. Root TODO remains the progress ledger.

The observer left six selected files without a port-group tag. SB01 explicitly associates KryProbe workload launch/host reader with process custody, MemVeil's native attempt decoder with capture/replay, MemVeil's lock with native dependency intake, LJ's generic ring with staging, and LJ's generic header with native ownership. These are assignments to existing obligations, not new support claims or an additional generic metadata subsystem.

## Selected dispositions

| Source / contract | Disposition and owner | Preserved behavior and boundary |
|---|---|---|
| P/O held files, reads and mapping | `PORT_SOURCE`, LX01–LX08 | Original descriptor authority, O_PATH admission/reopen, positional bounded reads, same observed bytes, stat/maps/mount domains, retained proof, collisions and no-new-target-mapping. GPL host source/tests remain GPL-compatible. File handling alone does not close mapped-image readiness |
| P/O/K process and helper custody | `PORT_SOURCE`, LX09–LX11 | Original pidfd/proc view, birth versus exec, owned-child signaling, bounded helpers, late output and pending cleanup. Output policies remain application-local |
| P/O attachment planning and retirement | `PORT_SOURCE` plus selected backend adapters, BP03–BP05 | Bounded bisection and stop classes; retain original file through partial/failed close. Physical link retirement is distinct from image continuity and quiescence |
| K possible-CPU, WHO and diagnostics | `PORT_SOURCE`, BP02/BP07 | Possible rather than online geometry; 80-to-88-byte consumer stride; insertion marker including genuine zero; successful-inserter identity; independent saturating diagnostic loss |
| P/K ring and L/LJ staging | GPL host `PORT_SOURCE`; existing native `DEPENDENCY_ADAPTER`, BP06/NX03 | Busy/discard/wrap and fixed boundaries; one delivery after short retry/source mutation; callback-negative consumption. Unknown Aya patch-addition grants remain blocked |
| P/K/O/M writer and closure evidence | `PORT_SOURCE`, BP07/BP08/CP09 | Per-program/CPU ownership, reentry refusal, epochs and pending fences. Product stop protocols and MemVeil's model remain distinct |
| K/P/O/M BTF/object handling | Tested dependency adapters and narrow `PORT_SOURCE`, BP09/BP10/TC05/TC06 | Bounded graphs, parent containment, split strings, exact rival types and prototypes. Domain shape profiles remain local; final objects and runtime linkage require their separate evidence |
| K/O/M capture facts/replay | `PORT_SOURCE` with independent vectors, CP01–CP11 | Unknown versus zero, generation/reuse, exactly-once losses, independent facts under missing correlation and transient query overlays. Crypto/DMA reducers remain local |
| L/LJ native handles/configuration | `DEPENDENCY_ADAPTER`, NX02–NX06 | Reuse the existing bridge; preserve size/version/layout, mutable output, parent lifetime, thread rules, rollback, map refusals and close versus release |
| J compiler implementation / standard objects | Compiler mechanism `PRODUCT_LOCAL`; test/object `VECTORS_ONLY`, TC/NX02 | Keep MojoBPF as a producer; reuse actual emitted-object and independent positive/negative regressions. Dirty CR09-M1 bytes are observed candidates requiring explicit later source selection |
| W private compiler and uncertain metadata/patch additions | `REFERENCE_ONLY`, assigned TC/BP/CP/NX owners | Block copying while retaining initialized-padding, argument-limit, atomic old/new-value, selector, private-stack, debug/BTF and removal-test obligations |

`INDEPENDENT_CONTRACT` is available when a separately justified original contract implementation fills a real missing component. It is not the default for existing donor fixes, and cannot be used to hide copied source or tests. Every newly required component still needs explicit TODO ownership, independent acceptance and dependency records.

## Source custody and moving heads

The intake uses the observer's completed 2026-10-18 read-only inspection. P advanced beyond its research baseline, with the 31 selected files unchanged at that observation. K product main stays selected; the separate selftest-lane-policy work is not silently adopted. O's preview worktree remains distinct from its product root. L and LJ remain separate authorities despite matching selected core bridge bytes. MemVeil's recorded consumed bridge is `681096cb588379307d0c8e94e1d77e53de4be22f`, which differs from L and LJ.

J's CR09-M1 authority has two selected dirty files: `tests/kernel/test_map_roundtrip.py` and `compiler/lib/MapMetadata.cpp`. Both original-tree and observed WIP hashes are retained. Its other current development, D2 worktrees and untracked experiments remain unselected research. Choosing either dirty input for a production port requires refreshing its bytes and comparing the selected authority at that time. Do not merge, reset, clean or freeze another owner's workspace.

All unselected refs, worktrees, remote-tracking refs, documents and experiments remain `RESEARCH_ONLY_NOT_ADOPTED`. Their full inventories stay in the research/preparation evidence, avoiding a competing bulk history in the public intake. A cached ref does not establish current publication. This intake ran no donor build, runtime test, live probe, source mutation or publication.

## Validation routes

Run the following from the repository root:

```sh
python3 -m unittest discover -s tools/planning/tests -v
python3 tools/planning/check_traceability.py docs/superpowers/plans/2026-10-17-scopebase-traceability.json
```

Default validation checks JSON, stable source inventories, task/requirement ownership, obligation coverage, immutable commits, selected-path observation membership, hashes, references, adoption restrictions and licensing structure. It reports `mode: STRUCTURAL`, `source_verification: NOT_RUN`, `qualification: NOT_EVALUATED`. It does not require private SSH, prove the source observations true or run ScopeBase behavior.

Explicit source validation also reads selected immutable Git objects and verifies current dirty bytes:

```sh
python3 tools/planning/check_traceability.py docs/superpowers/plans/2026-10-17-scopebase-traceability.json --verify-local-sources --source-root O=/local/osslscope --source-root M=/local/memveil --source-root L=/local/libbpf-mojo --source-root LJ=/local/libbpf-mojo-successor --source-root J=/local/mojobpf
```

Aliases need the exact selected commits locally. Local donor paths are defaults only for `host: local`; remote observations require explicit local roots. No SSH, fetch, build, donor mutation or privilege escalation occurs. Exit 0 means the requested checks are valid, 2 means required source evidence is unavailable/incomplete, and 3 means invalid records or mismatched bytes. `VERIFIED_SELECTED_SOURCES` still does not mean runtime qualification or license adjudication. Recheck moving source bytes immediately before copying.
