# Final research verification

This is the research-stage snapshot, preceding the full ScopeBase specification/plan package. Current planning checks are recorded in [planning verification](../../superpowers/reviews/2026-10-17-scopebase-verification.md).

Date: 2026-10-17. This record covers the research artifacts in this repository. It does not qualify an extracted library, donor product, compiler or runtime environment. No product build, live probe, mount fixture, installation or consumer migration was performed for this study.

## Scope and custody

The study considered locally visible branch/remote-tracking refs, registered worktrees and relevant dirty/untracked source and documentation in p11scope, KryProbe, remote OSSLscope and remote MemVeil/libbpf-mojo. MojoBPF received a bounded future-integration investigation. Detailed inventories, exact pins, source/test anchors and limits are in the four donor reports; they are not assertions that every historical line was audited or that all upstream refs were freshly fetched.

Source workspaces were inspected read-only. Moving p11scope work was recorded through `eb6bbe1df910a3cf40b6b7e8965cc65c69f203ae`; the selected initial identity donor file was unchanged across that final refresh. The roadmap requires a fresh selected-file/WIP check before porting. A recorded source pin is provenance, not a new passing result. MemVeil's consumed libbpf-mojo bundle remains distinct from newer sibling/joint worktrees.

Only root instructions, navigation and research artifacts were created or revised here. There is no Cargo workspace or implemented Scopebase suite. The regression catalog explicitly labels every family planned, unimplemented and not run; exact extraction pins and required subcase cells are deliberately unresolved until port selection.

## Independent review and corrections

- Astra's [architecture review](architecture-review.md) narrowed the first increment to retained files/bounded reads, retained file authority through attachment retirement, kept compiler work immediate without forcing a new crate, and required component-specific evidence. Its five blocking design corrections were resolved in the proposal.
- Sol's [synthesis review](synthesis-review.md) prompted explicit H29–H32 compiler regressions, corrected LLVM upstream status, aligned milestone dependencies, and preserved affected-kernel versus repaired-kernel workaround tests. Its findings and refinements were rechecked as resolved.
- Astra's [conformance review](conformance-architecture-review.md) made shipped user checks part of ready mapping support and separated observations, runtime authority and test reports. Final corrections cover scoped G dependencies, backend trust, post-detach operation identity, operator-route alternatives and proportionate cleanup records.
- A further Astra review of the testing delivery plan and catalog found ambiguous unconditional family tiers and a Rust-package omission in H13. Catalog v0.2.0 separates family inventories from required subcase plans and applies T5 to every selected delivered Rust/native component; Astra rechecked the correction as resolved. Advertised live claims retain mandatory T4. No other material contradiction was reported in that bounded review.
- Luna checked document structure/navigation and the requested root `AGENTS.md`. Earlier counts in [document checks](document-checks.md) are staged historical results; the final scan below covers the expanded artifact set.

These reviews assess the research and proposed contracts. They do not establish implementation readiness or runtime correctness.

## Final artifact checks

The root agent's Python scan completed successfully over the final artifact set:

- 21 Markdown files and 3 JSON files; all JSON parsed.
- 319 local link/reference occurrences, including Markdown links and catalog donor-document references; no missing targets or heading anchors.
- 53 Markdown tables; consistent row widths and closed fenced blocks.
- Contiguous, unique H01–H32, UC01–UC14 and G01–G23 inventories; 28 overlap rows and 81 unique backlog item IDs.
- All catalog H families match the testing matrix's tier inventories. Every UC/G/TODO reference and donor alias/document anchor resolves. Each case remains PLANNED, NOT_IMPLEMENTED, NOT_RUN and non-runnable, with a required subcase plan explicitly unresolved before porting.
- All 14 upstream research SHA values have full 40-hex syntax. This is a format check of the recorded observations, not a fresh upstream status check or an adoption decision.
- No trailing whitespace across the Markdown/JSON files. `git diff --check` also succeeded, but the new files are untracked, so the explicit whole-file scan is the relevant coverage.

Git status contains the expected new `AGENTS.md`, `README.md` and `docs/` tree. These checks establish research-artifact consistency only; they do not validate all technical propositions or execute the proposed tests.

Luna independently rechecked the expanded set: 235 Markdown local links/anchors resolved, all three JSON files parsed, and all ID counts agreed. It confirmed the catalog's descriptive family tiers versus unresolved required subcase plans and the explicit future/unobserved labels on command examples and illustrative results. No actionable finding remained. The root scan's 319 references additionally include 84 catalog donor-document references.

## Remaining implementation work

The [TODO](TODO.md) remains open for implementation. The [testing delivery plan](testing-delivery-plan.md) defines issue-to-regression-to-consumer closure and reopen rules. Its finite support cells must become concrete fixture recipes and required subcase matrices; production adapters, independent oracles, known-bad controls, runner validation and source-free installed checks still need implementation and actual results.

The 32 H families, 14 UC scenarios and 23 G obligations overlap and have different roles. They are not 69 independent tests and are not 69 confirmed product defects. The 28-row overlap matrix distinguishes inspected implementation, incomplete evidence, candidate reuse and inapplicability. Missing evidence is not automatically a missing implementation.

Public upstream research and naming observations are dated evidence. Dependency selection, licenses, crate availability, selected compiler inclusion and support cells require refresh when implementation or publication reaches those decisions. No publication, upstream issue, message or package reservation was made.
