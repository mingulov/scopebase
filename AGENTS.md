# Working in this repository

## Purpose and current state

This is the specification, planning and research workspace for **ScopeBase**, reusable foundations from p11scope, KryProbe, OSSLscope and MemVeil/libbpf-mojo, including SDK and selective C/Mojo/MojoBPF interoperability. Package names use `scopebase-*`; they are not published or reserved by this work.

The repository currently contains specifications, implementation plans, research, a backlog, accepted source-intake validation and local development coordination tools. It has no implemented shared library, Cargo workspace or qualified runtime suite. Do not describe a proposed command, catalog entry, donor test or historical receipt as an implemented or passing ScopeBase test.

The user's priorities are:

1. Independently useful Rust components, reusable regression tests and issue documentation.
2. A small SDK for future scope applications after real components have independent reference consumers.
3. Selective C/Mojo interoperability, building on existing bridges and standard object formats.

The user requires deep, proactive gap analysis, preservation of hard-won fixes, and tests that library users can run from the delivered package. A small file-handling pilot is an implementation increment; it does not complete the requested ready mapped-image capability.

## Where to start

- [Decision register](docs/superpowers/specs/2026-10-18-scopebase-decisions.md), [executor contract](docs/superpowers/specs/2026-10-18-scopebase-executor-contract.md), and [repair plan / all task routes](docs/superpowers/plans/2026-10-18-scopebase-plan-repair.md): mandatory WHAT/WHY decisions, source slices, stop rules and task origins. Read before dispatch or implementation; source inventory and dependency readiness alone do not make a packet ready.

- [Development workflow](DEVELOPMENT.md), [current handoff](handoff.md) and [execution policy](orchestration/policy.json): controller/worker roles, model efforts, task/review preparation and restart custody. Product work follows the active thread goal; do not create a replacement goal or infer a budget.

- [Root README](README.md), [project specification](docs/superpowers/specs/2026-10-17-scopebase-design.md) and [master plan](docs/superpowers/plans/2026-10-17-scopebase.md): current scope, contracts, completion levels and subsystem reading map.
- [Root TODO](TODO.md): canonical execution ledger. [Traceability](docs/superpowers/plans/2026-10-17-scopebase-traceability.json) maps every source obligation and plan dependency. The [research TODO](docs/research/2026-10-17-shared-libraries/TODO.md) remains the stable source inventory, not a competing progress ledger.
- [Main study](docs/research/2026-10-17-shared-libraries/README.md): supporting source research and earlier decisions.
- [Overlap matrix](docs/research/2026-10-17-shared-libraries/overlap-matrix.md): donor/recipient applicability and evidence limits.
- [Testing strategy](docs/research/2026-10-17-shared-libraries/testing-strategy.md), [user conformance](docs/research/2026-10-17-shared-libraries/user-conformance.md), and [gap analysis](docs/research/2026-10-17-shared-libraries/gap-analysis.md): required behavior, user delivery and unresolved public contracts.
- [Testing delivery plan](docs/research/2026-10-17-shared-libraries/testing-delivery-plan.md) and [regression catalog](docs/research/2026-10-17-shared-libraries/regression-catalog.json): issue lifecycle, affected-check selection and planned H case families. The catalog is not a runner or a result ledger.
- Read only the donor notes relevant to the current work. Their exact pins and branch/worktree inventories override assumptions about `main`. Implementation uses private frozen donor copies, including captured WIP; validate selected bytes in those copies, not by repeatedly refreshing the live projects.

The user requested the full specifications and plans together; authoring them does not claim implementation or authorize external publication. Follow the user's current task and applicable skill workflow without inventing additional approval requirements or repeating existing authorization. Implementation uses the master specification plus the selected subsystem plan. Later product migrations MG01–MG05 do not gate independently qualified ScopeBase packages or SDK/native reference clients.

## Source workspaces and custody

| Project | Location |
|---|---|
| p11scope | `/home/user/src/m/p11scope-ws`; active product has been `.worktrees/v040-integration` |
| KryProbe | `/home/user/src/m/kryprobe-ws`; product and active fixes may be in different worktrees |
| OSSLscope | `ssh -l agent um790`, `/work/osslscope-ws` |
| MemVeil / libbpf-mojo | Same host, `/work/memveil-ws` |
| MojoBPF | Same host, `/work/mojobpf-ws`; future integration consideration |

These are independent, actively developed source origins. The user's 2026-10-18 direction is to capture private frozen copies and proceed from them. The capture destination is `/home/user/src/m/bpfscope/.scopebase/donor-snapshots/2026-10-18/`; each completed project capture records its own source/history/worktree mapping, WIP, omissions and limitations. A directory's existence alone does not mean its capture is complete. Include applicable local/remote-tracking refs, registered worktrees, uncommitted source, untracked documents and preserved experiments; generated build outputs and VM images need not be copied. Frozen Git pointers and alternates must not lead back into live donors.

Use completed frozen copies for source selection, porting, regression preservation and implementation. Do not poll or repeatedly revalidate live donor heads, wait for donor cleanliness, or restart analysis because development continues. A later refresh is a deliberate, bounded update for a named needed change, with its scope recorded; it is not a prerequisite for every task. Capture is read-only with respect to donors and need not claim an atomic snapshot across concurrent edits. Distinguish ancestor/patch-equivalent history from genuinely divergent work within the captured history. Do not assume all branches should be merged or that captured remote-tracking refs prove current publication.

Preserve dirty files, source history, worktrees, locks, leases, VM resources and evidence. Do not reset, clean, switch, delete, merge or update dependencies in a donor as part of research. Capture the chosen state without freezing another owner's work. Product implementation belongs in an explicitly selected checkout and task scope; captured files remain immutable source inputs.

## Architectural rules

- The user's provisional choice is **Apache-2.0 for user-owned userspace ScopeBase code**, **GPL-2.0-only for BPF programs**, and **GPL-3.0-or-later for applications**, with no project MIT option. Shared project-owned target source needs `Apache-2.0 OR GPL-2.0-only` or approved separation. Historical donor SPDX and author-authorized destination terms are distinct. Do not treat the author's own old GPL label or missing header as an automatic copying prohibition. Preserve actual third-party options/notices. D03's specific Aya target dependency choice gates that payload, not unrelated host work.
- Source grants, final ELF `license`, and loader-supplied runtime license bytes are independent checks. The working GPL-v2 payload uses a recognized string such as `GPL`; SPDX or `Dual Apache/GPL` is not a substitute. A successful load cannot prove source-license compatibility. New H33 checks are planned, not implemented.
- PORT/ADAPT preserves identified donor mechanisms, affected call sites and original regressions. NEW requires a concrete missing-mechanism reason and frozen design. The packet names source symbols, destination behavior, cross-donor differences, oracle and bad control. Return NEEDS_DECISION for missing architecture/source/license/support/expected-result choices; do not invent replacements, placeholder APIs or weaker tests.
- Prefer existing Aya/libbpf, ELF/BTF, procfs and descriptor/path libraries plus narrow adapters. Extract new mechanisms only where the donor regressions demonstrate a missing contract.
- Keep host-only Rust packages usable without BPF toolchains, privileged setup or application dependencies. Do not silently install compilers or change host limits, credentials, signals or namespaces.
- Keep process observation/control authority, task birth/exec, stat/maps/mount identity, content observations and BTF type domains distinct. A pathname, PID, descriptor number or maps key alone is not universal identity.
- Retain original file authority through attachment retirement or explicit unresolved custody. Dropping an owner does not prove fallible native cleanup succeeded.
- Keep application policy and domain state machines local. Do not unify shutdown protocols, batch/live drivers, privacy rules or schemas merely because their types look similar.
- Explicit calibration means the caller controls effects; code, tests and documentation for advertised calibration behavior are still required. Test reports cannot construct live runtime authority.
- Preserve per-file provenance and licensing. Record upstream fixes and their removal tests; a merged fix does not establish inclusion in a selected compiler/backend.
- Preserve actual final-object ISA/helper/BTF/verifier/attach requirements. Do not remove initialized padding/private-stack/linker workarounds from current-kernel success or version comparisons. BPF_PROG_LOAD EPERM/EACCES has different possible causes; preserve operation/stage/verifier evidence and leave ambiguous causes Unknown.
- Donor inspection must suppress Git lazy fetching as well as explicit fetch. A missing promised local object is incomplete evidence, not permission to mutate a partial clone.

## Testing and completion standards

Every promoted mechanism needs its contract, defect explanation, independent oracle, known-bad control, selected donor pin, real reference consumers and a later migration/duplicate-retirement criterion together. Package-ready and product-migrated are separate completion levels; two thin wrappers around one mocked helper do not establish independent usability.

Keep evidence tiers distinct: inspected test source, pure/model tests, actual emitted objects, real Linux integration, isolated live-kernel behavior, and installed/downstream consumers. Required SKIP/BLOCKED/NOT_RUN, zero activity, successful loading or an old green run cannot certify changed bytes. An expected-refusal test can pass while its capability remains denied or unknown.

For a ready supported capability:

- Bind checks to the actual consumer library/version/features/backend and final objects, not the testkit's separately resolved copy.
- Ship a developer conformance API, fixtures and at least one independently usable installed operator route. Ordinary downstream `cargo test` does not automatically run dependency tests.
- Choose required cases from the advertised profile before discovering available environments. Missing required fixtures remain incomplete; unrelated optional profiles need not block a small component.
- Use independently generated positive and active-negative populations. A mutant must fail the intended semantic assertion, not merely crash during setup.
- Test real Btrfs/overlay/namespace cells for claimed mapping support, including identity collisions, copy-up, denial, retained proof and no-new-target-mapping behavior. Scripted fixtures remain a separate tier.
- State byte/work/memory/time bounds separately. A timeout does not interrupt every syscall or prove that a worker, mapping or link was retired.
- Preserve cleanup/partial-effect outcomes, counter epochs and evidence limits. User-local diagnostic success supplements maintainer qualification and does not replace runtime revalidation.
- Run affected checks after changes. Broaden or repeat only for changed inputs, failures or a named coverage gap; do not substitute endless stress reruns for a discriminating oracle.

Add missing necessary work to TODO with the affected capability, dependency and exit criterion. Keep H, UC and G identifiers stable; update cross-references and counts when adding cases. Do not close an implementation item merely because its design or test source exists.

Current planning inventory: 120 requirements, 86 tasks, 179 source-obligation mappings. H01–H32 retain their meanings; H33 appends license-boundary coverage. Original 119-requirement/32-family receipts remain historical. Packet completeness is currently a controller/expert obligation; the job helper does not enforce the new schema.

## Workflow and delegation

Use `rg` for source discovery. Batch independent reads; serialize mutations and dependent work. Give each agent disjoint file ownership and isolated build/evidence outputs. Shared privileged hosts/guests and heavy Cargo work require coordinated ownership; do not start live probes merely to make a research report look verified.

When parallel work materially helps, use GPT-6.1-Sol for substantial investigation/implementation, GPT-6-Astra for architectural decisions and adversarial review, and GPT-6-Luna for bounded mechanical tasks, subject to available model names and the user's latest direction. Sol high/xhigh is the implementation default; a fresh Sol max may handle a recorded hard-case escalation, including after unresolved Astra consultation. Muse Spark1.3 max/Contributor-on is a supplementary read-only ideas/review route; Sol/Astra/controller adjudicate its findings. Every native dispatch explicitly specifies model, effort and a fresh context. Provide focused context and review their results; an agent's completion message is not verification.

For the product planning baseline, run `python3 tools/check_planning_docs.py` to check JSON parsing, local links/anchors, table structure, stable IDs, source pins, requirement/source coverage, task/profile dependency graphs and claim consistency. Its fixed counts/status guards describe the initial planning baseline; amend them explicitly when implementation changes that state. `git diff --check` helps with tracked changes but does not cover untracked new files; inspect those too. Run `python3 -m unittest discover -s tests/orchestration -v` for the implemented coordination helpers. Run `python3 -m unittest discover -s tools/planning/tests -v` for the accepted SB01 intake validator and `python3 tools/planning/check_traceability.py docs/superpowers/plans/2026-10-17-scopebase-traceability.json` for structural ledger validation. The latter does not access donors or qualify source bytes unless explicit local-source verification is selected. These are development-tool tests. There is currently no Cargo/test command for a ScopeBase library implementation. Once code exists, document its actual commands here rather than inventing them now.

Save normative design/plan changes in `docs/superpowers/`, source findings in the research tree, and progress in root TODO. Keep traceability and navigation current. Reports must distinguish what was observed, inferred, proposed, unexecuted and still unknown. No external issue, message, publication or upstream submission follows automatically from finding a gap.

The active goal authorizes M0–M6 development, preserving/porting donor fixes and improving APIs when behavior and edge cases remain covered. Add new necessary components as separately testable TODO work. Appropriate CI/CD and privileged local/kernel tests are permitted within owned, coordinated resources; required unavailable cells remain incomplete. Product migrations and external publication remain later.
