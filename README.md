# ScopeBase

Start with the [decisions and reasons](docs/superpowers/specs/2026-10-18-scopebase-decisions.md), [executor contract](docs/superpowers/specs/2026-10-18-scopebase-executor-contract.md) and [amended execution plan](docs/superpowers/plans/2026-10-18-scopebase-plan-repair.md). They specify porting boundaries, task readiness, provisional Apache userspace/GPL BPF licensing and the decisions an executor must not invent.

The [amendment verification](docs/superpowers/reviews/2026-10-18-scopebase-plan-hardening-verification.md) records independent review, resolved plan defects and the checks performed. Plan acceptance does not accept the existing SB01 implementation candidate or qualify a library.

Development is coordinated through [DEVELOPMENT.md](DEVELOPMENT.md) and the single current [handoff](handoff.md). Local helpers prepare isolated jobs, immutable reviews and cooperative build locks; supplementary [Muse reviews](orchestration/MUSE-ORCHESTRATION.md) remain independent of task acceptance.

The [accepted setup verification](docs/superpowers/reviews/2026-10-18-scopebase-execution-verification.md) records 70 development-tool tests and independent review. These establish the coordination helpers, while product tasks and capability qualification remain separately tracked.

Start with the [project specification](docs/superpowers/specs/2026-10-17-scopebase-design.md), [complete implementation plan](docs/superpowers/plans/2026-10-17-scopebase.md), and [TODO](TODO.md). The master documents link all subsystem specifications and detailed plans. The [traceability registry](docs/superpowers/plans/2026-10-17-scopebase-traceability.json) maps source requirements, tests, tasks and dependencies.

ScopeBase covers independently usable Rust libraries, distributed tests and documentation; a small SDK with real host/live reference applications; and selective C/Mojo interoperability. Existing p11scope, OSSLscope, KryProbe, MemVeil and MojoBPF migrations are separately planned for later.

The amended planning package contains 120 requirements and 86 dependency-linked tasks, including testing and acceptance gates. TC-R10/H33 add source/build/kernel license boundaries; original IDs remain unchanged. The [original review record](docs/superpowers/reviews/2026-10-17-scopebase-verification.md) describes its earlier 119-requirement baseline. Run `python3 tools/check_planning_docs.py` for current documentation/traceability; this is not a ScopeBase runtime test.

The [feasibility study and extraction roadmap](docs/research/2026-10-17-shared-libraries/README.md) preserve the source research.

The study covers p11scope, KryProbe, OSSLscope, MemVeil/libbpf-mojo, and limited future integration with MojoBPF. It includes branches, worktrees, relevant uncommitted source/documentation, existing-library research, an overlap matrix, a testing strategy, and an actionable backlog.

The [testing delivery plan](docs/research/2026-10-17-shared-libraries/testing-delivery-plan.md) follows an issue from reproducer through consumer migration and installed checks. Its [regression catalog](docs/research/2026-10-17-shared-libraries/regression-catalog.json) preserves the original 32 families and appends H33; these are planned obligations, not executed results. Repository working instructions are in [AGENTS.md](AGENTS.md).

This repository contains research, specifications and development coordination tools. No shared library has been implemented or qualified by the planning/setup work. The source workspaces were inspected without modification.
