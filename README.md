# ScopeBase

Start with the [project specification](docs/superpowers/specs/2026-10-17-scopebase-design.md), [complete implementation plan](docs/superpowers/plans/2026-10-17-scopebase.md), and [TODO](TODO.md). The master documents link all subsystem specifications and detailed plans. The [traceability registry](docs/superpowers/plans/2026-10-17-scopebase-traceability.json) maps source requirements, tests, tasks and dependencies.

ScopeBase covers independently usable Rust libraries, distributed tests and documentation; a small SDK with real host/live reference applications; and selective C/Mojo interoperability. Existing p11scope, OSSLscope, KryProbe, MemVeil and MojoBPF migrations are separately planned for later.

The planning package contains 119 requirements and 86 dependency-linked tasks, including testing and acceptance gates. See the [review and verification record](docs/superpowers/reviews/2026-10-17-scopebase-verification.md). Run `python3 tools/check_planning_docs.py` to check the current documentation and traceability; this is not a ScopeBase runtime test.

The [feasibility study and extraction roadmap](docs/research/2026-10-17-shared-libraries/README.md) preserve the source research.

The study covers p11scope, KryProbe, OSSLscope, MemVeil/libbpf-mojo, and limited future integration with MojoBPF. It includes branches, worktrees, relevant uncommitted source/documentation, existing-library research, an overlap matrix, a testing strategy, and an actionable backlog.

The [testing delivery plan](docs/research/2026-10-17-shared-libraries/testing-delivery-plan.md) follows an issue from reproducer through consumer migration and installed checks. Its [32-family regression catalog](docs/research/2026-10-17-shared-libraries/regression-catalog.json) records planned obligations, not executed results. Repository working instructions are in [AGENTS.md](AGENTS.md).

This repository currently contains research and proposals. No shared library has been implemented or qualified by this study. The source workspaces were inspected without modification.
