# ScopeBase

[TT02-RSP01 prepared-response contract](docs/superpowers/specs/2026-10-22-scopebase-tt02-prepared-response.md) and [verification plan](docs/superpowers/plans/2026-10-22-scopebase-tt02-prepared-response-verification.md) ratify exact-r2 scoped maintenance under accepted TT02. Strict BP03 response-F consumed this work at acceptance `bfb9452`; native/operator/profile bindings remain with their later owners. Prior TT02 acceptance and 86-task/120-requirement/179-mapping inventory are unchanged.

Start with the [decisions and reasons](docs/superpowers/specs/2026-10-18-scopebase-decisions.md), [executor contract](docs/superpowers/specs/2026-10-18-scopebase-executor-contract.md) and [amended execution plan](docs/superpowers/plans/2026-10-18-scopebase-plan-repair.md). They specify porting boundaries, task readiness, provisional Apache userspace/GPL BPF licensing and the decisions an executor must not invent.

The [amendment verification](docs/superpowers/reviews/2026-10-18-scopebase-plan-hardening-verification.md) records independent review and resolved plan defects. **Fifty-one of 86 tasks are accepted** within their stated scopes (recounted at the 2026-10-25 merge; full per-task list and records are in [TODO](TODO.md) and [traceability](docs/superpowers/plans/2026-10-17-scopebase-traceability.json), reviews under `docs/reviews/`). The six packages (`scopebase-linux`, `scopebase-capture`, `scopebase-testkit`, `scopebase-bpf`, `scopebase-sdk`, `scopebase-conformance`) export bounded APIs; complete runtime/conformance profiles remain open.

Development is coordinated through [DEVELOPMENT.md](DEVELOPMENT.md) and the single current [handoff](handoff.md). Local helpers prepare isolated jobs, immutable reviews and cooperative build locks; supplementary [Muse reviews](orchestration/MUSE-ORCHESTRATION.md) remain independent of task acceptance.

Development resumed on 2026-10-22 and the integration branch was fast-forward merged into `main` on 2026-10-25 (139 commits, tip `db47ca3`) after the [gap audit](docs/reviews/2026-10-25-scopebase-gap-audit.md). Fifty-one of 86 tasks are accepted; thirty-five remain planned. [Current resume points](handoff.md#resume-here) are the single restart route; the earlier [transfer record](docs/reviews/2026-10-18-scopebase-transfer.md) remains historical.

CP06 is [accepted](docs/reviews/2026-10-22-cp06-views.md) at `e6fe76c`: scoped immutable views, required feeds and checked corrections with twelve qualified source/archive configurations and six root archive cells. Reducer, audit/export, installed conformance and migration work remains with its later owners.

LX05 implements the [strict pure parser contract](docs/superpowers/specs/2026-10-18-scopebase-lx05-proc-contract.md) within its [accepted package scope](docs/reviews/2026-10-22-lx05-proc.md). Runtime mapping identity, ready mapped-image support and complete conformance profiles remain later capabilities.

The [accepted setup verification](docs/superpowers/reviews/2026-10-18-scopebase-execution-verification.md) records 70 development-tool tests and independent review. These establish the coordination helpers, while product tasks and capability qualification remain separately tracked.

Start with the [project specification](docs/superpowers/specs/2026-10-17-scopebase-design.md), [complete implementation plan](docs/superpowers/plans/2026-10-17-scopebase.md), and [TODO](TODO.md). The master documents link all subsystem specifications and detailed plans. The [traceability registry](docs/superpowers/plans/2026-10-17-scopebase-traceability.json) maps source requirements, tests, tasks and dependencies.

ScopeBase covers independently usable Rust libraries, distributed tests and documentation; a small SDK with real host/live reference applications; and selective C/Mojo interoperability. Existing p11scope, OSSLscope, KryProbe, MemVeil and MojoBPF migrations are separately planned for later.

The amended planning package contains 120 requirements and 86 dependency-linked tasks, including testing and acceptance gates. TC-R10/H33 add source/build/kernel license boundaries; original IDs remain unchanged. The [original review record](docs/superpowers/reviews/2026-10-17-scopebase-verification.md) describes its earlier 119-requirement baseline. Run `python3 tools/check_planning_docs.py` for current documentation/traceability; this is not a ScopeBase runtime test.

The [feasibility study and extraction roadmap](docs/research/2026-10-17-shared-libraries/README.md) preserve the source research.

The study covers p11scope, KryProbe, OSSLscope, MemVeil/libbpf-mojo, and limited future integration with MojoBPF. It includes branches, worktrees, relevant uncommitted source/documentation, existing-library research, an overlap matrix, a testing strategy, and an actionable backlog.

The [testing delivery plan](docs/research/2026-10-17-shared-libraries/testing-delivery-plan.md) follows an issue from reproducer through consumer migration and installed checks. Its [regression catalog](docs/research/2026-10-17-shared-libraries/regression-catalog.json) preserves the original 32 families and appends H33; these are planned obligations, not executed results. Repository working instructions are in [AGENTS.md](AGENTS.md).

Accepted integrations passed their recorded affected archive cells (see each acceptance record); the current twenty-cell matrix was not rerun in full at the 2026-10-25 merge, and MSRV/all-features/live-cell qualification at merged bytes is tracked as NOT_RUN rows in the [gap audit](docs/reviews/2026-10-25-scopebase-gap-audit.md). Installed conformance, kernel capability and product migrations remain planned work. See [dependency policy](docs/dependencies.md) and [TODO](TODO.md). Frozen private donor copies are the implementation source; they are pruned and complete for the recorded scope, and ongoing work does not recheck live donors.
