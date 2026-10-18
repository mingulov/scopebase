# ScopeBase current handoff

Date: 2026-10-18. Current work: finish independent verification of the execution setup while SB01 source/contract intake proceeds in its isolated worktree under the active M0–M6 goal. Product requirements remain 119 and tasks remain 86; no library task is accepted yet.

## Active goal and accepted steering

Implement ScopeBase fully through M0–M6 using the specifications and TODO, in dependency order with independent reviews and each capability's required qualification. Existing product migrations and publication remain later. Port and preserve the donor fixes/regressions/knowledge, including relevant branches, worktrees and WIP. Better architecture/APIs are allowed with preserved behavior and coverage. Genuinely missing necessary components may be independently implemented/tested and added to TODO with dependencies and acceptance. The user permits appropriate CI/CD and privileged local tests for actual BPF/kernel behavior; ownership and evidence rules still apply.

The authoritative active goal is the thread goal tool. Read it at restart rather than creating another goal or inferring a budget. `.scopebase/goal.md` is a local text snapshot used for immutable task briefs. [TODO](TODO.md), [master plan](docs/superpowers/plans/2026-10-17-scopebase.md) and [development workflow](DEVELOPMENT.md) are the working routes.

## Checkouts and next steps

Main repository: `/home/user/src/m/bpfscope`. Setup integration: `.worktrees/execution-setup`, branch `chore/execution-setup`, initial contract commit `2b39988`. Isolated helper branches are `chore/setup-job-helper`, `chore/setup-review-tools`, `chore/setup-doc-checker`; preserve their dirty paths/evidence. The private setup ledger is `.worktrees/execution-setup/.scopebase/preparation-20261018/progress.md`.

1. Integrate helper commits and run `python3 -m unittest discover -s tests/orchestration -v`, `python3 tools/check_planning_docs.py`, actual doctor and dry-run.
2. Complete independent Astra review and any selected bounded Muse review; fix and recheck actual findings. Record exact final setup SHA/evidence, integrate the local setup and preserve its custody.
3. SB01 is implementing in `.worktrees/sb01-intake`, branch `feat/sb01-intake`, from base `c62d4dc`. The read-only source refresh records 124 selected files across eight authorities, including two dirty MojoBPF inputs. Its assignment and report/evidence are in that worktree's private `.scopebase/`; root retains the source refresh under the setup ledger. Preserve the GPL direct-port licensing and unresolved reference-only inputs, per-file provenance, adopted defects, regressions and proposed API mapping.
4. Accept SB01 only after its own checks/review, then start SB02. Future lanes follow the product DAG. Update this handoff with exact current commits, commands/results, open gates and resource owners at every substantive transition.

Model routing: explicit native Sol high/xhigh implementation; reasoned fresh Sol max escalation when needed; independent Astra high/xhigh critical/architectural review; Luna mechanical checks; supplementary Muse Spark1.3 max/Contributor-on ideas and readonly review. No helper automatically launches or accepts a product task. No privileged runtime resources are currently owned by this setup.
