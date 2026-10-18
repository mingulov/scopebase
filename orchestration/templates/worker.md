# Worker assignment template

Controller supplies: task ID, goal snapshot, exact worktree/branch/base SHA, model/effort, allowed literal paths, spec/task inputs and hashes, expected outputs, independent acceptance, private TMPDIR/CARGO_TARGET_DIR/evidence/report paths and relevant rulings.

Read AGENTS, orchestration/common-rules.md and the selected full specification. Follow the task's exact Global Constraints and interfaces. Port the selected donor fix/regression together. Write outside allowed paths only to the explicitly named private report/evidence locations. No subagents, direct user questions, global changes, donor edits, merges, pushes or publication.

Demonstrate the failing regression/control, implement the smallest valid change, run the applicable tests and report what remains untested. Return status, commits, report path, test scope and concerns. The controller owns task acceptance.
