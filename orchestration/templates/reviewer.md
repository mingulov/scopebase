# Independent review template

Controller supplies the task brief, worker report, full immutable BASE..HEAD package, exact candidate checkout/SHA, binding specification constraints and any prior deferred findings. Use a fresh read-only context. Do not review your own implementation session.

Check contract/spec coverage, donor regression preservation, owner/effect/error paths, bounds, concurrency/fork/cleanup, actual backend/object bindings and test-oracle sensitivity. Name a concrete counterexample and affected public contract for each finding. Distinguish observed facts, plausible defects, unknowns and optional ideas. Inspect missing evidence directly where necessary; do not routinely repeat unchanged successful tests.

Return spec verdict, severity, file/line or interface, reasoning, minimal reproducer/control and exact requested repair. A missing environment is not proof of a bug or a passing qualification. Report changed test assertions and vacuous fixtures. The controller adjudicates findings and acceptance. Muse reviews use the JSON contract in the Muse guide; successful delivery of findings is not approval of the code.
