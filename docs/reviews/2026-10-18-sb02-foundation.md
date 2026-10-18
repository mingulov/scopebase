# SB02 workspace and dependency foundation acceptance

Date: 2026-10-18. **SB02 accepted** by the controller at integration subject
`4bc7ae95c0cc46e084a81f5b7a24773514ac384d`. The reviewed policy code is
`92f6e33abe6fc878750bc25a6c1d81a012da1d87`, its documentation-only final is
`bdee9ad500e50d8fb5507d73d93a1966a04ba8ea`, and the reviewed dependency probes are
`eb4c77aa2e21719ca14f282968dcb5fa090c15c0`. Both branches were integrated without
conflicts; their implementation files are unchanged in the integration subject.

This accepts an empty virtual Cargo workspace, pinned compiler/dependency API
trials and development tools for package/feature policy. It supplies the SB02
prerequisite for component work. No shared library, installed conformance route,
live BPF behavior or supported product profile is qualified by this acceptance.

## Decisions and repairs

The [execution packet](../superpowers/plans/2026-10-18-scopebase-sb02-packet.md)
and [dependency report](../dependencies.md) record the requirements, exact pins,
API trials, dependency gaps and third-party notices. Rust 1.88.0 and 1.98.1 were
executed as the selected compiler pair; package-wide MSRV remains a later check.
The root has no product members or Cargo.lock. The preferred narrow host adapters
use rustix and object; the documented procfs, BTF and Aya limitations retain their
owning component tasks. cap-std/pathrs comparison remains with the first actual
confined traversal consumer, normally LX10.

Independent review and two focused repair rounds closed the demonstrated gaps:

- Subject approval remains bound to the original full source inventory through
  copied sources, lock creation, Cargo normalization and archive checks. Complete
  effective Cargo package/dependency/target metadata is compared. Unsupported
  build-visible manifest controls refuse explicitly rather than being ignored.
- Launched commands retain their process, log, error and cleanup observations
  through collection and later interpretation errors. Unobserved hashes/sizes
  remain null; unresolved cleanup retains its owner and process-group facts.
- A logical compiler cell is one probe/compiler, refusal/compiler or feature
  member/configuration/compiler tuple. Each has one cumulative 600-second budget
  across sequential phases; the full declared expansion is limited to 128 cells.
  Report-stage count is different. Timeout and retirement are separate facts.
- Explicit empty default members are retained. An empty outer feature-union list
  permits a member advertising only minimal/default modes; each supplied union
  must be nonempty and unique. The mandatory SB02 fixture still requires its JSON
  union, two clients and all six compiler/configuration cells.

The final independent Astra review passed specification and code quality, with no
remaining actionable blocker. Its immutable report SHA256 is
`114bc5008ce12263418c0c292b827d4677ce32e3f973de2d53981d8268cabdba`.
It independently rehashed 368 referenced logs and reran three focused tests.
The worker's final report SHA256 is
`a62588989daa613e6de9e49983170fa8fa2b4bed619a9c16e5acd24b00c39062`.

The original job's 18 inputs remain verified at its Git base and candidate. The
user subsequently directed frozen donor copies, so controller AGENTS/executor
inputs legitimately changed. Review used an immutable Git-bound package, not a
claim that the old mutable-origin helper passed. Original bindings were preserved.

## Verification and evidence scope

| Check at code `92f6e33` | Observation | SHA256 |
|---|---|---|
| Complete package-policy Python suite | 34 tests PASS, 131.773 seconds | `9080fdf05997c941d9c03ed9aac210dc4cc3b60b0636ff02673fe61b9a23961f` |
| Actual base feature CLI | 56 PASS rows, six compiler/configuration cells | `db7bc85168c65b6d3113c3a4aaf2ecfb3e8a7bc13d280d916c6a1a681ea8be2f` |
| Approved-script CLI, original lock absent | 56 PASS rows, six cells | `5d2e8a2abb6ecbba8e39bf900f89dc6754e86d422e387ce556d3a4444abf7ad2` |
| Approved-script CLI, original lock present | 56 PASS rows, six cells | `033844bce1ed93f0ab7479cc796547c79d9b3f05a3835d1f27bdb46457ac9499` |
| Selected rustix-fs and aya-btf/PP09 run | 34 PASS rows, six of 22 cells; 80 omitted required IDs; full matrix false | `14738f7a299a4d1f23d6897e0b628dd7e43f682f50daecec121a3fcd6fb4f2d9` |
| Evidence audit | Four CLI reports, two capable authors-only bad controls, ten post-launch fault reports, 368 log references | `4054f82984b10327c953d6d21dab0fa557af29ad0f18f537a49f7b8c450d3788` |

The old full 96-row dependency run and 45-row feature run retain their historical
subjects in the dependency report. Their unchanged probe-source bridge was
verified; they are not reruns of the repaired tool. The current selected run
exercises the changed command path and intended private-API refusal. An expected
refusal does not make a private API available. Fault-injection controls test
evidence preservation, not actual kernel/compiler failures.

Controller integration checks compare every worker-owned file to its reviewed
candidate, validate planning/traceability and inspect whitespace. The integrated
file comparison and structural checks are recorded with acceptance bookkeeping;
unchanged suites are not repeated solely to change the commit label. All 55 reviewed files match; binding SHA256 `73d09afa4361fc55d240539fc0d9290868d37b4724966a578be86036c0d73316`. Planning PASS and structural traceability VALID have no errors; source verification remains NOT_RUN.

## Successor obligations and custody

The [host source selection](../contracts/host-kernel-source-selection.md) freezes
the initial 5.15.223, 6.12.113 and 7.2.11 sources. Expected archive hashes are
attributed selection inputs; acquisition, signature/archive verification,
configuration, images, boot identity and real operations remain TT04 work.
These sources are not a universal BPF floor or substitutes for affected-old,
distro/backport and workaround-removal cells.

Before the first product matrix is accepted, LX01/controller must add product-role
notices, real-root lock preservation and isolated product-member staging. Missing
or stale locks must refuse without mutation; restored valid twins must pass.
An actual member without a nested `[workspace]` must package from the owned output
root without changing its approved manifest. This is an explicit successor
extension of the empty-root/standalone-fixture boundary, not a reopened SB02 check.

All source/grant/vendor roots, worktrees, immutable reports and owned evidence
remain preserved. Policy and probe workers have finished and released the shared
build lease. Administrative claims may be reconciled with this acceptance and
their resource-retirement reports; reconciliation does not delete the records or
qualify a runtime. New work uses completed private donor captures, without polling
live heads. Later component ports preserve their original mechanisms and tests.
