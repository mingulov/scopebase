# Prepared host calls: exact budgets, strict refusals, no hidden allocation

BP03 delivers a descriptive BPF host capability plus a prepared-only
consuming call. Its [descriptive contract](../../superpowers/specs/2026-10-22-scopebase-bp03-host.md),
[prepared-response contract](../../superpowers/specs/2026-10-22-scopebase-tt02-prepared-response.md)
and [verifications](../../superpowers/plans/2026-10-22-scopebase-bp03-verification.md)
retain the original defect populations. The integrated candidate passed
two-lane final review and bounded source/archive qualification. Candidate
implementation is separate from native/operator/profile qualification and
any release or migration acceptance.

A prepared call must admit its exact whole-call budget before running, fail
refusals with the original kind and stage, and never allocate outside the
admitted reservation. `BpfPreparedCall` prepares scalar no-dispatch work,
one moved partial followup and full R<=F responses; metadata finish stays
allocation-free. Backend, Allocate and capacity failures are exact refused
library-stage outcomes: the prepared route preserves constructor error
kinds and stages instead of collapsing them into grammar faults, and the
legacy descriptive route is unchanged. Response handling stays strict
across R/B/F/J/Q with whole-call allocator observation.

Budgets are proved from two independent sides. The test-only allocator
observer counts allocations inside armed whole-call windows without
sharing production counters or steps: refusal windows must stay at zero,
positive windows must match exact attribution, and injected allocations
must fail. The error-context oracle reads the actual owned buffers back
from error responses and compares against a measured carrier basis, never
the recorded budget counter. Profile-constructor collapse,
forgotten-payload and injected-allocation mutants each fail their named
semantic assertion with byte-restored twins passing.

The descriptive half keeps quiet-zero, partial-own and excluded-hit
populations at their exact verdicts with hazard separate from permission.
Three frozen p11scope ranges supply the filter predicate, the four
original population rows and the hazard/capability value split; donor
errno wording is not a shared cause classifier and native probe bodies
stay unported. All mechanisms here are bounded host evidence. Full native
behavior, distro/object/helper/license/cleanup cells, installed
conformance and product migration remain with their existing owners. No
donor duplicate is removed here.
