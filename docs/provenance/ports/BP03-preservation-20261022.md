# BP03 preservation map

Candidate host implementation for the ratified [descriptive BP03 contract](../../superpowers/specs/2026-10-22-scopebase-bp03-host.md) and the [TT02-RSP01 prepared-response contract](../../superpowers/specs/2026-10-22-scopebase-tt02-prepared-response.md). This is a source/defect map, not acceptance or a test-result ledger. The [selected-port receipt](BP03-20261022-host.json) binds final destination hashes and the immutable [admission](../admissions/2026-10-22-next-host-scopes.json).

Only frozen p11scope `2c2713e66292b0d2688508a25f79e813ae823d81` is selected, three inclusive line slices in total. All slice hashes were checked against the gitless private capture; no live donor or implicit Git lookup was used. Historical GPL-3.0-or-later observations and OWNER authorization are preserved separately; destination host/test/data terms are Apache-2.0. No third-party, target/BPF/shared-source or whole-file grant is inferred. Earlier BP02/CP05/LX08 grants/receipts and production bytes remain unchanged.

| Frozen source scope | Exact slice SHA256 | Origin and destination symbols | Preserved difference or limit |
|---|---|---|---|
| `P:crates/bpf-multi/src/lib.rs:591–605` | `f646768079fa08d871aae306be7d70e9946dfa9f9a58acc7a1638b03ac247c51` | ADAPT; `capability.rs::{ProbePopulation,assess_filter_probe}` from `PidFilterHits::proves_pid_scope` | Preserve the pure two-counter value and exact fixed-population predicate: all original own populations require both own threads and no excluded hit. Generalized expected count/excluded execution stay explicit. Not the native probe; no live canary/own completion/excluded execution qualification. |
| `P:crates/bpf-multi/src/lib.rs:1179–1192` | `4d61beca5aa1dcc622450dd0395435988e8b32d40ea679ec749c8d5552974154` | ADAPT; `tests/capability.rs::filter_original_populations` plus `filter-inputs.json`/`filter-expected.json` from `only_both_own_threads_and_no_other_process_prove_pid_scope` | Retain all four original rows (2,0),(1,0),(2,1),(0,0) with supplied E2/X1 in original row order. Original native probe and related signals/children remain reference-only. |
| `P:src/uretprobe_hazard.rs:34–50` | `2956fe9e2b2b09fd69a0e431b81c87df9921233a8aa9a1046062367ed0392bde` | ADAPT; `capability.rs::{CapabilityState,HazardState}` and `tests/capability.rs::hazard_and_capability_remain_separate` from `KernelVerdict` | Affected/Clean/Unknown and NotPermitted distinctions survive as separate hazard/capability descriptions. Donor errno wording is not a shared cause classifier; native load/attach behavior stays unqualified. |

The prepared-response machinery (`BpfPreparedCall`, strict R/B/F/J/Q handling, whole-call allocator observation, error-context oracle) is separately specified NEW code built on accepted TT01/TT02 machinery, not a donor port: no donor slice, helper implementation or reducer body is copied for it. Native load/attach/seccomp probe bodies, UAPI/backend fragments and O/K/M comparisons remain ungranted for copying by BP03.

## Defect, independent truth and sensitivity

| Defect/invariant | Original correspondence and delivered assertions | Independent truth and semantic control |
|---|---|---|
| Quiet-zero, partial-own and excluded-hit populations must keep their exact verdicts; hazard stays separate from permission. | The three P ranges map to `filter_original_populations`, the filter active negatives and `hazard_and_capability_remain_separate`. | Frozen literal states plus a relation-partition enumerator that never calls production branch code; literal Denied+Clean, Unknown+Affected, Incompatible+Unknown getter expectations. Missing-own-accepted, errno-only-denied and stages-collapsed bad controls fail named assertions; restored twins pass. |
| Prepared calls admit exact whole-call budgets with strict refusals and no hidden allocation. | NEW prepared contract: scalar no-dispatch, one-moved-partial followup, R<=F, allocation-free metadata finish, exact Backend/Allocate/capacity refusals with original kind+stage. | Independent test-only allocator observer with zero/refusal/positive windows plus error-context byte oracle reading actual owned buffers against a measured carrier basis. Profile-constructor collapse, forgotten-payload and injected-allocation mutants fail named assertions; restored twins pass. |

## Later owners and duplicate retirement

All model/script evidence is bounded host qualification. Full BP03 native/operator/profile behavior, finite distro/object/helper/license/cleanup cells, installed conformance and product migration remain open under their existing owners. No source duplicate, live/ABI/profile gate or later task is closed here.
