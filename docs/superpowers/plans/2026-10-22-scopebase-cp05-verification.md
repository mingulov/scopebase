# CP05 Generations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development when explicitly dispatched by the controller, or superpowers:executing-plans for inline execution, to implement this plan task-by-task. Steps use checkbox syntax for tracking. This document authorizes no new agent dispatch, product implementation or build before its input gates are bound.

**Goal:** Deliver the selected immutable full-key generation API and package-runnable original/independent checks proving unknown or evicted provenance cannot retire a successor.

**Architecture:** Production contains only caller-supplied keys and checked equality/advancement. Separate donor-shaped fixtures use that API against independent append-only action/fact truth; two packaged clients own different local reducers and journals.

**Tech Stack:** Rust edition 2021/std, MSRV 1.88.0 and pinned 1.98.1, `x86_64-unknown-linux-gnu`, `default=[]`, additive existing json feature. Python3 runs the delivered controls helper; no new dependency, Proptest install, BPF/native compiler, guest or platform setup.

**Spec:** [Exact CP05 contract](../specs/2026-10-22-scopebase-cp05-generations.md), [capture design](../specs/2026-10-17-scopebase-capture-design.md), [executor contract](../specs/2026-10-18-scopebase-executor-contract.md).

## Global constraints

- **INPUTS_UNBOUND, not PACKET_READY:** product base `UNBOUND_POST_BP02_ACCEPTANCE`. The [combined source admission](../../provenance/admissions/2026-10-22-next-host-scopes.json) is adopted at `40ef090f8876bea1fc9c01df95f2b053d1b7113d`, SHA256 `e29cc889d99b73d3790a48fe555f4f74c60c4f718f7e184bd000f142a01e7bc1`; root still binds the execution gates below.
- The documentation patch starts at `fdf548e7d1be5ed65008c0ee1274230600b8f3ec`; do not use it as the future product execution base. Preserve the older private preparation/evidence and historical admissions/receipts.
- Source is only the completed frozen K/M copies and exact eight grant candidates in the spec. No live-donor refresh, implicit parent Git discovery, lazy fetch or copying ungranted first-seen/validator bodies.
- Private invariant fields, exact specified public signatures, structured errors, redacted diagnostics, no hidden core syscalls/clock/identity inference. Generic callbacks retain their own effects/costs.
- Root owns shared lib.rs/manifests/lock/policy/admission/traceability/TODO; one CP05 implementation writer owns generation/test/example/helper paths in an explicit isolated checkout. Serialize every Cargo/native command through the frozen absolute controller build wrapper/common resource.
- Cardinality, replay work, generic retained bytes, elapsed time and actual retirement are different claims. Pure scripted interleavings do not prove concurrency, kernel ordering, callback reentrancy or cleanup.

## Review focus

- Generic raw Eq/Clone can mutate interior state or panic: direct production probes must prove metadata short-circuit/overflow ordering without contaminating counters through harness comparisons (Task2).
- K's unknown creation boundary and config_revision are separate from a known observation key/capture Epoch: scripted first-seen uncertainty is recorded once at admission and never promoted to proved (Task3).
- M reader unknown-ID acceptance, known duplicates, retired-cap 0 and post-eviction reuse have distinct outcomes: preserve reader and analysis policies separately (Task3).
- Duplicate operation token and shifted tombstone storage must preserve original submit identity: compare every prefix to action/fact IDs, with separate duplicate refusal flags and multi-raw compaction literals (Task3).
- A library dependency's tests do not run in ordinary downstream cargo test: actual archive helper/direct mode, feature/subject metadata and two independent client builds are required (Tasks4–5).

---

## File ownership and interfaces

| Owner | Create / modify | Responsibility |
|---|---|---|
| CP05 writer | `crates/scopebase-capture/src/generation.rs` | Only production ObjectKey/getters/matches/next_generation/require_generation and conditional traits |
| CP05 writer | `crates/scopebase-capture/tests/generation_histories.rs` | Ten direct cases, all 17 mapped original subsets and literal bound/interleaving vectors |
| CP05 writer | `crates/scopebase-capture/tests/support/generation_models.rs` | Separate K and M local bounded models using actual production keys |
| CP05 writer | `crates/scopebase-capture/tests/support/generation_oracle.rs` | Independent append-only action/fact journal and expected retention; no production relation/model helper reuse |
| CP05 writer | `crates/scopebase-capture/tests/support/check_cp05_controls.py`; `tests/ui/generation_no_debug.rs`, `generation_rc_send.rs`, `generation_send_ok.rs` beneath the same crate | Packaged source/archive semantic and precise compiler controls with valid twins |
| CP05 writer | `crates/scopebase-capture/examples/{transform_generations,mapping_generations}.rs` | Distinct actual API clients, no test-support imports |
| CP05 writer; root integrates | `crates/scopebase-capture/{README.md,THIRD-PARTY-NOTICES.md}`; `docs/issues/capture/generations.md` | Runnable package routes, preserved source/defect/subset/oracle/control/migration record |
| Root serialized | `crates/scopebase-capture/{src/lib.rs,Cargo.toml}`; `package-policy.json`; root TODO/handoff; provenance navigation/selected-port receipt | Export, real archive allowlist/client entries, current source admission, reviewed candidate acceptance |

Consumes accepted `Epoch::{new,successor,capture,producer,ordinal}`, `ContractError`, and optionally unchanged `ObservedIdentity<I>`/`IdentityUnknown` in clients. Produces exactly the signatures in the CP05 spec's [production API](../specs/2026-10-22-scopebase-cp05-generations.md#production-api-and-effects); no other production API or generic tracker. Fresh tests/models/oracle/delivery glue are NEW because generic Rust trait/callback and package-control interfaces are absent from product-specific donors. Identified lifetime/domain/history mechanisms are ADAPT and original subsets VECTORS_ONLY, with precise mapping in the spec.

## Task 1: bind execution inputs and selected source admission

**Files:** root-owned immutable combined admission, execution packet and preservation binding; no production edit until complete.

**Interfaces:** consume the selected contract/verification plan and actual accepted predecessor artifacts; produce a concrete twelve-field executor packet and fresh resource/output handoff.

- [ ] **Step1:** Bind actual post-BP02 product SHA, clean explicitly selected execution checkout, accepted CP02 domain/error hashes, relevant CP04 input hashes, crate/version/features, both compiler identities and actual current policy/lock/helper hashes. Preserve unrelated worktrees, pending work and all earlier source/evidence.
- [ ] **Step2:** Consume/verify the actual adopted combined admission path/digest above:132 rows/41 ready/86 pending/five reference-only and 216 ready ranges at that snapshot. Root already merged CP05's two missing rows, LX08's independent pidns row and predecessor grants. Verify the exact eight CP05 selections, OWNER-2026-10-18 and unchanged reference-only inputs against that immutable snapshot. Do not re-adopt the old private131-row overlay or overwrite the current ledger.
- [ ] **Step3:** Read/hash each selected frozen file/range using the explicit independent histories from the spec and `GIT_NO_LAZY_FETCH=1`, `GIT_NO_REPLACE_OBJECTS=1`, `GIT_OPTIONAL_LOCKS=0`. Missing locally promised source is incomplete, not a reason to fetch/rewrite. M identity133–150 validation/rendering remains context, and K first-seen bodies799–848/1314–1346 remain ungranted context; no copying those bodies.
- [ ] **Step4:** Freeze the actual writer, shared-root owner, absolute wrapper/resource identity, fresh per-run target/result roots, selected-source/preservation record and future receipt path `docs/provenance/ports/CP05-20261022-initial.json`. Validate structural intake/current planning documents. Root then records PACKET_READY for this increment; source admission alone cannot do so.

Expected result: actual post-BP02 input hashes/checkout/resource bindings replace every remaining UNBOUND field in the execution handoff, consuming the already-adopted source digest. Any missing field returns NEEDS_DECISION or BLOCKED_ENVIRONMENT with its owner; no independent product implementation starts before BP02 acceptance.

## Task 2: direct immutable-key tests and production implementation

**Files:** generation.rs and generation_histories.rs; root integrates only the module export when behavior exists. No placeholder export.

**Interfaces:** consume Epoch/ContractError; produce ObjectKey API and conditional traits exactly as specified. Metadata refusal precedes arbitrary raw operations.

- [ ] **Step1:** Add the direct named tests below against the absent destination. Record a focused missing-code RED; it is not semantic mutant evidence.

| Test | Exact assertions and positive twin |
|---|---|
| `full_key_match_requires_every_component` | Same complete key matches/PartialEq/require Ok. Independently change capture byte, producer byte, epoch ordinal, raw handle, raw namespace/device and object generation: each relation false and require GenerationMismatch. |
| `late_completion_does_not_match_successor` | Submit raw7/gen0; current raw7/gen1 stays live after old completion refusal. Same-gen0 completion twin retires only gen0; foreign epoch/gen0 refuses. |
| `generation_zero_and_exact_max_are_valid` | Round-trip supplied 0/MAX and raw0;0 advances to1, MAX-1 toMAX, retaining epoch/raw. No generic positive-only rule. |
| `generation_max_refuses` | MAX -> ArithmeticOverflow before raw Clone; source wrapper fields stay in place. Raw clone counter 0 on overflow,1 on MAX-1 success. |
| `unknown_ids_are_nonjoinable` | Unknown event IDs41/42 both survive/known registry 0. Mixed known0/unknown/known1 registers2; duplicate known still refuses. No unknown ObjectKey is minted. |
| `bounded_tombstone_eviction_returns_unknown` | Explicit IDs1/2/3, cap 2 retain2/3, evictions1, lookup1 UnknownContinuity; late old completion cannot retire successor. Cap3 retains known1. |
| `compaction_does_not_rebind_pending_identity` | Outstanding bound generation survives shifting storage indices; its retire/config effect never transfers to another occupant. Current-bound twin succeeds. |
| `payload_traits_and_debug_preserve_boundaries` | No-Debug payload constructs/gets/formats with sentinel absent; Clone-only advances, Eq-only matches, PartialEq-only compares. No extra Default/Ord/Hash bounds. ObjectKey<u64> Send+Sync; Rc send control fails at its intended compiler site. |
| `payload_panics_do_not_change_wrapper_fields` | Probe raw immutable marker plus separate shared counters/panic switches. Epoch/generation mismatch: Eq 0; equal metadata/unequal raw and equal raw: Eq 1. matches/PartialEq/require each obey once, not twice. Catch Eq/Clone panics in harness only; inspect metadata/marker through getters without Eq/Clone and retain visible interior effects. |
| `bounded_histories_match_independent_oracle` | Task3's complete55,987 scripts/every prefix, fixed work denominator and nonzero trigger counters. The fixture cannot supply the expected relation. |

- [ ] **Step2:** Run `cargo test -p scopebase-capture --test generation_histories --no-default-features` through the bound wrapper/pinned MSRV as shown below. Record missing-code failure separately; do not count import/build refusal as semantic RED.
- [ ] **Step3:** Implement move-only construction/getters and conditional traits, exact complete relation, generation checked addition and existing error categories in generation.rs. Match epoch→generation→raw once. Check overflow before raw clone. No generic inferred identity, allocation registry, serde/layout promise or Epoch expansion.
- [ ] **Step4:** Re-run the focused target and direct tests. Build/setup-valid production controls mutate only owned generation.rs copies: `erase-epoch`, `erase-raw`, `erase-generation`, `wrap-generation`, `require-always-ok`, `clone-before-overflow`, `raw-eq-before-metadata`, `repeat-raw-eq`, `debug-fixed-secret`. Each reaches its named semantic assertion and fails; restored valid bytes pass the same case. Debug secret injection must compile without K:Debug; unwanted-Debug-bound is a separate compiler control.

Expected result: real production functions pass all direct equality/error/trait/effect tests; every declared production mutant fails its intended semantic assertion after valid setup. No model-only result qualifies these traits/callback boundaries.

## Task 3: preserve17 original subsets, bounded models and independent journal

**Files:** generation_histories.rs, support/generation_models.rs, support/generation_oracle.rs and issue record.

**Interfaces:** the models consume production ObjectKey operations plus external scripted facts; the oracle consumes only literal action/fact intent and its own state. The exact17 original/destination names, source ranges, expected subsets and controls are in the spec's [selected original subsets](../specs/2026-10-22-scopebase-cp05-generations.md#selected-original-subsets). Require each row independently; enumeration cannot replace an original.

- [ ] **Step1:** Adapt K's admitted submit-bound ID matching/stable retention and M's admitted identity-present gate/retired ring into separate local test models. Preserve K's pending/live/retired count bounds, first binding on duplicate token and forced ambiguity. Model K first-seen creation evidence as an externally supplied scripted input: set unknown-creation count once at admission; successful config changes only config_revision/config count. Do not copy ungranted admission/config bodies or import capture Epoch as configuration era.
- [ ] **Step2:** Add all 17 prefixed original cases with their exact assertion subsets/positive twins from the spec. Keep requested name/type/mask/driver literals as supplied provenance; no decoder/truncation/wire support is claimed. Preserve M50/60 durations and cap 4/six-retirement/two-eviction original, plus the known/unknown/mixed/known-duplicate reader cases. Defer its token grammar/rendering bodies to CP11 rather than claim a parser was ported.
- [ ] **Step3:** Implement the independent action/fact oracle. Model-local allocation ordinals remain monotonic; oracle allocation identity is the allocation action index. The oracle independently counts admitted allocations to project expected local ordinals; it does not derive identity mappings from model returns. Keep fact IDs `(action_index,fact_kind)` with one occurrence/kind/row; InputObservation is always present. The exact alphabet, transition/outcome table,8 fact kinds and per-action bounds are in the spec's [test-only protocols](../specs/2026-10-22-scopebase-cp05-generations.md#test-only-protocols-and-independent-truth). Journal≤6 action rows/facts ≤18; do not describe facts as6 when an allocation also forced-retired an old occupant.
- [ ] **Step4:** Enumerate lengths 0..6 in stable alphabet order at pending/live/retired caps 2. Assert exactly55,987 scripts/324,726 replayed actions, every prefix's optional outcome/flags/current/retired/pending/continuity projection, and nonzero reused-old, unbound-at-submit, overlap and eviction populations. Duplicate token sets its distinct refusal flag and retains first binding; CapacityRefused is reserved for count admission. Unknown/missing pending completes cannot acquire a current identity; bound stale stays Mismatch.
- [ ] **Step5:** Add required literal vectors outside that enumeration: raw8 and a third distinct live raw for cap 2 overflow, foreign epoch, K cap 0/cap 1/N+1/three pending tokens, M sufficient-active/retired-cap 0, two pending destroys overlapping one target, and pending identity while older tombstone compaction shifts a live record. The four-retirement K/cap 2 and six-retirement M/cap 4 original populations remain separate. State count/byte/work/memory limits separately.
- [ ] **Step6:** Run all 17 named originals/direct target and enumeration. Observe setup-valid adapter semantic RED/restored GREEN for raw-only return matching, return-time binding, unbound promotion, stored-index binding, double retirement, capacity bypass, live eviction, wrong FIFO/old-ID reuse, erased uncertainty, unknown-default insertion, eager allocation assignment, provenance reassignment, first-seen-as-proved/per-config uncertainty and token-only namespace matching. Each control names its original/direct case and assertion; no generic nonzero exit or setup crash counts.
- [ ] **Step7:** Write `docs/issues/capture/generations.md`: trigger, selected frozen pin/range, defect/invariant, actual destination symbol/hash, exact original subset, independent oracle, bad control/twin, support boundary and later CP11/MG migration/duplicate-retirement criterion. Preserve source/license notices and distinguish scripted partial evidence from a copied runtime mechanism.

Expected result: both local donor policies retain their selected regressions, while the independent oracle establishes identity/uncertainty facts. No universal production lifecycle machine, real kernel ordering, retirement fence or live capacity claim is introduced.

## Task 4: deliver controls and two actual API clients

**Files:** both examples, packaged Python helper/UI controls, README/notices, root-owned archive/policy/client declarations.

**Interfaces:** helper accepts exactly:

```text
python3 tests/support/check_cp05_controls.py run
  --source-root ABS_CAPTURE_CRATE --cargo ABS_CARGO --rustc ABS_RUSTC
  --feature-set no-default|default|json --output-dir ABS_NEW_OUTPUT
  [--build-wrapper ABS_CONTROLLER_WRAPPER]
```

- [ ] **Step1:** Implement transform_generations with its own submit/reuse/retire/config journal and literal outcomes; mapping_generations with a different known/unknown/structured-domain/retired-history reducer/journal. Both import actual production API, never either test model/oracle. Build each as a distinct external package with its own manifest/lock/metadata against exact source version/features, then the actual extracted archive. These are scoped reference consumers, not CP11's full application adapters.
- [ ] **Step2:** Implement the helper over fresh owned subject copies. Direct pinned Cargo/rustc is standalone default; coordinated mode uses only an explicit optional wrapper. Reject unsafe/existing output roots before mutation. Bind input/changed/restored source hashes, tool identities/features, exact test selector, setup/trigger evidence, expected semantic assertion and positive twin. Never derive expectations from mutant output or discover a hidden repository wrapper.
- [ ] **Step3:** Package the Task2 production and Task3 adapter controls. Add no-Debug positive/mutant-bound and Rc-send negative/u64-Send positive compiler fixtures. Freeze expected fixture primary file/line and E0277/required trait category from the fixed fixture before invoking the mutant; do not accept a different diagnostic site or setup import failure. An unintended Debug bound is compiler refusal, not semantic disclosure RED.
- [ ] **Step4:** Root adds every delivered source/test/support/UI/example file to Cargo include and package-policy package_files and the two client records. README gives archive-root cargo test/examples/helper commands, complete raw-domain/unknown obligations, trait callback costs and later authority gates. Runtime checks must not require docs/issues or private donor archives.
- [ ] **Step5:** Run source plus actual archive tests/doctests/examples/helper controls and both independent external clients for 1.88.0/1.98.1 × no-default/default/json. Keep twelve source/archive configurations separately named. Feature selection is no-default:defaults=false/features[]; default:defaults=true/features[]; json:defaults=false/features[json]. Verify actual resolved package/version/feature closure in metadata; generate fresh client lockfiles offline before locked commands.
- [ ] **Step6:** Run one actual archive helper in direct mode under one outer common wrapper lease, omitting its optional inner wrapper. Other coordinated helper campaigns use explicit per-build wrapper acquisition without an outer held lease. This proves portable archive use without a nested lock deadlock and adds no invented matrix cell.

Expected result: all delivered checks run against actual source/archive subject bytes and two materially different clients. Missing/setup-failed required rows remain incomplete; an expected refusal can pass while capability/coverage stays unknown.

## Task 5: integrate, independently review and accept only the scoped increment

**Files:** root integration/acceptance records, actual selected-port receipt/preservation map, shared exports/policy/TODO/handoff. New implementation commits remain separate from this documentation change.

**Interfaces:** consume the actual immutable source admission and reviewed implementation SHA; produce exact receipt/destination/test bindings and a six-cell affected capture report.

- [ ] **Step1:** Root validates the exact staged package list/notices, all selected source-to-destination subsets,17 original mappings and actual immutable admission digest. Produce/check `docs/provenance/ports/CP05-20261022-initial.json` against current destination hashes/symbols and reviewed preservation map. A source grant can cover context that is not copied; never call deferred M checked/render or ungranted K first-seen bodies ported. Retain historical receipts, replacing changed destination lineages only through bounded supersedes records.
- [ ] **Step2:** Obtain an independent Sol max review of actual production traits/errors/callback order, domain/unknown/creation distinctions, both donor-shaped local policies, action/fact/work bounds, all original subsets, oracle independence/control causality, actual archive delivery and two-client meaning. Resolve findings with affected checks on changed bytes; review completion alone is not verification.
- [ ] **Step3:** Root prepares a fresh bounded affected driver from the accepted CP04 driver mechanism with new SHA/helper/input hashes, using `tools/build/check_features.py::run_member` for only scopebase-capture under the full registered policy. It must report executed_members=[scopebase-capture],6 selected cells,full_matrix_complete=false and explicit unchanged-member omissions; verify archive/source equality and actual clients. The future driver is a controller deliverable, not a claimed existing runnable file.
- [ ] **Step4:** Run current planning/intake/selected-port checks, package-policy tests if policy tooling/fixtures changed, and `git diff --check`; inspect new untracked files too. No unchanged CP02–CP04 mutation campaign or Linux/BPF/testkit package matrix is repeated absent changed input/failure/named gap.
- [ ] **Step5:** Root binds actual reviewed candidate SHA, source admission/receipt/preservation digests, selected destination hashes, exact source/archive control reports and six affected capture archive cells. Update TODO/handoff only for this increment and commit the reviewed files with `feat(capture): enforce scoped generation matching`. CP08/CP10/CP11/CP13/TT07/MG and full runtime/conformance gates remain open. No publication or donor edit follows.

## Commands after input freeze

Every command below is **NOT_RUN** by this plan. Root fills the actual execution checkout/output paths, compiler/helper bindings and driver before use. From the admitted checkout, the focused MSRV command is:

```sh
SCOPEBASE_CP05_RUSTC=/home/user/.rustup/toolchains/1.88.0-x86_64-unknown-linux-gnu/bin/rustc
SCOPEBASE_CP05_CARGO=/home/user/.rustup/toolchains/1.88.0-x86_64-unknown-linux-gnu/bin/cargo
/home/user/src/m/bpfscope/.scopebase/controller/build-routing-20261018/scopebase-build \
  -- env RUSTC="$SCOPEBASE_CP05_RUSTC" CARGO_TARGET_DIR="$SCOPEBASE_CP05_FRESH_TARGET" \
  "$SCOPEBASE_CP05_CARGO" test --offline --locked \
  -p scopebase-capture --no-default-features --test generation_histories
```

`SCOPEBASE_CP05_FRESH_TARGET` is an absolute fresh root-selected target path in the dispatch. Repeat declared feature selections/both compilers in isolated bound outputs. A lock refusal before Cargo starts is NOT_RUN/environment-blocked. Initial missing-code RED, semantic control RED and restored GREEN are different records. Archive tests use the extracted subject's manifest, not the workspace target.

From an actual extracted archive root, coordinated helper mode is:

```sh
python3 tests/support/check_cp05_controls.py run --source-root "$PWD" \
  --cargo /home/user/.rustup/toolchains/1.88.0-x86_64-unknown-linux-gnu/bin/cargo \
  --rustc /home/user/.rustup/toolchains/1.88.0-x86_64-unknown-linux-gnu/bin/rustc \
  --feature-set no-default --output-dir "$SCOPEBASE_CP05_FRESH_OUTPUT" \
  --build-wrapper /home/user/src/m/bpfscope/.scopebase/controller/build-routing-20261018/scopebase-build
```

`SCOPEBASE_CP05_FRESH_OUTPUT` is an absolute nonexisting root-selected path in the dispatch. For the required direct-mode route, omit --build-wrapper and run the whole Python invocation under one outer wrapper; never hold that lease while requesting an inner one.

Root's affected driver invocation, after that file exists and is frozen, is:

```sh
/home/user/src/m/bpfscope/.scopebase/controller/build-routing-20261018/scopebase-build \
  -- python3 /home/user/src/m/bpfscope/.scopebase/controller/cp05-integration-20261022/run-affected.py
```

Post-integration administrative/receipt checks are:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/check_planning_docs.py
PYTHONDONTWRITEBYTECODE=1 python3 tools/planning/check_traceability.py \
  docs/superpowers/plans/2026-10-17-scopebase-traceability.json \
  --port-receipt docs/provenance/ports/CP05-20261022-initial.json
git diff --check
```

The receipt must really exist before its command is meaningful. Run accepted planning-tool tests only if those tools change. Source/admission/contract changes invalidate their affected current-copy checks; unchanged packages retain prior evidence.

## Self-review and remaining gates

- [x] Exact public signatures/errors/traits/call order are bound by the linked spec; production trait tests are distinct from fixture equality.
- [x] All17 original subsets/source ranges/controls/twins are mapped; first-seen and text-validator limitations remain explicit.
- [x] Six-action generation has fixed55,987-script/324,726-action denominators, exact optional outcomes/refusal flags/fact kinds and independent≤6-row/≤18-fact bounds. Longer original vectors remain separate.
- [x] Source/archive delivery, two distinct external consumers and the standalone direct helper route have exact owners and inputs; full installed/live profiles remain later.
- [x] Every review-focus risk maps to an owning task. No new dependency, allocator/tracker API, live fixture, source grant, product test, build or implementation commit was created by this plan.
- [ ] Root freezes actual post-BP02 base, current prerequisites and checkout/resource/output bindings while consuming the adopted combined admission digest, then records PACKET_READY. These execution input gates remain open.
