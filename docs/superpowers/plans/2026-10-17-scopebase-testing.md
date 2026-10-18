# ScopeBase Testing and User Conformance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver trustworthy shared regressions, real environment qualification and checks that installed library users can run.

**Architecture:** A dev-only testkit accepts the consumer's actual production adapter while independent fixtures/oracles supply truth. Versioned profiles select requirements before environment discovery; an installed operator route and external clients exercise the distributed package. Live/object/native lanes remain separately owned and scoped.

**Tech Stack:** Rust 2021, proposed MSRV 1.88.0, serde-based bounded schemas where needed, existing property/model/fuzz tools, owned Linux workers and disposable guest provisioners, selected upstream BPF backend, native sanitizer tools for selected profiles.

**Spec:** [Testing specification](../specs/2026-10-17-scopebase-testing-design.md), with [project constraints](../specs/2026-10-17-scopebase-design.md).

## Global Constraints

- Follow the [decision register](../specs/2026-10-18-scopebase-decisions.md) and [executor contract](../specs/2026-10-18-scopebase-executor-contract.md). The [task-origin routes and concrete repair packets](2026-10-18-scopebase-plan-repair.md#task-origins-and-decision-routes) supplement this task; broad source groups are not dispatch-ready source selections.
- PORT/ADAPT preserves the identified donor mechanism, affected call sites, original regression, independent oracle and bad control together. NEW requires the recorded missing-mechanism reason and frozen design. Unresolved architecture, source, license, support or expected-result choices return NEEDS_DECISION; no fresh approximation or weaker gate.
- Apply provisional Apache-2.0 userspace / GPL-2.0-only BPF / GPL-3.0-or-later application terms and the shared-source/third-party rules in D03–D04. Keep source SPDX, author authorization, actual target input option and kernel runtime declaration distinct.

- Initial Rust packages use version `0.1.0`; initial host target is `x86_64-unknown-linux-gnu`, Rust edition 2021, proposed MSRV `1.88.0`.
- Production packages never depend on testkit; default host builds do not invoke BPF/native toolchains.
- All commands and test files below are future implementation steps, not commands or passing results available in this documentation-only checkout.
- Exact bytes/features/backend/fixtures/profile bind qualification. Required missing cases remain incomplete; unrelated profiles do not gate independent packages.
- Product migrations remain MG01–MG05; two useful independent reference clients qualify package contracts without asserting unchanged application behavior.
- One owner per shared file/interface; isolate output roots and serialize shared privileged environments and heavy builds.

## Review Focus

- A second resolved library version accidentally becomes the subject: TT02/TT07 must reject it through an intentionally mismatched consumer.
- A required collision/copy-up/negative workload never occurs: TT03–TT05 must keep the missing trigger incomplete despite matching outputs.
- A fixture/oracle changes without production changes: TT08 must invalidate every dependent verdict.
- Worker death or a cleanup error follows successful observation: TT02/TT06/TT07 preserve success data and unresolved custody separately.
- A retry hides an earlier semantic failure: TT02/TT08 retain the failed attempt and block qualification until explicitly resolved.

## Ownership and structure

TT owns `crates/scopebase-testkit/`, `crates/scopebase-conformance/`, `profiles/`, `tools/qualification/`, `fixtures/linux/`, `fixtures/vectors/` index and test CI orchestration. Domain vectors/checkers are authored by LX/BP/TC/CP/NX and registered here; TT must not rewrite their production algorithm as an oracle. TC owns `tools/bpf-compat/`; BP owns semantic BPF producers; NX owns native clients and ABI tests. Shared manifests get one integration writer.

TT tasks establish reusable tooling and its own named sensitivity tests. Domain tasks then supply their concrete cases and execute that tooling for their profiles. In particular, implementing TT10's checker does not depend on already qualifying LX12/BP11/CP13/SDK09/NX10; those tasks depend on the checker and close their own actual-result gates. Registering a later profile does not reopen completed unrelated tooling, but changes to shared semantics rerun affected tests. This distinction prevents a tooling-versus-consumer dependency cycle.

### TT01: Versioned case/profile and traceability registry

**Depends on:** SB01–SB02; selected domain contracts can supply cases incrementally. **Requirements:** TT-R01, TT-R04, TT-R14; F04/F05/T01 and all H/UC/G inventories.

**Files:** Create `crates/scopebase-testkit/src/{lib,ids,catalog,profile}.rs`, `crates/scopebase-testkit/tests/catalog.rs`, `profiles/cases-v1.json`, `profiles/profile-schema-v1.json`, `docs/testing/case-authoring.md`. Convert selected entries from the research catalog without changing its historical meaning.

**Interfaces:** Produce `CaseId::parse`, `ProfileId::parse`, `CaseCatalog::load(bytes, CatalogLimits) -> Result<CaseCatalog,CatalogError>`, `ProfilePlan::select(catalog, profile_id) -> Result<ProfilePlan,PlanError>`. Their immutable result contains required subcases/tiers/cells before any environment query. Preserve `UNIMPLEMENTED` entries separately from runnable cases.

**Required frozen input/control:** Register new H33 as a planned source/build/kernel-license family, without changing H01–H32 meanings. Select its applicable T0/T2/T4/T5 subcases before environment discovery; source closure and intended runtime refusal are separate.

**TC-R10/H33 facet:** H33 registration and applicable subcase/profile selection. Follow D03–D04; other facets remain with their named owners.

- [ ] Write `catalog::exact_ids_and_required_selection` with these assertions and duplicate/unknown-reference controls:
  `assert!(CaseId::parse("H04.path_swap\n").is_err());` and `assert!(CaseId::parse("H04.path_swap").is_ok());`. Removing a selected required case must fail plan validation, not shrink its denominator.
- [ ] Run `cargo test -p scopebase-testkit --test catalog`; first confirm the intended contract fails, then implement bounded parsing, reference validation and immutable profile selection, including transitive required-component profiles and versioned capability extensions. Reject unknown IDs, cycles, conflicting versions and any attempt to remove a required component after discovery.
- [ ] Populate named subcases for the first selected domain, mapping every future H/UC/G obligation to an owner or explicit later profile. No runnable flag without executable fixture/oracle/control.
- [ ] Rerun the test and `python3 tools/qualification/check_catalog.py profiles/cases-v1.json`; require zero dangling/duplicate IDs and exact required-case preservation. Implement that validator as part of this task with invalid-fixture tests.
- [ ] Review the selected support claim and commit this complete registry slice.

**Done:** Catalog selection is independently testable and cannot turn availability into requirement deletion. Domain-case expansion continues in owning tasks; the project-level inventory remains complete.

### TT02: Subject binding, independent oracles and verdict engine

**Depends on:** TT01. **Requirements:** TT-R02–TT-R05, TT-R08, TT-R12; T03/U07/G18/G20/G22.

**Files:** Create `crates/scopebase-testkit/src/{adapter,artifact,observation,oracle,result,runner}.rs`, `tests/{binding,verdict,harness_controls}.rs`, `profiles/result-schema-v1.json` and `fixtures/vectors/harness/`.

**Interfaces:** Produce the specification's exact `ConformanceAdapter`, `CaseOracle::evaluate`, `run_profile`, `SubjectBinding`, `RunReport` and typed errors. Implement `RunReport::qualification() -> Qualification` from frozen requirements, preserving underlying fields. Initial parser caps: 8 MiB input/observation, 4,096 case records, 64 KiB diagnostic.

**Required frozen input/control:** Freeze the build/consumer identity recipe and bounded encoding before adapters. Add H33 controls where EPERM/EACCES has distinct permission/verifier/license causes; a generic error or missing positive cannot pass the expected GPL-only rejection.

**TC-R10/H33 facet:** H33 binding/cause/verdict controls without manufacturing legal or runtime authority. Follow D03–D04; other facets remain with their named owners.

- [ ] Write `verdict::refusal_is_not_support`, `binding::wrong_subject_rejected`, `harness_controls::missing_trigger`, `harness_controls::cleanup_survives_zero_exit` and `harness_controls::duplicate_terminal`. Require `assertion=pass, capability=denied` to remain distinct from positive support; wrong artifact yields invalid, missing required trigger yields incomplete, semantic failure stays failed.
- [ ] Run `cargo test -p scopebase-testkit --test verdict --test binding --test harness_controls`; demonstrate failures at their named validation branches using valid restored twins.
- [ ] Implement bounded decoding, binding comparison, expected-evidence separation, case aggregation and precedence. Adapters cannot submit their own qualification/expected output. Malformed backend output gives a typed error without unsafe memory access.
- [ ] Add every planted-invalid runner case from the testing spec, including silent filtering, inactive excluded target, oracle self-copy, stale receipt and false terminal summary. Oracle self-copy is rejected by contract review plus an independent wrong-value control, not claimed magically detectable from any coherent input.
- [ ] Rerun tests, then mutate verdict acceptance to ignore one required field and verify its corresponding assertion fails. Restore valid code, review and commit.

**Done:** No false-green path remains in the named result/admission branches. This qualifies the verdict logic, not any production component.

### TT03: Owned Linux fixture worker and independent raw truth

**Depends on:** TT01–TT02, LX01 ownership interfaces. **Requirements:** TT-R03, TT-R06, TT-R08, TT-R12; UC01/UC08–UC11/UC13.

**Files:** Create `fixtures/linux/worker/{Cargo.toml,src/main.rs,src/protocol.rs}`, `crates/scopebase-testkit/src/fixture.rs`, `crates/scopebase-testkit/tests/fixture_protocol.rs`, `tools/qualification/linux_oracle.py`, `tools/qualification/tests/test_linux_oracle.py`.

**Interfaces:** `FixtureSession::create(root: &Path, limits: FixtureLimits) -> Result<FixtureSession,FixtureError>`; `FixtureAccess` supplies owned capabilities and phase endpoints. Worker protocol operations: create A/B, acquire FD, map exact range, barrier, rename/unlink/link, mutate, report raw evidence, close. Every request/response carries run and operation IDs and a bounded length.

**Required frozen input/control:** Freeze worker message encoding/framing, operation/run IDs, FD transfer, barriers, readiness and partial-effect custody with LX09 before parallel helper/client implementations. The operation list alone is not a complete protocol.

- [ ] Write `fixture_protocol::false_ready_and_replayed_ledger`, `replacement_keeps_original_fd`, `restricted_credential_is_real` and `worker_death_preserves_custody`. Expected A/B bytes are independently authored; the observer never supplies expected identities. An unrelated ready message fails run/operation binding.
- [ ] Run `cargo test -p scopebase-testkit --features linux-fixtures --test fixture_protocol`; first observe the named missing behavior, then implement owned creation, IPC barriers, raw fstat/fdinfo/maps/mount evidence and bounded cleanup.
- [ ] Implement the small oracle parser independently of the production resolver; test malformed/duplicate/truncated raw records and actual denied stages with `python3 -m unittest discover -s tools/qualification/tests -p test_linux_oracle.py`.
- [ ] Run valid and wrong-domain/reopened-path controls through real files. Verify the trigger happened before checking the library result and inspect peak/remaining owned resources.
- [ ] Review that fixture and production share no truth-producing resolver; commit worker, oracle and tests together.

**Done:** Real host fixtures establish the intended operations independently, survive controlled failure and cannot target foreign resources.

### TT04: Real filesystem cells and mapping-policy audit

**Depends on:** TT03, LX mapping interfaces; implementation can proceed alongside LX03–LX07 with frozen protocols. **Requirements:** TT-R04, TT-R06, TT-R12; L04/U01–U06/UC02–UC07.

**Files:** Create `profiles/environments/{host,filesystem}-v1.json`, `tools/qualification/provision_fs.py`, `tools/qualification/tests/test_provision_fs.py`, `fixtures/linux/mmap-audit/`, `docs/testing/filesystem-fixtures.md`, `crates/scopebase-testkit/tests/filesystem_cells.rs`.

**Interfaces:** Provisioner `plan|create|inspect|cleanup --manifest PATH --run-root PATH` only operates on named owned disposable resources. `FixtureManifest::admit(raw: &[u8], context: &ObservedEnvironment) -> Result<AdmittedFixture,FixtureError>` checks actual backing/mount/namespace identities; text manifest alone grants no authority.

**Required frozen input/control:** Freeze deterministic collision/copy-up/foreign-view/denial and transient-mmap audit recipes. Prove the event actually occurred and a deliberate violating control is detected before using matching output as truth.

- [ ] Write `filesystem_cells::split_and_collision_are_required`, `copy_up_trigger_must_happen`, `wrong_mount_view_rejected`, and `transient_target_mmap_detected`. Aligned Btrfs data must not pass the split case; an mmap+munmap between snapshots must fail no-new-mapping enforcement.
- [ ] Run deterministic provisioner/admission negatives first with `python3 -m unittest discover -s tools/qualification/tests -p test_provision_fs.py`; implement ownership checks, bounded manifests and refusal/cleanup paths.
- [ ] Build recipes FS01–FS10 from the specification. Pin exact image/kernel/config/tool versions; record xino/metacopy/layer layout and the observed split/collision/copy-up conditions. FS07 remains an explicit separately unsupported profile until qualified, never a silent omission from an advertised claim.
- [ ] Run `cargo test -p scopebase-testkit --features linux-fixtures --test filesystem_cells` in admitted cells, then run both production mapping policies through the operator route once TT07 exists. Validate each control at its semantic assertion layer.
- [ ] Inspect cleanup, preserve required missing cells as incomplete, review effect/privilege recipes and commit.

**Done:** Every advertised filesystem cell has independent actual trigger evidence and a runnable installed route. Partial provisioning is implementation progress, not ready mapping support.

### TT05: Isolated object and live-kernel orchestration

**Depends on:** TT01–TT03, BP02 map fixture and TC03 object admission. Further selected producers add their own execution gates without blocking creation of the orchestrator. **Requirements:** TT-R07, TT-R12; H01–H22/H29–H32 applicable branches.

**Files:** Create `profiles/environments/kernel-v1.json`, `tools/qualification/{admit_object,run_guest,inspect_cleanup}.py`, their tests, `docs/testing/kernel-cells.md`; consume TC objects/manifests and BP semantic workloads without rewriting them.

**Interfaces:** `admit_object(manifest_path, object_path, profile_path) -> Admission`; `run_guest(admission, environment_manifest, owned_run_root) -> RunManifest`. Admission records final object digest and cannot rebuild it implicitly inside the guest.

**Required frozen input/control:** Run H33 on exact preselected owned kernel/config cells: valid GPL helper activity, otherwise-valid non-GPL license refusal and helper-free baseline where permitted. Containers sharing the host kernel do not qualify another kernel. Missing privilege/helper/cause/positive remains incomplete.

**TC-R10/H33 facet:** owned real-kernel H33 fixtures and required positive/refusal cells. Follow D03–D04; other facets remain with their named owners.

- [ ] Write `test_loaded_bytes_match_admitted_object`, `test_active_excluded_target_is_required`, `test_no_reproducer_is_incomplete`, and `test_foreign_pin_is_not_cleanup_target` with deliberately modified objects, zero workload and foreign sentinels.
- [ ] Run `python3 -m unittest discover -s tools/qualification/tests -p 'test_kernel_*.py'`; demonstrate controlled rejection before implementing execution orchestration.
- [ ] Implement exact object transfer/hash admission, owned guest/resource leases, operation ledgers and independent cleanup inspection. Use explicit privilege/config prerequisites; do not alter host policy automatically.
- [ ] Execute selected semantic cases on their actual oldest/current/distro/reproducer cells. H09 requires affected-cell reproduction plus separate repaired-kernel control; H29 checks returned old and stored new values. A compile/load success cannot close a semantic gate.
- [ ] Run restored valid controls, record missing environments without green substitution, review and commit.

**Done:** Live results name exact candidate bytes, actual trigger/populations and resource disposition. Object/host/model results remain separately labeled.

### TT06: Fault schedules, property/model/fuzz and sanitizer campaigns

**Depends on:** TT02; the initial runnable target is TT01's bounded catalog parser. Domain tasks supply subsequent state models/targets and execute their required campaigns before their own readiness gates. **Requirements:** TT-R08–TT-R09, TT-R12; T02–T04 and relevant G01–G23.

**Files:** Create `tests/models/`, `fuzz/`, `profiles/campaigns-v1.json`, `tools/qualification/run_campaign.py`, `docs/testing/model-and-fuzz-limits.md`; domain authors own individual model/target semantics.

**Interfaces:** Campaign manifest names target, seed/corpus, version, limits, domain contract and artifact; `run_campaign(manifest, output_root) -> CampaignResult`. Results distinguish exhausted finite search, time-bounded exploration, crash and unmet prerequisites.

- [ ] Write ownership/cancellation/publication schedules that fail on early owner release, double charge/refund, shared-cursor reads, poisoned retry and stale generation. Add 512-case focused property runs with fixed regression seeds; each target's expected invariant is independent.
- [ ] Implement minimal harness hooks at public transition barriers without adding a fake production backend to release paths. Run each focused domain test command from its plan and demonstrate the intended mutant fails after valid setup.
- [ ] Add parser/decoder fuzz targets, minimize failures and run the initial 60-minute-per-target qualification campaigns; scheduled changed-target campaigns use 10 minutes. Preserve seeds and result scope, not a universal fuzz-pass claim.
- [ ] Execute finite Rust models to their configured bounds, Miri for supported pure unsafe boundaries, and NX sanitizer cases. Record unmodeled syscall/mmap/FFI/BPF edges. Missing required tool support remains an explicit gap.
- [ ] Review coverage of each named error/transfer branch, restore valid controls and commit the corresponding focused model/target slice.

**Done:** Each technique addresses a named uncertainty; required branches have discriminating tests. There is no arbitrary line-coverage percentage substituting for semantic controls.

### TT07: Installed operator command and downstream package delivery

**Depends on:** TT01–TT03 and LX02/LX03/LX04 for the first held-file adapter. Later profile registration consumes TT04/TT05 as applicable; neither LX11 nor a final package-ready task is a prerequisite of the operator implementation. **Requirements:** TT-R02, TT-R05, TT-R10, TT-R14; U03/U04/U07/U08/UC14/T06/T07.

**Files:** Create `crates/scopebase-conformance/{Cargo.toml,src/main.rs,src/commands.rs}`, `tests/downstream/conformance-client/`, `tools/qualification/test_installed.py`, `docs/{conformance,install,troubleshooting}.md`, `packaging/fixture-manifest.json`.

**Interfaces:** Future command syntax: `scopebase-conformance describe`; `plan --profile ID --fixture-root PATH`; `run --profile ID --fixture-root PATH --output PATH [--fixture-manifest PATH] [--mapping-policy POLICY]`; `verify-receipt PATH`; `cleanup --run PATH`. Defaults never perform active setup during describe/plan. Use the exact result/exit contracts in the spec.

**Required frozen input/control:** Include H33 applicable original notices, source-option and final-object manifest in the installed offline route; test missing-notice and mismatched-source/object controls. Normal dependency cargo test never substitutes for this user-run delivery.

**TC-R10/H33 facet:** installed applicable H33 route and required notice delivery. Follow D03–D04; other facets remain with their named owners.

- [ ] Write `installed::different_resolved_library_is_not_certified`, `offline_read_only_prefix`, `missing_fixture_is_incomplete`, `cli_refusal_exit_and_effects`, and `receipt_is_not_runtime_authority`. Require exact compiled subject metadata and independently resolved downstream package code.
- [ ] Build package archives, install fixture closure into a read-only prefix and run `python3 tools/qualification/test_installed.py --prefix PATH --output PATH` in a fresh source-free offline environment; first demonstrate missing-fixture/incorrect-binding failures.
- [ ] Implement CLI dispatch, bounded machine/human results and stable exits 0/1/2/3/64. Package workers/prebuilt selected objects and audit helpers with their own hashes/licenses. No hidden compile/download is permitted in run-only profiles.
- [ ] Run applicable cases through both the standalone command and real independently built consumer adapters. Exercise minimal/default/feature unions and explicit `cargo test -p scopebase-testkit --doc`; dependency tests are not assumed to run automatically.
- [ ] Verify complete profile accounting and cleanup, review public instructions and commit.

**Done:** Users can run shipped checks against named subjects without source workspaces. A standalone tool result does not silently qualify another application's embedded version.

### TT08: Causal CI selection and safe parallel scheduling

**Depends on:** TT01–TT02, initial runnable component tasks; integrates TT04–TT07 as they become available. **Requirements:** TT-R11–TT-R12, TT-R14; T05/G19/G21.

**Files:** Create `.github/workflows/{contracts,objects,linux,qualification}.yml`, `tools/qualification/select_affected.py`, `profiles/impact-v1.json`, `tools/qualification/tests/test_selection.py`, `docs/testing/ci.md`. Use repository-supported CI if GitHub is not selected; this task must record that concrete choice before workflow execution.

**Interfaces:** `select_affected(change_manifest, contract_graph, requested_profiles) -> SelectionPlan` returns required tests/cells and explanations, including unresolved impact. One coordinator owns shared manifests and environment leases.

- [ ] Write selectors where only a dependency, feature, compiler flag, fixture/oracle or consumer adapter changes. Assert affected unchanged-source cases are selected. Unknown impact broadens its declared boundary; it cannot return empty success.
- [ ] Run `python3 -m unittest discover -s tools/qualification/tests -p test_selection.py`; implement the versioned contract-impact graph and reviewable exclusions.
- [ ] Wire fast T0/API/package checks, selected objects, host fixtures, leased live cells and scheduled campaigns. Set distinct Cargo target/run roots and immutable shared object inputs; serialize global manifest edits and shared guests.
- [ ] Plant a prior semantic failure followed by a successful retry: required qualification remains unresolved until an explicit reviewed cause/fix/new candidate is recorded. Provisioning retries retain attempt history without pretending a semantic failure was infrastructure.
- [ ] Exercise the workflow's selection/aggregation logic with recorded synthetic CI outcomes, then actual selected jobs. Review and commit.

**Done:** CI runs the required causal subset and reports unavailable required jobs as incomplete. It does not require every platform for every host-only change.

### TT09: Resource, performance and concurrent-consumer qualification

**Depends on:** TT03 and LX03/LX04 for the initial resource contract. Additional BP/CP/NX workloads register measured gates in their own readiness tasks. **Requirements:** TT-R12–TT-R13; T04/T06/Q06/G04–G05/G08/G15–G17.

**Files:** Create `benches/contract_costs.rs`, `profiles/performance-v1.json`, `tools/qualification/measure_resources.py`, `tests/downstream/coexistence/`, `docs/testing/performance.md`.

**Interfaces:** `ResourceSample` names epoch and units for current/peak FD, worker, mapping, link, retained/working bytes and attempts; sampler errors remain errors. Performance manifests freeze workload, environment, baseline and metric interpretation before comparison.

- [ ] Write cap N/N+1, overflow, peak reallocation/clone, concurrent scans, reservation-transfer and repeated failed-cleanup cases. Verify no hidden unbounded quarantine and no cross-consumer cleanup; preserve a foreign sentinel.
- [ ] Run `cargo test --manifest-path tests/downstream/coexistence/Cargo.toml` plus selected domain resource tests; demonstrate early-refund/double-charge/global-lock or foreign-retirement mutants at the intended assertion.
- [ ] Implement bounded instrumentation and same-environment comparison tooling. Record CPU/time distributions separately from deterministic cap and complexity assertions.
- [ ] Run measured standalone consumers and applicable live workloads. Document meaningful regression/tradeoff decisions; do not accept violated caps as timing noise or claim additivity of overlapping memory metrics.
- [ ] Review output privacy/cost and commit the bounded measurement slice.

**Done:** Resource promises have observable tests and supported observers coexist; performance claims name reproducible workloads and environments.

### TT10: Qualified support matrix and test-delivery completion

**Depends on:** TT02/TT07/TT08 for checker implementation and independently expected invalid/valid record controls. Applying it to a profile additionally requires that profile's actual TT/domain results; the checker does not depend on final package/SDK/native readiness tasks. **Requirements:** TT-R01–TT-R14; U08/T07 and all selected readiness gates.

**Files:** Create `docs/support.md`, `profiles/qualified-index-v1.json`, `tools/qualification/check_release.py`, `tools/qualification/tests/test_release.py`, `docs/testing/adding-a-profile.md`.

**Interfaces:** `check_release(candidate_manifest, requested_profiles, result_set) -> QualificationSummary` rejects stale/wrong-byte/partial results and never removes required obligations. The qualified index contains only named exact profiles/results, not a universal supported-kernel assertion.

- [ ] Write missing-cell, changed-fixture, changed-object, unknown-schema, missing-cleanup, absent-consumer, omitted transitive component-profile and missing runtime-linkage-extension controls; require incomplete/invalid outcomes even if all supplied results are green.
- [ ] Run `python3 -m unittest discover -s tools/qualification/tests -p test_release.py`; implement release selection over immutable required manifests and actual result bindings. Independently recompute the requested profile/extension closure and require a bound result for every required component; a green SDK/native summary cannot substitute for those results.
- [ ] Run the complete selected finite matrix through distributed/operator and independent client routes. Account for every required subcase and restore valid controls. A held-file result cannot close mapped-image readiness.
- [ ] Generate/check public support/prerequisite/effect documentation from accepted results; link issue/removal records and explicitly open future profiles. No package publication occurs automatically.
- [ ] Review the exact candidate support statement and commit the qualification artifact/code changes. Only actual passing required results close package-ready items.

**Done:** Maintainers have a repeatable completion check and users receive usable tests/documentation. Product-migrated status remains in MG, independent of this package verdict.
