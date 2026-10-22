# BP03 descriptive host verification plan

**RATIFIED DESIGN ONLY / PLANNED / NOT_RUN.** This plan specifies required
future checks; it is not an execution record. Read the host contract first.
All listed case names, dialects, source/helper files and commands are planned
outputs. The frozen authoring assets shipped beside the contract are normative
input/expected definitions, not implemented product checks. The
actual shared source admission is the centrally adopted immutable
`docs/provenance/admissions/2026-10-22-next-host-scopes.json`, SHA256
`e29cc889d99b73d3790a48fe555f4f74c60c4f718f7e184bd000f142a01e7bc1`.

## Core acceptance groups

| Group | Exact positive/negative assertions | Evidence limit |
|---|---|---|
| `filter_original_populations` | Preserve P's (own2,other0), (own1,other0), (own2,other1), (own0,other0), supplying expected2 and independently_executed_excluded1. Results Supported/Incompatible/Incompatible/Unknown, respectively | T0 supplied facts, no original native test execution |
| `filter_complete_priority_table` | Every literal filter-cases.json row equals its frozen expected state. Independent finite partition enumeration covers E/O equality/zero/order and X/H zero/nonzero, plus all MAX/1 boundary rows. Every typed population returns Ok; no Unsupported/Denied | Enumerator partitions numeric relations; it must not call or transliterate production branch code to construct expected truth |
| `observation_fields_are_lossless` | Read each public getter after valid construction; retain arbitrary binary reason/diagnostic, signed errno, required_size, every BP01 kind/stage, operation, step and cause method/IDs unchanged | Scalar snapshots only; no source-error inspection/classification |
| `constructor_bounds_and_error_order` | Hard max/exact max+1 per field; malformed label after an exhausted cap must still report the earlier cap; duplicates/unsorted IDs; all three outcome/error combinations; zero/MAX independent Limits; input/work/retained cap at n and n-1; injected allocation failure | Private fallible allocation seam is test-only; no global allocator or host-limit change |
| `borrowed_input_does_not_retain_capacity` | Build caller Strings/Vecs with small lengths and intentionally larger capacities, create observation from borrowed slices, then drop/mutate caller buffers. Getters retain original bytes, returned retained_bytes equals actual owned capacity accounting, and small fitting caps succeed | Does not bound caller memory, allocator overhead or RSS |
| `context_matches_every_field` | Base match true; mutate exactly object/profile/kernel_build/BTF value/BTF presence/architecture/namespace/security/topology, one at a time: false. Matching None-BTF twin true; Some(zero) differs from None. No case normalizes strings/digests | Matching context is descriptive and has no native effect |
| `origin_is_local_and_claim_is_preserved` | new origins CallerDescribed/CallerDescribed; import origins Imported/caller_described; re-encode preserves wire claim but repeat import is still Imported. Payload fields match independent literals. Imported object is deliberately not Eq to original local object | No roundtrip-only oracle; no native-observed variant |
| `hazard_and_capability_remain_separate` | Denied+Clean, Unknown+Affected and Incompatible+Unknown preserve both fields. Neither Clean nor imported Supported calls an effect or rewrites other state | No hazard policy/override or native cause inferred |
| `bp01_stage_and_cause_are_independent` | Cover all 11 current BP01 Stages and kinds; specifically EvidenceStage::Load with Stage::Execute, errno13/1 and distinct cause labels/states. Reason/diagnostic bytes remain unchanged. A source Error with panicking format/source methods is not touched | H33 descriptive/model evidence only, not cause authentication |
| `profile_receiving_domain` | Exact 1/64/65/128/129-byte boundaries, slash, uppercase, first punctuation, non-ASCII and controls as profile-cases.json. Checked bridges use unchanged receiving parser bytes and exact receiving error type | Distinct domains preserved; no alias/normalization |
| `json_strict_bounded_record` | Exact example getters/import origin, reordering and JSON whitespace positive twins; missing required null, duplicate/unknown key at each object, wrong kind/version/revision, wrong scalar/null/hex/decimal, invalid UTF-8, escaped alias, trailing value, depth/array/count/size/work/retained/allocator controls | Typed visitors, no generic Value; no public Deserialize bypass |
| `public_traits_and_authority_boundary` | Positive stated per-type Clone/Copy/Eq/Send/Sync traits and permitted pure APIs; observation Clone, forbidden Default/private fields/unchecked IDs/public Deserialize/native owner coercion fail for exact intended diagnostics | Compile-only checks, no native invocation |

R2 adds the exact cases in adapter-cases.json and codec-cases.json. Constructor
RunLimits minima and invocation equality/mismatch are specified in
[adapter-resources.md](../specs/2026-10-22-scopebase-bp03-host.md#adapter-resource-contract). Test zero explicit BPF work before
input scan, disabled byte/retention caps, checked composition overflow, two
individually fitting records whose sum does not fit, output+prefix peak, actual
capacity overgrant and guaranteed fixed-error checked construction. The direct
encoder's zero-work counter excludes only fixed metadata length arithmetic;
no counting writer/serializer/payload loop may enter. Test byte/work/retained
multi-fault precedence, allocation-stage preservation and reordered duplicate/
unknown/schema/semantic faults from [codec-resources.md](../specs/2026-10-22-scopebase-bp03-host.md#codec-resource-contract).

Typed `CapabilityObservation::new` errors must assert kind/stage/errno/
required_size exactly as contract.md. Diagnostic prose is not a schema or oracle.
Snapshot tests use a Cartesian set of all current kind/stage values and errno
None/0/1/13/-1/i32::MIN/i32::MAX, required_size None/0/usize::MAX. Expected getters
are those independently selected literals, not formatted production output.
No required stage may disappear behind an errno or the evidence-stage mapping.

For constructor retention tests, private inspected fields may be measured only
from in-crate tests. External consumers use the public retained_bytes getter,
literal field expectations and actual caps. Allocation-failure control reaches a
valid semantic input after all budgets pass, then refuses allocation with
Backend/Allocate and zero returned payload. It must not crash during setup.

## Authoritative packaged assets and independent clients

Proposed BPF package files:

- `src/capability.rs`, `src/capability/json.rs` and root reexports.
- `tests/capability.rs`, `tests/capability_json.rs`,
  `tests/ui/bp03_{positive,private,default,deserialize,native_owner}.rs`.
  Both new integration targets are explicitly registered; capability_json has
  required-features=["json"]. Inherited autotests/autoexamples remain false.
- `fixtures/capability-v1/{filter-inputs,filter-expected,context-inputs,context-expected,profile-inputs,profile-expected,observation-inputs,observation-expected}.json`
  plus malformed `.bytes`/`.bin` files and an ordinary valid JSON case index.
- `examples/capability_cache.rs` and `examples/filter_assessment.rs` as explicitly
  registered BPF-only public-API consumers. They import no testkit; JSON code in
  capability_cache is cfg-gated. Complete bridge/adapter clients ship in testkit.
- `tests/support/check_bp03_controls.py`: bounded package-user route to exact
  positive/negative external compilation and semantic controls; default route is
  direct Cargo from explicit --toolchain-root/--cargo-home/--cargo-config, with
  an explicit optional --build-wrapper. No mandatory
  reference to a private controller path in the delivered helper.

Proposed testkit package files:

- `src/bpf/{mod,adapter}.rs` behind bpf-host, with JSON operations behind
  bpf-host-json; default testkit behavior remains independent of BPF.
- `tests/bpf_host.rs` and `tests/fixtures/bp03/{catalog-core,catalog-json,bundle-template}.json`,
  `controls.rs`, the complete clients/populations/src/oracle.rs and README.md.
  These supply actual case/oracle/control
  registrations, not a second copy of the expected BPF fixture populations.

Each corpus uses a single source of expected truth. The proposal's literal data
is a seed for those delivered input/expected files; splitting files does not
change expected rows. The post-build binder creates a vector manifest pointing
to measured primary assets from the explicit unpacked BPF package. The template
contains source paths and version declarations; actual lengths/hashes/consumer
identity are filled from bytes after building, never placeholder digests. Package
users explicitly provide both unpacked package roots. No Cargo dependency test
discovery or checkout-relative external asset is required.

Two separately locked external clients are mandatory:

1. `bp03-cache` constructs bounded CallerDescribed observations from its own
   fixed metadata, queries context applicability, exercises getters/traits and
   checked ID bridges, and, with json, imports/re-encodes independently authored
   observation vectors. It uses its direct actual BPF dependency and distinct
   context-cache caller logic; it is not a wrapper around the filter helper.
2. `bp03-populations` uses BpfHostAdapter and actual public assessment against
   measured populations, a separately wired TT02 VectorFixtureSession, and a
   literal independent oracle/ledger. It executes the required development
   subset and writes/reimports the TT02 report. This is actual model execution,
   not a receipt replay standing in for execution. It must explicitly invoke
   the delivered cases.

Complete sources/templates ship in testkit/tests/fixtures/bp03/clients/cache
and clients/populations. The root bp03-cache.rs/bp03-populations.rs and population
oracle copy are byte-identical projections of those shipped templates, never
separate authorities. Their exact paths, typed manifest substitutions, actual
archive local patch, target declarations, inherited closure and metadata gates
are fixed in [delivery.md](#delivery-resource-contract) and delivery-recipes.json. Every new
client has its own lockfile, actual direct BPF/testkit paths, and measured binary.
The source mode stages byte-verified sibling packages; archive mode uses actual
unpacked normalized packages, without rewriting their manifests. No BPF testkit
dev-dependency cycle or implicit dependency-test discovery is introduced.

## Exact T0 dialect, cases and intent

All scripts use TT02's existing steps-v1 structural envelope, positive case
revision1, cell `model`, one attempt, distinct positive operation IDs, and the
actual `execute`/`retire` seam. No new script interpreter or verdict fold is added.
Preflight validates the entire script before reading input slots. One unsupported
schema/op/arity/parameter combination rejects with typed UnsupportedSchema,
step_id=None, errno=None, cause=Unknown, empty completed_steps/partial observation,
and an empty complete effects batch. It still participates in normal retirement.

| Schema / operation | Inputs and exact result bytes |
|---|---|
| bp03-host-v1 / assess-filter | One slot containing exactly four LF-terminated canonical decimal-u64 lines in E,O,X,H order; no CR, sign, leading zero except0, blank line or trailing bytes. Result is supported/incompatible/unknown ASCII, without LF |
| bp03-host-v1 / to-testkit-profile | One slot containing BPF profile bytes plus one terminal LF; no extra LF. Validate source BPF domain, then receiving testkit domain on unchanged bytes. Success `ok:` followed by unchanged ID; receiving failure `receiving-id-error`; source failure `source-id-error` |
| bp03-host-v1 / from-testkit-profile | Same single LF input; validate source testkit parser then BPF parser. Same exact three result forms |
| bp03-host-json-v1 / import-observation | One slot containing the exact bounded BPF JSON observation. Success result is ASCII `imported\n` followed by bounded canonical to_json bytes; getter origin is queried, never copied from input. Codec error produces CaseError with current step, BP01 kind/stage encoded in bounded diagnostics, raw errno unchanged, cause Unknown |
| bp03-host-json-v1 / context-applies | Two slots `base` and `candidate`, each a complete bounded observation. Decode both, call base.applies_to(candidate.object(),candidate.profile(),candidate.context()), result is ASCII true/false without LF |

No scalar parameters are accepted. Core adapter refuses the JSON dialect without
the corresponding feature, with the normal typed preflight above. Invalid count
byte grammar is InvalidOutput at stage `input`, current step set, cause Unknown,
no operation completion. This is an adapter/input error, not a native refusal.
Public constructor/codec errors are CaseErrorCategory::Refused with actual step,
unchanged raw errno and no inferred cause; all such cases are AssertionOnly.
Current completed_steps is empty on a failing sole step and contains that step
on success. Observations retain schema revision1/current invocation key and no
effects. No record claims fork, attach, trigger, excluded or native cleanup.

Proposed local development catalogs select these case revisions:

| Case ID | Required core or JSON subset | Exact assertion IDs |
|---|---|---|
| H22.model-filter | core and JSON; every frozen filter row | filter.state, filter.not-native-support |
| H22.model-profile-bridge | core and JSON; every frozen bridge row | profile.result, profile.bytes-unchanged |
| H22.model-context | JSON; base and every one-field mutation | context.applies, context.not-authority |
| H22.model-origin | JSON; both claimed origins and imported getter | origin.imported, origin.claim-preserved |
| H33.model-description | JSON; same-errno/different described causes and Stage::Execute/Load | description.fields, cause.not-authenticated |
| H22.model-json | JSON; exact positive and malformed twins | json.result, json.no-authority |

Catalog IDs are `bp03-host-models-v1` and `bp03-host-json-models-v1`, separate
explicit development subsets, not new canonical support profiles. Every case
uses AssertionOnly/T0; actual environment capability is Unknown. Assertions
about the absence of authority are compile/API checks rather than trusting a
serialized boolean. Core/JSON catalog required sets are fixed before execution;
the core subset is not obtained by dropping failed JSON cases. Canonical
bpf-host-v1, H22.filter-canary, H22.uretprobe-hazard and H33.license-admission remain
planned/open under BP11/TT05/TC owners. No denominator is shrunk to make those
profiles pass. Task/requirement/family IDs and their original meanings remain.

The independent oracle consumes ExpectedEvidence/CaseOutcome and literals only.
It does not call assess_filter_probe, applies_to, the codec or profile conversion
to determine expected truth. ExpectedEvidence is inaccessible to the adapter.
The fixture ledger contains independently authored fixed input/expectation and
coverage declarations, with TruthKind::FixedBeforeExecute. It does not observe
actual input delivery, function entry or return. These model rules use empty
coverage and empty requires_coverage; no invented observation is needed for
AssertionOnly. Actual model execution evidence is measured consumer/adapter
source plus actual runner outcomes, independently wired direct public-API checks,
and correctly re-bound semantic mutants/restored twins. Receipt import is
separate. Use existing TT02 artifact/session/intent/cleanup/reimport validation
and preserve actual oracle_verdict. No observer, fixture engine or verdict engine
is added.

## Semantic controls and restored twins

Every semantic mutant must compile, complete valid setup, reach its named
assertion through the actual adapter/public API and fail that assertion. Admission
controls assert that the protected payload operation was never entered; they do
not require forbidden activity to establish setup validity. Rebind the changed candidate's
actual bytes so a stale-source/binary hash does not cause the failure instead.
Preserve the wrong and restored outputs, exact sources/hashes and oracle bytes.

| Control | Discriminating positive/active-negative input | Intended failure |
|---|---|---|
| all_zero_supported | E0/O0/X0/H0, plus valid2/2/1/0 twin | filter.state: Unknown vs wrong Supported |
| ignores_excluded_hits | 2/2/1/1 and 0/0/0/1, plus 2/2/1/0 | filter.state: Incompatible vs wrong pass/Unknown |
| missing_own_thread_accepted | 2/1/1/0 plus2/2/1/0 | filter.state: Incompatible vs wrong Supported |
| extra_own_or_expected_zero_accepted | 2/3/1/0 and0/1/1/0 | filter.state: Incompatible |
| exclusion_prerequisite_omitted | 2/2/0/0 plus2/2/1/0 | filter.state: Unknown |
| incomplete_overwrites_known_failure | 2/1/0/0 and2/2/0/1 | filter.state: Incompatible retains judgeable failure |
| context_field_omitted | One separately compiled mutant for each object/profile/kernel/BTF value/BTF presence/architecture/namespace/security/topology check | context.applies: false for the corresponding literal mutation |
| ID_normalized | Uppercase testkit input, slash BPF input and length65 BPF input; valid lowercase64 twin | profile.result and unchanged bytes |
| import_recreates_local_origin | Valid wire claiming caller_described | origin.imported: Imported, despite matching payload/claim |
| duplicate_or_unknown_last_wins | Duplicate state/cause/context fields and unknown member after valid setup; valid reordered twin | json.result: Malformed/Inspect |
| truncates_payload_or_diagnostics | Distinct arbitrary binary bytes at exact admitted limits | description.fields and byte-for-byte getters |
| errno_only_denied | Same errno13/1 and Stage::Execute, distinct supplied Permission/Verifier/License/Unknown descriptions | description.fields, no rewrite from errno |
| stages_collapsed | EvidenceStage::Load plus original Stage::Execute/Allocate/Inspect | description.fields: both domains exact |
| per_record_budget_reset | Context records individually fit but Dbase+Dcandidate+result reserve exceeds H; twin has exact joint capacity | adapter.joint-retained: refused before second publication/comparison |
| prefix_peak_omitted | D+JSON+prefixed Vec peak exceeds H although final result alone fits | adapter.prefix-retained: Refused, no partial output |
| implicit_work_from_time | Explicit BPF work_steps=0 with otherwise generous RunLimits.execution_ms | adapter.work-before-scan: no payload parse or public operation |
| invocation_limits_ignored | Different legal invocation RunLimits against an admitted stored ceiling | adapter.limit-binding: fixed checked binding error, zero input access |
| encoder_counts_before_work | Valid record, adequate byte cap and work0 | codec.no-payload-before-work: zero serializer/hex/counter entries |
| allocation_remapped_to_malformed | Valid shape/schema/fields and injected allocation refusal | codec.error-stage: Backend/Allocate, no payload |
| wrong_library_copy | Two distinct BPF package sources at same version, direct vs adapter edges differ | Binding control rejects graph/subject mismatch before qualification; this is explicitly a binding negative, not semantic mutant sensitivity |

The known K fork/self-link sources are retained as source-inspection
counterexamples only. No synthetic fork-success or link-create-success is treated
as a live positive twin. A control that crashes/denies/skips before its tested
semantic assertion is NOT_SENSITIVE and cannot satisfy acceptance.

## Compile boundary using a real owner API

BP02 is accepted at integrated subject
`8f10d948bdd6cf92007870a838d258ee35333eb8`, ledger commit
`6050f379e9990284a8b75a8d20a38b8ef84f9b89`. Bind the actual accepted
`ValidatedMap::lookup(&mut self,
key:&[u8])->Result<Option<Vec<u8>>,OperationError>` declaration in the selected
execution base. The frozen r2 inspection at maps/handle.rs:217 recorded that
signature; its old candidate hash is historical inspection evidence and does
not bind the future execution input. Positive compilation contains a function taking
`&mut ValidatedMap` and calling that exact method without executing it.
The active negative changes only its receiver to `&mut CapabilityObservation`
and calls the same real method by UFCS; expected E0308 is the receiver type
mismatch. Do not invent a missing owner symbol or create native resources.
The observation's ordinary construction/serialization positive must compile in
the same actual package/configuration. If accepted BP02 changes the signature,
root must update this concrete bound test before dispatch, not claim an old
candidate or nonexistent API establishes the boundary.

## Source/archive campaign and exact stop rules

The definitive target/feature/client/tool/cache recipes are [delivery.md](#delivery-resource-contract)
and delivery-recipes.json. Freeze the actual post-BP02 source manifest and actual
archive Cargo.toml/Cargo.toml.orig/normalized declarations before the first Cargo
call. Explicitly register capability, capability_json(required-features=json),
BPF-only examples and the primary fixture include. Preserve the entire inherited
BP02 Linux dependency/target closure; std-only describes this increment's core
implementation, not the resulting Linux package graph.

Run12 BPF source/archive/compiler/configuration cells and24 BP03 client runs;
run20 testkit metadata/target/lib/integration/doc cells and80 retained TT01/TT02
client runs, plus24 BP03 runs in the12 activated cells. Shared identical actual
runs may satisfy both inventories only with identical complete bindings, as in
delivery.md. Core/default/JSON-union source, dependency and raw feature graphs
must match both direct consumer and adapter edges. Preserve affected inherited
host checks; no new privileged BP02 probe is started for this model increment.

All build/helper routes bind version, absolute toolchain root, Cargo home/config,
admitted cache/vendor source inventory, private targets and one explicit wrapper
route. The portable shipped helper is testkit/tests/fixtures/bp03/run_consumers.py
with exact --package/--testkit-package/--out/--toolchain/--toolchain-root/
--cargo-home/--cargo-config and optional --build-wrapper arguments. The root
campaign driver has both compiler-root bindings and measures source/archive
manifests, dependency projections, normalized targets, both client sources,
locks, binaries, fixture/input/expected/ledger/oracle/control bytes. Missing
required roots/cache/dependencies remain NOT_RUN/incomplete; no implicit install
or version-only PATH/rustup/mise discovery is permitted.

After implementation focused capability commands use the explicitly registered
targets under the controller wrapper and admitted toolchain/config/cache: --test
capability for all3 BPF modes and --test capability_json only with --features
json. The full fixed cell/command inventory is in delivery-recipes.json; none of
these commands was run in this preparation.

Acceptance requires destination-bound selected-port receipts for the three
admitted P ranges, all focused valid-setup semantic controls/restored twins,
actual source/archive consumers, affected testkit feature/metadata/regression/
client checks and independent review of the repaired contract/source map.
The fixed ledger's predeclared values do not independently observe operation
entry or completion. Native H22/H33, installed operator, full bpf-host-v1,
finite distro/object/helper/license/cleanup cells and product migration remain
open under their existing owners. Final base/resources remain UNBOUND.

## Canonical definitions and status

Read the [host contract and ratification identities](../specs/2026-10-22-scopebase-bp03-host.md#ratification-prerequisite-evidence-and-document-map)
with the [complete finite authoring assets](../specs/bp03-host/README.md).
The reviewed shorthand contract.md, adapter-resources.md and codec-resources.md
means the contract and its embedded resource sections. delivery.md and plan.md
mean this plan's [delivery resource contract](#delivery-resource-contract) and
[implementation sequence](#implementation-sequence). JSON/fixture/template names
refer to the delivered normative support subtree; no private ignored proposal
is needed to recover those definitions. New package Rust sources/helpers and
catalogs listed above remain implementation outputs, not authored here.

BP02's accepted task/subject/6050/receipt identities are historical prerequisite
evidence, not BP03 execution-base authority. Actual current base/API/dependency/
feature/lock/source/archive/tool/cache/resource/writer/output bindings and current
TT02 maintenance remain UNBOUND. Required missing inputs remain NOT_RUN.
The full BP03 native/operator/profile task remains open. No changed-byte product,
model, compiler, package/archive, native or installed test ran during adoption.


## Delivery resource contract

Status: ratified R4 delivery repair. The frozen r2 BP02 v8 manifest
inspection remains historical; BP02 is now accepted as bound in the contract.
No actual BP03 execution base is selected here. Before implementation
root must bind the actual accepted Cargo.toml, Cargo.toml.orig/normalized archive
declarations, file-list projection, lock and dependency policy. Do not overwrite
the inherited manifest with a BP01-era empty-graph manifest.

## Exact package delta

Preserve package identity/version0.1.0/MSRV1.88.0/license/build=false,
autotests=false, autoexamples=false, existing explicit targets and default=[].
The inspected inherited include patterns are Cargo.toml/README/license/notices,
src/**,tests/**,examples/**. Append fixtures/capability-v1/**. Preserve every
inherited cfg dependency: on Linux/x86_64/GNU/64-bit/little-endian this includes
rustix=1.1.5 with std,fs,process,thread,linux_4_11; libc=0.2.191/std;
sha2=0.11.0; all defaults off. Bind the full inherited resolved union, not just
these three direct names. The BP02 selected projection currently has13 packages;
root must bind the actual accepted projection. No new host-native feature or
loader/compiler dependency is proposed.

The new core implementation uses std only, but the resulting selected Linux
package graph retains those BP02 dependencies. Optional JSON adds only the exact
already admitted serde1.0.229/std and serde_json1.0.151/std declarations. The
combined testkit graph also retains TT02's admitted serde/derive/sha2 closure and
the actual feature union. Preserve actual notices/options and build-script
activation; do not assert an empty package graph or remove inherited grants.

Append exactly these explicit BPF targets; automatic discovery remains off:

```toml
[[test]]
name = "capability"
path = "tests/capability.rs"

[[test]]
name = "capability_json"
path = "tests/capability_json.rs"
required-features = ["json"]

[[example]]
name = "capability_cache"
path = "examples/capability_cache.rs"

[[example]]
name = "filter_assessment"
path = "examples/filter_assessment.rs"
```

Both Cargo examples depend only on BPF public APIs. capability_cache constructs
descriptions, queries exact context matching and uses only BPF ProfileId; its
JSON branch is cfg(feature="json"). filter_assessment calls the pure helper.
Neither example imports testkit or uses its profile bridge. No testkit
dev-dependency is added to BPF. UI source files are explicitly executed by the
portable compile helper or included by the registered capability tests; their
presence alone is not Cargo target execution.

The testkit keeps its existing default=[], include src/**/*.rs/tests/*.rs/
tests/fixtures/** and existing serde/serde_json/sha2 dependencies. Add only the
optional exact BPF edge/features from contract.md; src/bpf exports are gated by
bpf-host. Add tests/bpf_host.rs as an explicit test target with
required-features=["bpf-host"], despite currently enabled test auto-discovery,
so baseline tests never import a disabled module. JSON-only groups within that
target are cfg(feature="bpf-host-json"). Preserve current TT01/TT02 targets.

## One shipped source for each complete external client

The authoritative full sources are in the testkit package:

| Client | Canonical shipped template/source | Root campaign copy |
|---|---|---|
| bp03-cache | tests/fixtures/bp03/clients/cache/{Cargo.toml.in,src/main.rs} | tests/package-policy/fixtures/clients/bp03-cache.rs equals shipped src/main.rs byte-for-byte |
| bp03-populations | tests/fixtures/bp03/clients/populations/{Cargo.toml.in,src/main.rs,src/oracle.rs} | bp03-populations.rs equals shipped src/main.rs; bp03-oracle.rs equals shipped src/oracle.rs |

Each main is fully implemented independent caller logic. cache performs direct
public construction/context/getter/ID/optional-import checks; populations wires
the actual BpfHostAdapter, VectorFixtureSession, literal oracle and runner/report
round trip. The oracle lives in the population template's src/oracle.rs and is
also the registered OracleSource through its exact source mapping. Do not maintain
a divergent oracle copy or a second expected population. Case/control sources
and the primary BPF fixtures remain registered/bound individually.

Both template manifests are one-package workspaces with exact package name,
version0.1.0, edition2021, explicit [[bin]] path=src/main.rs and no implicit bin
selection. Their only direct dependencies are scopebase-bpf=0.1.0 and
scopebase-testkit=0.1.0, pointing to the exact staged source/unpacked packages.
Their default-feature booleans and testkit features are frozen by the table
below. Literal expected vectors need no new direct client serde dependency:
the helper creates separately measured raw input/expected vector assets from
the canonical packaged literal index, and the oracle compares outcome bytes
with ExpectedEvidence bytes. It never computes truth through the subject APIs.

Cargo.toml.in is a finite template: only BPF_PACKAGE_PATH, TESTKIT_PACKAGE_PATH,
BPF_DEFAULT_FEATURES, TESTKIT_DEFAULT_FEATURES, BPF_FEATURES and TESTKIT_FEATURES are substituted as typed
TOML values. No shell expansion, environment lookup, arbitrary dependency or
manifest merging is allowed. Freeze the rendered manifest before any Cargo call.
The package includes the template and its complete Rust sources. The root
campaign checks byte equality of each root copy with that shipped source; root
copies are historical/campaign navigation, not another authority.

For source mode, make byte-verified owned sibling copies named scopebase-bpf and
scopebase-testkit below the fresh output stage. This preserves the testkit source
manifest's ../scopebase-bpf path edge without modifying originals. For archive
mode, verify and unpack both actual produced .crate files and preserve their
normalized manifests/Cargo.toml.orig unmodified. Every client manifest includes
the following local patch pointing to the same BPF package as its direct edge:

```toml
[patch.crates-io]
scopebase-bpf = { path = "THE_SAME_TYPED_BPF_PACKAGE_PATH" }
```

That sentinel is the same typed BPF_PACKAGE_PATH substitution, not a new free
input. It resolves the archived testkit's normalized version-only BPF edge
offline to the measured BPF package. In source mode the explicit source path
must already resolve to that same staged package; the patch does not excuse a
foreign path dependency. A lock may mention optional BPF packages in baseline
testkit modes; only the actual filtered resolve-node graph establishes which
dependencies/features execute.

Before any Cargo call: inspect source/normalized archive package identity,
features, inherited direct dependency/cfg declarations, every target path and
required-features, include/file-list mapping, exact client template/source and
rendered dependency/patch paths. Bind any supplied admitted seed lock. In a new
owned standalone stage only, create a missing cell/client lock with the explicit
toolchain's `cargo generate-lockfile --offline --manifest-path ABS_MANIFEST
--config ABS_CONFIG` under the identical wrapper/env/cache route. Compare its
package/version/source projection against the admitted closure and freeze its
hash before metadata or builds. Never change source/archive originals or resolve
against undeclared cache contents. Then run offline/locked metadata and compare
the actual resolved graph and targets. Require exactly one BPF package ID in
activated consumer graphs, direct and adapter edges equal to it, exact version/
source/features/backend/objects matching the independently bound SubjectBinding.
The same-version second-copy negative must fail this check; do not qualify the
testkit's separately resolved copy. Baseline testkit resolve graphs have no BPF
node. Archive bindings include both package archive hashes and normalized target
evidence, not just source manifest bytes.

## Explicit source/archive cells

For each library input source/archive and compiler1.88.0/1.98.1, freeze these
testkit configurations before dispatch:

| Mode | Testkit Cargo arguments / raw feature set | Isolated testkit / retained-client BPF features | New combined BP03-client BPF features | Required clients |
|---|---|---|---|---|
| default | no feature flags / [default] | no BPF node | no new BP03 client | retained TT01 inventory+selection, TT02 run+receipt |
| minimal | --no-default-features / [] | no BPF node | no new BP03 client | same four retained clients |
| core-default | --features bpf-host / [bpf-host,default] | [] | [default] | retained four plus cache+populations core |
| core-minimal | --no-default-features --features bpf-host / [bpf-host] | [] | [] | retained four plus cache+populations core |
| json-union | --no-default-features --features bpf-host,bpf-host-json / [bpf-host,bpf-host-json] | [json] | [json] | retained four plus cache+populations complete JSON union |

An enabled empty default=[] still contributes the raw Cargo feature "default".
For the two new clients, core-default sets both dependency default-features=true,
BPF features=[] and testkit features=[bpf-host]. Core-minimal sets both defaults
false with the same explicit lists. JSON-union sets both defaults false, BPF
features=[json] and testkit features=[bpf-host,bpf-host-json]. The direct BPF edge
therefore adds the default marker in core-default even though the testkit's
optional BPF edge disables defaults. The isolated testkit and retained clients
do not have that direct edge. Preserve both graphs without normalization.

This is20 affected testkit metadata/target/lib/integration/doc cells and80
explicit retained-client executions. The12 activated cells add24 explicit
BP03 client executions. Each cell runs the complete previously accepted TT01/
TT02 tests and the new bpf_host target where enabled; JSON-only groups execute
in json-union. Baseline modes verify the optional module/edge stays disabled.
Keep raw dependency/features metadata and both isolated BPF and combined graphs.
No previous green manifest receipt validates these changed edges/exports.

The corresponding BPF input/compiler modes are default (raw [default]), no-default
(raw []) and json (raw [json])
(--no-default-features --features json), yielding12 BPF metadata/target/lib/
registered-capability/doc cells and24 client executions. Map their clients to
core-default,core-minimal,json-union respectively. Identical actual executions
may be referenced by both BPF/testkit cell receipts only when source/archive,
compiler, feature graph, locks, binary, fixtures/oracle and both subject bindings
are exactly identical. Do not rerun solely for duplicate bookkeeping or count
one execution for a differently bound cell.

Preserve inherited BP01/BP02 host regression targets/consumers. Do not blindly
run privileged maps_live/maps_mounts or reopen BP02 guest qualification as a
BP03 model check; inherited live evidence remains separately bound and unchanged
unless a changed input or named failure creates an affected obligation. These
new cells confer no live/kernel/operator/canonical profile support.

## Portable helper and actual tool/cache roots

Ship tests/fixtures/bp03/run_consumers.py in testkit; BPF's package README points
to this delivered route. Its exact CLI is:

```text
run_consumers.py --package BPF_ROOT --testkit-package TESTKIT_ROOT --out FRESH_DIR
  --toolchain VERSION --toolchain-root ABS_ROOT --cargo-home ABS_ROOT
  --cargo-config ABS_FILE [--build-wrapper ABS_FILE]
```

The BPF-only tests/support/check_bp03_controls.py has the same required arguments
except --testkit-package. It compiles/runs only the registered BPF UI/direct-API
control set and its restored twins; it does not import the testkit, alter its
fixture engine or run BP02 privileged targets. Both helpers use the identical
tool/cache/config and single-wrapper binding rules below.

The version is one of1.88.0/1.98.1 and must match that root's actual bin/cargo,
bin/rustc/bin/rustdoc versions and recorded executable SHA256s. Never discover
tools through PATH, HOME, rustup or mise. Child env uses explicit CARGO_HOME,
RUSTC,RUSTDOC,CARGO_TARGET_DIR,CARGO_NET_OFFLINE=true and private output/temp roots.
Use a fresh owned child cwd outside repository workspaces, so the stage is
standalone and no unrelated workspace member adds a BPF node to baseline graphs.
Use an explicit environment allowlist and reject unbound CARGO_/RUST_ overrides.
Inventory every ancestor-discovered Cargo config, Cargo-home config and supplied
config; reject an undeclared effective source/patch/registry/tool override. Merely
passing --config is not a claim that Cargo ignores other configuration files.
The resolved Cargo home/config and complete admitted cache/vendor inventory are
bound inputs, with configuration hashes and source projection. Missing cache,
compiler or dependency is NOT_RUN/incomplete; no install, fetch or fallback.
No arbitrary preexisting Cargo home is evidence of an admitted closure.

The helper checks all3 feature modes using distinct targets and independent
client lockfiles. It accepts exactly one routing choice: explicit internal
--build-wrapper for each heavy child, or direct children when the operator has
explicitly wrapped the entire helper once. Record chosen route/argv/roots and
propagate it to nested helpers. No implicit wrapper lookup or recursive slot
acquisition. The controller's local route is the existing absolute wrapper;
portable users need no private controller path. No host limits/credentials change.

The root campaign driver tests/package-policy/bp03/execute.py additionally accepts
the two version→toolchain-root bindings and source/archive inputs, records the
20 testkit/12 BPF required-cell inventory and invokes the same shipped client
helper. It preserves the explicit --output/--config/--build-wrapper contract;
--config is the exact --cargo-config binding forwarded to the helper. Full
argument/schema recipes and path/source mappings are in delivery-recipes.json.

Actual accepted post-BP02 manifests, tool/cache/config/version/digest bindings,
source/archive file hashes, resource ownership and final base remain UNBOUND.
These are finite execution inputs to fill after review/convergence, not open
API/behavior choices and not permission to start a build now.

## Implementation sequence

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task only after controller review/ratification and final-base binding. Design ratification alone authorizes no implementation, reviewer dispatch or commit.

**Goal:** Deliver bounded descriptive capability/context values, a pure complete
filter assessment and explicitly executable downstream model checks.

**Architecture:** Keep std-only host values in scopebase-bpf with an optional
strict JSON codec. Add a narrow optional testkit adapter using the accepted TT02
engine. Native probes, authority and live profile qualification remain later work.

**Tech Stack:** Rust1.88.0/1.98.1; existing BP01 Limits/OperationError; accepted
BP02 shared ArtifactId from the selected accepted base; existing TT02; optional exact serde
1.0.229/std and serde_json1.0.151/std, defaults off and no derive requirement.

**Spec:** [Repaired host contract](../specs/2026-10-22-scopebase-bp03-host.md), [verification](#bp03-descriptive-host-verification-plan),
[adapter composition](../specs/2026-10-22-scopebase-bp03-host.md#adapter-resource-contract), [codec phases](../specs/2026-10-22-scopebase-bp03-host.md#codec-resource-contract)
and [delivery recipes](#delivery-resource-contract). Root ratified the eight choices and independently reviewed R1–R4 repairs.
Actual post-BP02 execution base/resource bindings remain open. All finite expected
fixture data ships in the companion bp03-host subtree; no implementation command ran.

## Global Constraints

- The new core implementation needs no native backend, BPF toolchain, privileges
  or testkit. Preserve the resulting package's inherited BP02 cfg dependency union.
- Keep all existing normative public names/ProbeContext/ProbePopulation fields.
- Use actual immutable source admission
  `docs/provenance/admissions/2026-10-22-next-host-scopes.json`, SHA256
  `e29cc889d99b73d3790a48fe555f4f74c60c4f718f7e184bd000f142a01e7bc1`.
- Do not apply stale intake-draft-r1 full-ledger/adoption patches. Preserve all
  central CP05/LX08/current grants and rows.
- Final execution SHA, accepted BP02 APIs, vendor path, compiler hashes and
  allocated paths are UNBOUND. Resolve them before any product command.
- Root owns shared exports, manifests, features, lock, catalogs, policy, ledger
  and acceptance; one writer per assigned product/testkit file set.
- All heavy work uses the existing absolute controller wrapper/common resource
  domain and private targets. No Cargo/native/guest command ran in preparation.
- Source grants, descriptions, model results, installed delivery, live support
  and product migration remain separate evidence/completion levels.

## Review Focus

- Caller over-capacity buffers must not inflate retained observation storage;
  Task2 explicitly tests borrowed input and actual owned capacities.
- Any excluded hit or nonzero own mismatch must remain a known model failure
  even when unrelated support prerequisites are absent; Task1 pins priority.
- Imported caller_described wire records must never recreate a local issuer;
  Task3 has an explicit getter assertion outside roundtrip equality.
- A valid-looking optional-feature adapter must use the consumer's actual BPF
  copy; Task5 checks resolved package IDs and changed-source negative bindings.
- BP01 Stage::Execute and EvidenceStage::Load must both survive with identical
  errno and differing descriptive causes; Tasks2/4 pin the independent fields.

---

### Task 0: Bind the reviewed executor packet

**Files:** root-owned normative addendum under docs/superpowers/, verification
plan, package policy/feature delta, and the selected execution checkout.

**Interfaces:** Consumes actual BP01/TT02/LX05 acceptances and the central source
admission. Produces one immutable packet with final product SHA, accepted BP02
ArtifactId/ValidatedMap declaration hashes, admitted dependency/vendor closure,
source/case ownership, required cells, effect limits and resource routing.

- [ ] Bind root ratification and independently reviewed contract/verification/literal
  fixtures against the adopted eight choices and R1–R4 findings. Do not dispatch
  with one unresolved signature, truth-table row, cap, dialect or expected result.
- [ ] Bind actual accepted BP02 outputs and the selected final execution SHA,
  including actual current TT02 maintenance. Missing bindings stop dependent
  execution; do not invent a second ArtifactId or native owner.
- [ ] Bind the actual accepted BP02 Cargo.toml, archive Cargo.toml/Cargo.toml.orig,
  normalized targets/include projection and complete inherited cfg dependency
  closure. Add explicit capability/capability_json targets, required-features=json,
  BPF-only examples and fixtures include exactly as delivery.md. Record actual
  feature/notice delta and explicit toolchain/cache/config/vendor bindings before
  any Cargo metadata/build. Preserve default=[] and no new native backend feature.
  Allocate disjoint capability/testkit paths; serialize root
  manifests/exports/catalogs and all build commands.
- [ ] Add exact normative navigation/TODO bookkeeping without completing BP03.
  Run the existing planning/structural validators on adopted documents only.

### Task 1: IDs, contexts and pure filter assessment

**Files:** Create scopebase-bpf `src/capability.rs`, `tests/capability.rs` and
the primary filter/profile/context fixtures. Root registers the explicit test/
example targets and fixtures/capability-v1/** include, preserving inherited targets.

**Interfaces:** Consume shared ArtifactId, BP01 errors/Limits. Produce the exact
ProfileId/ProbeContext/ProbePopulation/enums and assess_filter_probe signatures
from contract.md. No native effects or serialization yet.

- [ ] Add all literal filter cases and independently authored finite relation
  partition expectations. Preserve the original donor four-population test and
  source-range mapping; fail at the intended state assertion against a valid
  all-zero-Supported control after setup succeeds.
- [ ] Run focused capability tests to establish initial RED. If the public API
  is absent, record the compile failure only as implementation absence; it is
  not semantic sensitivity. The valid-setup mutant checks follow implementation.
- [ ] Implement the constant-work four-count table exactly, preserving Result
  and returning Ok for all typed populations. Implement byte-preserving IDs,
  exact grammar/error order/traits/redacted Debug and unchanged public context
  fields. Enforce BPF ID's128-capacity bound for finite adapter reservations.
  Do not add a trusted constructor or infer architecture support.
- [ ] Run the focused suite and the excluded-hit, own-short, own-extra,
  expected-zero, missing-exclusion and known-failure-priority mutants with
  restored valid twins. Record independently generated expected truth.

### Task 2: Bounded descriptive construction and error snapshots

**Files:** Extend capability.rs and capability.rs tests; add public UI sources
and example capability_cache.rs. Root controls exports/include list.

**Interfaces:** Consume Task1 types and BP01 OperationError getters. Produce
ObservationOrigin/Outcome/DescribedCause, OperationErrorSnapshot,
CauseDescriptionInput/CapabilityObservationInput, private CapabilityObservation
and all getters/new/applies_to/retained_bytes signatures in contract.md.

- [ ] Write exact error-order/cap/zero/MAX/shape/traits/getter/context tests and
  hostile original Error-format/source controls. Add the nine context mutations,
  Some(zero)-vs-None, Denied+Clean and Unknown+Affected cases before implementation.
- [ ] Establish initial RED for the new record/getter tests. After the working
  implementation below, run owned omitted-context, errno-only-rewrite and
  collapsed-stage controls; require named semantic failures after valid setup
  and current changed candidate bindings. Initial missing symbols do not count.
- [ ] Implement length-only preflight, exact checked P/W charges, grammar/order,
  outcome/error shape, fallible bounded owned copies and actual capacity charges.
  Never retain caller buffer capacity or format/traverse the original source.
- [ ] Test borrowed buffers with large spare capacity, post-construction caller
  mutation/drop and per-allocation injected failure after valid preflight.
  Verify Backend/Allocate, zero returned payload and unchanged caller-owned data.
- [ ] Run focused capability and positive/negative UI checks on the exact
  candidate. Bind the actual accepted ValidatedMap::lookup compile receiver
  negative without executing native methods or constructing native resources.

### Task 3: Strict optional JSON codec

**Files:** Create capability/json.rs, tests/capability_json.rs and raw malformed
fixtures; root applies the reviewed exact optional-json dependency/notice delta.

**Interfaces:** Consume Task2 immutable record/shared validation. Produce only
CapabilityObservation::{to_json,from_json} under feature json, exact schema1
and the explicit imported/local-claimed provenance behavior.

- [ ] Freeze independent literal positive JSON/getter expectations and every
  malformed/escaped/missing-null/duplicate/unknown/overflow/limit fixture as
  specified. Add valid member-reordering/whitespace twins; .bytes/.bin holds
  malformed UTF-8/JSON rather than invalid .json files.
- [ ] Establish initial RED for the new codec tests. After implementation, run
  last-wins/ignored-unknown/import-local-origin controls and require the intended
  JSON/origin assertion failures after valid setup. A missing codec or a passing
  roundtrip alone is insufficient.
- [ ] Implement preflight and fixed borrowed typed visitors with duplicate
  bitsets/fixed reference slots; no Value/tree/derived public Deserialize.
  Share validation/copy routines, exact error-phase remapping and local Imported
  assignment. Implement exact length-only arithmetic from codec-resources.md;
  prepay before any payload traversal/serializer/counting writer. Implement the
  bounded output writer and peak record+output retention charge, preserving
  Backend/Allocate and post-allocation stages. No generic user writer callback.
- [ ] Add zero-work/no-payload-visit, byte/work/retained multi-fault, duplicate/
  unknown/schema/semantic member-reordering and valid-allocation-failure twins
  from codec-cases.json. Assert exact kind/stage/required_size, not setup crashes.
- [ ] Run focused JSON tests and exact byte/work/retained boundary controls;
  test lowercase-hex/decimal preservation, errors without partial payload and
  repeat imports. Verify default/no-default still compile without serde edges.

### Task 4: Delivered TT02 adapter and literal oracle cases

**Files:** Create testkit src/bpf/{mod,adapter}.rs, tests/bpf_host.rs,
tests/fixtures/bp03/controls.rs and complete client templates including the single
clients/populations/src/oracle.rs, plus core/JSON local catalogs/templates.
Root owns shared lib.rs/features/dependencies/lock/catalog registration.
Root also owns the narrow crate-private IDs footprint helper; no public ID API
or existing parser behavior changes.

**Interfaces:** Consume actual TT02 ConformanceAdapter/FixtureSession/CaseOracle,
Observation/CaseError/RetirementReport/RunLimits and Task1–3 public BPF APIs.
Produce BpfHostAdapter::new(subject,bpf_limits,run_limits) and the two checked profile bridge
signatures. Reuse existing run_profile/RunReport; no new verdict implementation.

- [ ] Implement literal expected/ledger fixtures independent of BPF logic and
  whole-script dialect preflight tests. Unknown schema/op/arity/parameters return
  the exact existing UnsupportedSchema shape before input access, with retirement.
- [ ] Implement constructor response minima, stored/invocation RunLimits equality,
  explicit BPF input/work charges and the joint per-invocation owned-payload
  ledger exactly as adapter-resources.md. Test two independently fitting records
  whose joint peak fails, JSON+prefix peak, zero-work before scans, arithmetic/
  observed-capacity refusals and the reserved checked error response.
- [ ] Implement only the closed core/JSON operations in verification.md. Invoke
  actual linked public APIs, preserve current keys/steps/schema/errors and report
  an empty effect ledger. Cause labels in imported descriptions remain data;
  actual T0 capability evidence is Unknown.
- [ ] Implement `retire` preserving request identity and unexpected pending/
  uncertainty with incomplete status, never fabricating retirement authority.
  Test normal empty complete and unexpected-pending incomplete responses.
- [ ] Execute all core/JSON required cases through VectorFixtureSession and
  existing run_profile, then reimport the actual report using the same contract.
  Retain actual oracle_verdict, scope and source bindings. Do not relabel an
  import as fresh case execution or register native planned cases as executable.
- [ ] Keep TruthKind::FixedBeforeExecute with empty coverage/requires_coverage for
  these AssertionOnly cases. The immutable ledger declares fixed truth; it does
  not observe function entry/return. Establish execution separately through actual
  measured outcomes/direct clients and sensitive re-bound mutants; add no observer.
- [ ] Run source-backed mutants from verification.md with valid setup and
  restored twins; assert each named value/description/profile/origin field.

### Task 5: Actual source/archive consumers and package-user route

**Files:** Ship complete external templates under testkit/tests/fixtures/bp03/
clients/{cache,populations}, its run_consumers.py and exact root byte-copy mappings.
BPF examples remain BPF-only. Create tests/package-policy/bp03/{execute,controls}.py,
member/expected-feature records and package READMEs. Root updates policy/include.

**Interfaces:** Consume actual exported Task1–4 APIs and primary packaged corpus.
Produce the exact execute.py CLI in verification.md, independent external
lockfiles, measured package/source/archive/client/fixture/oracle bindings and
explicit source/archive results for both clients.

- [ ] Implement the exact helper/campaign CLI recipes in delivery-recipes.json:
  absolute toolchain roots for both compiler versions, explicit Cargo home/config/
  cache inventory, fresh output/targets and exactly one wrapper route. Never
  discover versions from PATH/HOME/rustup/mise or install a missing prerequisite.
- [ ] Inspect actual source/archive normalized manifests/targets/includes and
  rendered template dependencies/local patch before the first Cargo call. Stage
  source siblings byte-identically; preserve archive manifests and bind the local
  crates-io patch to the same measured BPF root as the client's direct edge.
- [ ] Wire the two consumers independently as specified. Check metadata has
  exactly one BPF package ID and equal direct/adapter edges, then bind actual
  source/version/features/locks/compiler/consumer binaries and measured corpus.
- [ ] Run the wrong-library-source binding negative and its restored twin;
  distinguish this binding failure from semantic mutant sensitivity.
- [ ] Execute12 BPF source/archive cells/24 BP03 clients and the enumerated20
  testkit default/minimal/core-default/core-minimal/JSON-union metadata/target/
  lib/integration/doc cells with80 retained TT01/TT02 clients. New24 BP03 runs
  in activated testkit cells may be shared only with identically bound BPF cells.
  Bind actual binaries/fixtures/locks and raw inherited/combined dependency
  features. Missing required inputs remain NOT_RUN/incomplete; do not start an
  inherited privileged BP02 probe merely for this model increment.
- [ ] Run selected semantic controls against source and actual archive, retaining
  intended assertions/restored twins and package-user commands. Inspect the
  actual archive file list and prove delivered fixtures/helper source are usable
  outside the repository.

### Task 6: Source receipts, independent review and bounded acceptance

**Files:** Root-owned selected-port receipts, preservation map, acceptance record
and TODO/handoff/navigation. No old source receipt or active evidence is erased.

**Interfaces:** Consume actual final candidate SHA/API bytes, central immutable
admission, all Task1–5 changed-byte evidence and independently usable consumers.
Produce acceptance only for this host increment, with every later gate explicit.

- [ ] Bind destination paths/hashes/symbols for each of the three exact P source
  ranges in immutable selected-port receipts against the actual central admission.
  Explain ADAPT of the fixed donor predicate and descriptive enum separately
  from NEW glue. Preserve original native test obligations for later owners.
- [ ] Obtain independent review of API/error precedence, complete truth table,
  no authority reconstruction, per-field contexts, bounded codec/capacity/work,
  actual consumer copy, source/license correspondence and semantic sensitivity.
  An agent summary does not replace root inspection of actual outputs.
- [ ] Root runs affected canonical planning/intake/receipt checks, reviews exact
  final SHA evidence and records scoped acceptance if all required host checks
  pass. No historical green result validates changed bytes.
- [ ] Keep native H22/H33, finite kernel/distro/helper/license/cleanup cells,
  full bpf-host-v1, installed operator route, migration and publication open with
  existing owners. Do not close the full BP03 capability from model results.

Execution method is intentionally not selected in this design-only plan. Root's
final packet may select an already authorized method; this file does
not dispatch an executor/reviewer, create a worktree, run a command or commit.
