# CP04 insertion provenance and full-map host contract

Status: **CONTROLLER_RATIFIED_CONTRACT**, 2026-10-18. Root ratifies Astra P1-P5 and execution S1-S2. This freezes implementation choices and selected source admission; CP04 implementation and all live/ABI/profile qualification remain open. Original private preparation files remain immutable. The architecture binding root is `12c12d71be21f0d98ca8767567502c66e0c93543bc9d6fd366bba51b7eedded1`; execution supplement SHA256 is `a6b75a95ddef133d0652ae673eab32bfdf0167c6fababa749eddf62dafa3e2fc`, binding root `4e16b2a5fe0213999557d763db762add225d92dc13a049165919cbac7b1787be`. S1-S2 below govern the two amended details. The immutable task input index supplies the exact source-selection map and final base. Read with the [capture specification](2026-10-17-scopebase-capture-design.md), [CP04 plan](../plans/2026-10-17-scopebase-capture.md#task-cp04-insertion-frozen-provenance-and-survives-full-map-model) and [ratified decisions](2026-10-18-scopebase-decisions.md#cp04-insertion-provenance-rulings).

## Purpose, base and scope

Implement CP04's independently useful insertion-frozen provenance fold and shipped host migration/full-map regression fixtures in `scopebase-capture` 0.1.0. Base `b278205dde499418b0fd8c9df580de9d55d87c5c`; accepted CP02 subject `365a312c5673fa68ffcad7132970f0aefc1ab812` and CP03 APIs are prerequisites, latest accepted CP03 integrated subject `c145e28f1f8415da4172f9ab7b51e00f7e2c6391`. Required behavior: exactly one owner, valid zero identity, exact secondary counts, explicit saturated refusal, checked overflow, independent diagnostics despite full tables. All claims are T0/T1 host semantics and package delivery for this increment.

Applicable decisions: D01 mechanism/regression preservation; D02 independent component; D03 host/data license and separate authorization; D04 no implied target/runtime license evidence; D09 independent actual-consumer evidence; D10 plus the ratified P1-P5 in the [decision register](2026-10-18-scopebase-decisions.md#cp04-insertion-provenance-rulings); D11 no new dependency; D13 source custody; D14 honest incomplete gates. Only frozen KryProbe input is needed. Other donors' differing reducers/counter policies are retained in accepted CP02/CP03; none is selected as a CP04 port. Do not re-survey donors, change dependencies or invent broad runtime APIs.

## Exact public contract

Add `pub mod provenance;` to `src/lib.rs`. No root reexports. All struct fields and the lane's exact/saturated representation are private. The signatures below are exhaustive for this increment; declarations shown with semicolons denote signatures, not permission to ship stubs.

```rust
// scopebase_capture::provenance
#[non_exhaustive]
pub enum IdentityUnknown { NotObserved, Ambiguous, Exhausted }
#[non_exhaustive]
pub enum ObservedIdentity<I> { Known(I), Unknown(IdentityUnknown) }
pub enum LaneIdentity<I> { InsertionOwner(I), Secondary }
pub struct ProvenanceLane<I, U: Unit> { /* private */ }
pub struct InsertionFold<I, U: Unit> { /* private */ }

impl<I, U: Unit> ProvenanceLane<I, U> {
    pub fn new(identity: LaneIdentity<I>, count: Count<U>) -> Self;
    pub fn saturated(identity: LaneIdentity<I>) -> Self;
}
impl<I, U: Unit> InsertionFold<I, U> {
    pub fn identity(&self) -> &I;
    pub fn total(&self) -> Count<U>;
}
pub fn fold_insertion_identity<I: Eq + Clone, U: Unit>(
    lanes: &[ProvenanceLane<I, U>],
) -> Result<InsertionFold<I, U>, ContractError>;

// Append this payload-free variant to the existing non_exhaustive ContractError:
// SaturatedCount -- at least one encountered lane has no exact count due to
// explicitly reported saturation; no partial fold is returned.
```

Traits: `IdentityUnknown`: Debug/Clone/Copy/PartialEq/Eq. `ObservedIdentity<I>`, `LaneIdentity<I>`, `ProvenanceLane<I,U>` and `InsertionFold<I,U>`: Clone iff I:Clone; PartialEq iff I:PartialEq; Eq iff I:Eq; Debug for any I. No Copy, Default, Hash, Ord, serde or conversion impl is required for these four generic types. Use manual generic implementations where deriving would introduce U marker bounds. ObservedIdentity equality distinguishes Known/Unknown and unknown reasons; lane equality includes marker state plus exact versus saturated count, with exact values compared normally; fold equality compares identity and total. Debug may show variants/counts but never the identity payload or invoke its formatting. Do not implement unsafe Send/Sync or arbitrary error string contracts. Existing `ContractError` traits/non_exhaustive behavior remain.

Both constructors are infallible and consume their arguments without cloning. `new` declares an exact count, including MAX. `saturated` declares a nonexact count and retains the identity marker; it cannot later become an exact count. No count getter or partial/saturated result is exported. A donor-shaped adapter maps raw MAX to saturated and smaller raw words to new. BP02 owns the actual decoder; the CP04 adapter is only test/example source.

Validation order is normative:

1. Scan marker variants in original order. On the second owner return `ConflictingProvenance`. At end, absent owner returns `MissingProvenance`, including an empty slice. Identity value/equality and counts are not examined.
2. Scan counts from lane0. An explicit saturated state returns `SaturatedCount`; otherwise checked-add its Count to the running zero and return `ArithmeticOverflow` on overflow. Stop at the first count error in slice order.
3. Clone the unique owner's identity once, return that identity and the total. Do not clone on any Result error. Folding makes no Eq calls despite its retained Eq bound.

Required precedence table: empty/missing plus any saturation/overflow -> Missing; two equal or unequal owners plus any saturation/overflow -> Conflicting; unique owner and earlier saturated lane -> Saturated; unique owner and overflowing exact prefix before a later saturated lane -> Overflow. `[Exact(MAX-1),Exact(1)]` -> exact MAX; `[Exact(MAX),Exact(0)]` -> exact MAX; `[Exact(MAX),Exact(1)]` -> Overflow; a donor raw MAX at either marker state -> Saturated. A unique owner with all zero counts succeeds with zero total and no activity claim. Secondary counts may be positive. No numeric identity value is a sentinel. An invalid numeric marker2 cannot be expressed by LaneIdentity; do not use unsafe fabrication to pretend to test it. Retain BP02 raw-decoder ownership explicitly.

## Effects and bounds

Library-owned code reads the immutable slice, performs checked integer operations and builds an output; no I/O, system calls, locks, time/ID reads, global state, allocation proportional to lane count, async work or production table exists. For n lanes, at most two traversals, O(n) library work and O(1) auxiliary storage, excluding the output payload and caller-defined clone. Payload clone runs once on success, can allocate or have arbitrary caller-defined time/effects/panic; no byte, allocator, elapsed-time or hard interruptibility bound is promised. No Eq invocation occurs in folding; explicit equality trait calls have caller-defined I cost. Constructors move their payloads. ScopeBase does not mutate the supplied slice, lane wrapper fields or stored count states on success, Result refusal or unwind. Its marker/arithmetic validation calls neither payload Clone nor Eq. User-defined successful-path Clone may mutate the input payload or other state through interior mutability, allocate, block or panic; those effects cannot be rolled back. No payload immutability, UnwindSafe, Send or Sync guarantee is added. See S1 below for the required clone-panic control. Normal Rust allocation/abort behavior applies. Slice admission/retained input bytes belong to the caller. No implicit lane maximum is added to the public API.

Fixtures explicitly bound ncpu<=4, diagnostic slots<=2, table capacities<=2048, operation scripts<=2053 and identity payloads to fixed tuples/short literals. Validate fixture configuration before allocating/mutating. Fixture storage is O(capacity + ncpu*slots + script length); do not call those cardinalities exact heap-byte limits. No real scheduler/race semantics are claimed by scripted interleavings. Test/control processes require private output and ordinary bounded timeout/retirement evidence; a timeout is an incomplete result, never a semantic kill.

## Preservation and precise test populations

The implementer must keep the original source correspondence in `source-selection.json`, and create the selected-port receipt plus preservation record on the final candidate. ADAPT means the identified owner scan, ordered count refusal and winner-selection mechanism is retained; the small wrappers/error typing are NEW because VWho cannot represent arbitrary I/unit or separate exact MAX from donor saturation. Test models adapt actual PcpuWho/Sim* source; literal case shapes are VECTORS_ONLY. Do not describe latest-display policy, generic unknown reasons or brand-new independent oracles as donor ports.

`tests/insertion_provenance.rs` must contain the following named, independently asserted cases. Preserve each donor case rather than one representative scenario:

| Case | Input/setup and expected assertion | Original correspondence / sensitive wrong control |
|---|---|---|
| `migration_keeps_inserting_identity` | Owner `(uid1000,cgroup123,parent12,stack7)` on laneA, laneB initially zero/unmarked, then one hit each; exact total2 and original tuple | ABI unique-mark regression; WHO migration / take latest or secondary identity |
| `single_cpu_control_keeps_identity` | One owner, two hits on laneA, idle laneB; identity unchanged,total2 | WHO single-CPU twin / drop owner counts |
| `migration_under_change_keeps_insertion_identity` | Second hit carries different thread/command/display identity99; model latest display changes, production identity remains insertion tuple | WHO changed-context / refresh owner on hit |
| `race_loser_never_marks` | Script winner and losing insertion; loser lane is zero before its hit and remains Secondary after; both counts included | WHO NOEXIST race / mark losing lane |
| `unrelated_secondary_zero_does_not_replace_identity` | One owner and three secondary zero identities/stack fields; four hits total4, stack7 preserved | WHO unrelated stack0 / infer first nonzero or latest identity |
| `zero_identity_is_known` | Marked genuine uid0/stack0 is Known; same unmarked data fails Missing; owner3 + secondary7 =10 | Both zero regressions / zero-as-missing |
| `missing_owner_refuses` | Empty, idle unmarked, busy unmarked and malformed-count unmarked populations -> Missing | ABI + WHO missing / use first lane or count error first |
| `two_equal_owners_still_conflict` | Equal payload owners and unequal payload owners, including saturated/overflow counts -> Conflicting | ABI + WHO conflict / deduplicate equal owners |
| `secondary_counts_are_conserved` | Positive counts on owner at each position and all secondary positions; unique owner may have zero | Original checked sum / owner-only or skip-zero-owner fold |
| `explicit_saturation_and_exact_max_are_distinct` | Generic exact MAX succeeds alone; raw donor MAX on owner/secondary refuses Saturated; MAX-1 plus1 succeeds in both paths; MAX-1 plus2 overflows | ABI saturated calls + new boundary twin / drop sentinel or ban generic MAX |
| `owner_errors_precede_count_errors` | Cross-product 0/1/2 owners, ordinary/saturated/overflow count profiles; exact error table above | Original two passes / arithmetic first |
| `count_errors_follow_lane_order` | Exact MAX,1,saturated -> Overflow; saturated,Exact MAX,1 -> Saturated, unique owner fixed | Original ordered count loop / pre-scan all saturation |
| `payload_clone_and_equality_contract` | Tracking clone count and an Eq implementation that panics if called; valid fold clones1, every Result error clones0, fold never calls Eq; Clone panic preserves library-owned wrapper/count fields and borrowed access; caller interior-mutable effects remain visible | NEW generic cost boundary / eager cloning or owner equality |
| `generic_traits_and_redacted_debug` | I without Debug, Unit generic helper with no marker bounds; Debug must not include a secret payload or call its Debug; distinct unknown reasons remain distinct | NEW generic wrappers / deriving unwanted bounds or leaking payload |

Independent oracle: enumerate n=0..4 lane positions; identity variants Secondary, Owner0, Owner7; counts 0,1,2 plus a literal boundary corpus. Compute owner indices by collecting test metadata (not payload equality), and expected exact total by u128 sum. Match saturated/prefix-overflow precedence using separately generated literal ordered-error cases, not by calling production. Positive and active-negative populations must be created from independent metadata; adapter output cannot create the oracle. Include all owners at every position, equal owners and boundary exact-MAX twins. Fix enumeration and literal expected rows in test source; no random retries or dependency acquisition.

`tests/support/cp04_model.rs` adapts the selected donor PcpuWho and Sim* code into private-to-tests models; `tests/full_map_loss_contract.rs` supplies:

| Case | Setup/trigger proof | Independent expected result |
|---|---|---|
| `full_table_signal_survives_repeated_failure` | Capacity1, five distinct operation IDs; first identity inserted, operations2..5 each refuse and leave size1; diagnostic preallocated outside table | Literal failed IDs `[2,3,4,5]`, aggregate total5, signal4, local partial=true |
| `below_capacity_control` | Same script capacity5; all five inserted | No failures, total5, measured signal0, local partial=false |
| `preexisting_signal_survives_and_caps` | Initial signal254, four scripted new-key failures from full capacity1 table | Failure ledger4 plus stored signal255; no exact-omission conversion |
| `historical_full_identity_and_who_maps` | Gate256 full without a reserved diagnostic entry; attribution table2048 distinct `(kh,tgid)` keys then a new key; assert both capacities and failed key absence | Attempt ledger2049, aggregate counters each2049, one independent signal, local partial=true |
| `historical_below_capacity_twin` | Gate128 and attribution128 below original limits | Total128, measured signal0, local partial=false |
| `existing_key_at_capacity_is_not_a_failure` | Full table receives its already retained key | Size unchanged, aggregate advances once, no new diagnostic |
| `failed_insert_is_atomic` | Snapshot keys/owner lanes before rejected new insertion | Keys and identities unchanged; separate counter/signal reflect operation |
| `cross_lane_failure_slots_are_independent` | Failures in two CPUs/two model slots, preallocated before table filling | Scripted per-slot counts and actual CP03 fold agree; no real ordinal/layout claim |

The failure oracle starts from the immutable operation journal and literal failed-ID population; it never infers failure count from the model's diagnostic field or the model's return vector. Assert the historical full-table preconditions before calling the read under test. Call accepted `loss::fold_capped_signals(&[u8], 255)` to observe signals. The local partial boolean illustrates donor policy only; it is not a public Complete/Partial contract.

## Semantic controls and portable fixture delivery

Ship `tests/support/check_cp04_controls.py`, using CP03's existing disposable-copy, actual-compilation, process-retirement and restored-twin conventions. It must edit only its disposable copy and never alter selected source/donor files. A control passes only after valid setup, compilation, test execution and failure at the named semantic assertion, followed by a restored pass on the same population. Required controls: first-lane identity, last/secondary identity, zero-as-missing, owner deduplication, race-loser mark, hit refresh, owner-only tally, saturating/wrapping total, ignored saturated flag, raw-MAX treated exact, generic-MAX refused, arithmetic-before-ownership, global saturation prescan, eager-clone, Debug payload disclosure, and lazy loss stored in already-full table. Some controls target production; race/refresh/lazy-loss target the shipped producer fixture, and are reported as such. Do not imply a production mutation for test-only code. Keep an explicit mutant-ID -> edited path -> named test/assertion -> restored result table. An anchor mismatch, compile error, crash, unretired process or zero reached assertions is INVALID_CONTROL.

The lazy-loss control must actually attempt to add a diagnostic marker to the same already-full gate/table, observe insertion refusal and read absent-as-zero. It must reach `full_table_signal_survives_repeated_failure` and `historical_full_identity_and_who_maps` loss-presence assertions after confirmed capacities, preserving aggregate totals. Merely returning zero directly is not the historical control. The restored independent-slot model must pass both and the below-capacity twins.

Author the sole authoritative corpus at `crates/scopebase-capture/fixtures/insertion-v1.json`. Generate the planned root path `fixtures/capture/insertion-v1.json` by byte-for-byte copying that delivered corpus; the root path is a compatibility mirror, never independently edited truth. Source verification fails if the mirror differs. Archive verification consumes only its own delivered corpus and requires no root checkout. This is a bounded CP04 host-vector artifact, **not** CP10's future replay format or decoder. Freeze schema1: root keys `schema_version=1`, `kind="cp04-host-vectors"`, `cases`; case keys `id`, `lanes`, `expected`; lane keys `identity` (null for secondary, or array `[uid,cgroup,stack]` of canonical decimal strings), `count` (canonical decimal u64 string for exact, or string `"saturated"`); expected is either `{ "identity": [decimal,decimal,decimal], "total": decimal }` or `{ "error": "MissingProvenance"|"ConflictingProvenance"|"SaturatedCount"|"ArithmeticOverflow" }`. UID range u32, cgroup u64, stack signed i32 (canonical minus allowed only for negative stack); known all-zero identity remains an array, never null. Read at most65537 bytes and reject files above65536 before JSON parsing. Catch decoding/recursion failures as invalid corpus, with no generated code. Require exact JSON scalar kinds (booleans are not integers), UTF-8 and the specified required keys. Bound cases<=128, lanes/case<=8, unique IDs of 1..64 ASCII alnum/underscore/hyphen. Required case IDs are empty, busy_missing, equal_owners, unequal_owners, zero_known, secondary_sum, exact_max, exact_max_zero, sum_equals_max, sum_overflow, saturated_owner, saturated_secondary, missing_beats_saturated, missing_beats_overflow, conflict_beats_saturated, conflict_beats_overflow, overflow_before_saturated, saturated_before_overflow, zero_activity_owner, and owner_last. Each ID must retain the input and literal expected meaning named by the contract above; the checker must reject a missing required population, and reviewers must compare the actual rows to those meanings. Additional bounded rows are permitted. Reject duplicate JSON object members, unknown fields, invalid scalar/type/range, noncanonical numeric strings, duplicate IDs or excess limits in the test helper before generating code.

The standard-library Python controls helper uses json.loads with duplicate-member detection and rejection of nonstandard numeric constants, validates only this bounded schema, and creates a temporary Rust integration target with constructors and literal assertions over the **actual selected package bytes**; its expected values come directly from the fixture, not production execution. This avoids a new default/dev JSON dependency and keeps the file exercised in every feature cell. Generate every inserted Rust token only from admitted bounded numeric values or a closed vocabulary. Use fixed indexed test names such as vector_000; never insert raw JSON text, case IDs, labels or diagnostic strings into code. IDs belong only in the bounded evidence index. Other than closed error/constructor vocabulary and fixed indexed names, generated test source receives only range-checked numeric literals. Error variant names come from the fixed whitelist. Compile the positive generated target and semantic mutants using the explicit execution mode in S2 below; coordinated normal cells pass the per-call wrapper. Bind JSON hash, generated-target hash, compiler and subject in the evidence. Source/archive mirror equality is mandatory. Ordinary package integration tests remain runnable independently; this Python command is an additional delivered vector/control route, not an installed operator/conformance API.

The shipped helper has three explicit modes; only `run` supplies execution evidence. `sync-mirror --source-root ABS_PACKAGE --root-mirror ABS_ROOT_FIXTURE` validates the authoritative package corpus then writes its exact bytes to the named approved mirror. `check-fixture --source-root ABS_PACKAGE [--root-mirror ABS_ROOT_FIXTURE]` validates the schema/required population and, when supplied, exact mirror equality; it is parsing/custody evidence only. `run --source-root ABS_PACKAGE --cargo ABS_CARGO --rustc ABS_RUSTC --feature-set no-default|default|json --output-dir ABS_NEW_OUTPUT [--root-mirror ABS_ROOT_FIXTURE] [--build-wrapper ABS_EXISTING]` performs those checks and executes generated actual-package assertions plus mutants/restored twins. It requires absolute non-donor source paths, fresh output outside source and pinned existing compiler paths, following CP03's process/copy guards. Package README documents this exact regeneration/check pair from a source checkout:

```sh
python3 crates/scopebase-capture/tests/support/check_cp04_controls.py sync-mirror --source-root "$PWD/crates/scopebase-capture" --root-mirror "$PWD/fixtures/capture/insertion-v1.json"
python3 crates/scopebase-capture/tests/support/check_cp04_controls.py check-fixture --source-root "$PWD/crates/scopebase-capture" --root-mirror "$PWD/fixtures/capture/insertion-v1.json"
```

These are planned commands for the new delivered helper, not claims that it exists yet. Archive `run` omits root-mirror and executes against its own corpus. Generated tests must call `fold_insertion_identity` in the selected package and compare its returned variant/identity/count against the literal expectation; parsing, code generation, text comparison or successful compilation alone is not execution of that fixture. Before generating Rust, the run mode checks a bounded malformed-corpus population: duplicate member, unknown key, missing required key, missing required case, duplicate ID, bool/type mismatch, numeric overflow/noncanonical string, over-limit bytes/lanes/cases, and attempted arbitrary Rust text in numeric/error/ID fields. Each must refuse with no generated test or Cargo call, and the valid restored corpus must proceed. Record these as fixture-input validation controls, separate from product semantic mutations. Keep the independently generated arithmetic/owner oracle and semantic bad/restored populations in addition to the literal corpus. A fixture-only generated target never supplies its own expected results.

## Two independent package consumers

Ship `examples/insertion_journal.rs`: a KryProbe-shaped caller with tuple identity and Events; independent insert/hit journal produces raw lane words, converts raw MAX explicitly and folds; literal expected owner/total, zero identity and saturation refusal are checked. Keep latest display local. Ship `examples/cache_attribution.rs`: a distinct cache caller with String identity and Objects, its own finite insertion/retry reducer and independent attempted-key ledger; exact MAX remains valid for a supplied exact summary, failed detail inserts produce separate capped diagnostics without changing aggregate counts. It must not import the first example, tests/support, testkit or a shared expected-result reducer.

Run each both as a packaged example and as the sole main.rs in its own fresh external workspace/Cargo.toml/Cargo.lock, resolving `scopebase-capture = { path = ACTUAL_SUBJECT, version = "=0.1.0", ... }`. Verify Cargo metadata selected exactly that source or extracted archive path and feature set. Bind client sources/lockfiles, output assertions and subject hashes. These are actual but bounded API consumers, not CP11 full application consumers or MG03 migration.

## Sole-writer paths and provenance

Implementer owns only these agreed paths; root may serialize a shared-file handoff before dispatch:

- New `crates/scopebase-capture/src/provenance.rs`; append-only variant change `src/error.rs`; `src/lib.rs` module/docs; package `Cargo.toml` include additions only; `README.md`, `THIRD-PARTY-NOTICES.md`.
- New package `tests/{insertion_provenance.rs,full_map_loss_contract.rs}`, `tests/support/{cp04_model.rs,check_cp04_controls.py}`, `tests/ui/{cp04_units_match.rs,provenance_units_do_not_mix.rs}`, `fixtures/insertion-v1.json`, and `examples/{insertion_journal.rs,cache_attribution.rs}`.
- Generated mirror `fixtures/capture/insertion-v1.json`; `docs/issues/capture/insertion-loss.md`; narrow updates `docs/issues/capture/{donor-manifest.json,contract-map.md,provenance.md}`; `docs/provenance/ports/{CP04-20261018-insertion.json,CP04-preservation-20261018.md}`.
- New `tests/package-policy/cp04/check_cp04.py`: bounded affected-capture wrapper adapted from the existing CP03 runner. Keep shared build/policy helpers unchanged; preserve all existing capture package files and append CP04 additions in its private projection. If a shared helper change is necessary, return NEEDS_DECISION rather than silently widening the lane.

Root owns canonical spec/plan/D10, `docs/provenance/donors.json`, immutable admission `docs/provenance/admissions/2026-10-18-cp04-insertion.json`, root TODO/traceability/navigation/status/acceptance and any required tracked package-policy update. Worker may prepare their exact scoped data but cannot self-admit grants or close tasks. Root Cargo.toml/Cargo.lock, other crates, donors and preexisting CP02/CP03 tests/controls stay outside this implementation ownership. If an existing file needs a substantive correction, report the reason and let root amend ownership. Prior receipts are immutable; if their destination hashes actually change, issue bounded successor receipts rather than rewriting history.

Source license mapping: existing rows identify these source files as user-owned, historical GPL-3.0-or-later, `OWNER-2026-10-18`, no third-party terms recorded. The [immutable CP04 admission](../../provenance/admissions/2026-10-18-cp04-insertion.json) records these exact scope extensions; it is an input grant, not a completed port. Destination host, test and fixture source is Apache-2.0 under that existing owner policy. Preserve historical observation and source symbol hashes in notices/receipts; do not copy kernel upstream source, target layout or GPL source license strings into an invented shared grant. Full source/remainder boundaries are `source-selection.json`.

## Verification commands and selection

All commands in this section are **planned, NOT_RUN by preparation**. Root ratification/admission is recorded here; an immutable isolated task checkout precedes execution. Worker runs focused tests while developing, then one exact-candidate affected campaign; failed controls retain their evidence. Use a new private path outside the checkout, one shared heavy-build slot, and no nested `scopebase-build` lease. `SCOPEBASE_RUN` is a task-specific absolute private job path chosen by root, not a path under the worktree. The runner acquires per-command leases and may use one outer lease only for the accepted baseline policy subphase, following CP03.

```sh
bin/scopebase-build -- cargo test --locked --offline -p scopebase-capture --no-default-features --test insertion_provenance --test full_map_loss_contract
python3 tests/package-policy/cp04/check_cp04.py --output-dir "$SCOPEBASE_RUN"
python3 tools/check_planning_docs.py
python3 tools/planning/check_traceability.py docs/superpowers/plans/2026-10-17-scopebase-traceability.json
git diff --check
```

The focused `cargo` resolves through the repository's accepted pinned toolchain setup; the final runner uses absolute Cargo/rustc paths from the bound root package policy: Rust1.88.0 and1.98.1, x86_64-unknown-linux-gnu. Use a private target and existing offline dependency input; never install a toolchain or fetch dependencies. Root additionally runs `python3 tools/planning/check_traceability.py docs/superpowers/plans/2026-10-17-scopebase-traceability.json --port-receipt docs/provenance/ports/CP04-20261018-insertion.json`; this accepted local receipt check does not visit donors.

Final campaign follows CP03's six affected capture archive compiler/feature cells and twelve supplemental cells (source/archive × both compilers × no-default/default/json). Run existing package tests/doctests and CP02/CP03 examples/UI refusals; run both CP04 examples and independently locked clients, generated fixture target, primary-diagnostic new unit refusal and CP04 semantic mutants/restored twins in **all twelve**. New refusal must be E0308 on the cross-unit lane argument at the expected primary source span, with a compiling same-unit twin; setup/compiler-only failures do not count. No U marker trait requirements may leak. Preserve old source/control hashes, previous CP03 mutation receipts and selected-port maps. Previously accepted CP03 mutants need not be repeated when their production inputs/controls are byte-identical; if changed, root selects their affected controls explicitly and updates receipt lineage. Do not overwrite or relabel the prior 636-mutant/1044-restored campaign as CP04 evidence.

Build the actual cargo archive, inventory every delivered file, verify source/archive content including Cargo.toml.orig and fixture mirror, and bind exact current package metadata/dependencies/feature sets. The root runner must preserve all four registered workspace members and report the other three packages omitted, with their unchanged-input evidence; six affected cells are not a new twenty-cell matrix. No new registry dependency or feature is allowed. Run planning/provenance checks after documentation changes; run orchestration/planning/package-policy helper unit suites only if their owned implementations actually change or root names an admission coverage gap. Inspection/hashing, these tool tests and host fixtures are distinct evidence tiers.

Independent reviewer: fresh Astra architecture/adversarial review of typed saturation, ordered refusals, cardinality/zero semantics, clone/privacy traits, original regression correspondence, source/license boundaries, oracle sensitivity, actual archive/client binding and honest test-only producer limits. Root checks every selected-port mapping against final candidate hashes, required commands/semantic assertions/restored twins, archived delivered tests and unchanged predecessors before acceptance. A worker DONE is not acceptance.

## Exit and later work

Accept only CP04's host increment once all listed behaviors, shipped tests/vectors/controls, two bounded consumers, source admission/selected-port receipt and affected evidence are complete. Missing required cells remain incomplete. Preserve CP04 prerequisites CP02/CP03 and CP10's dependence on CP04. No new IDs or inventory counts are necessary. H15 host insertion subset and H17 host full-map subset gain exact evidence; their live/ABI families remain open. UC14/G18-G20/G22 and CP-R16/17 remain later as mapped by the existing specification.

Root TODO must retain or make explicit these capability/dependency/exit items within existing tasks: BP02 raw marker2 plus exact wire stride/all consumers and raw-saturation decoding; BP07 actual winner/loser/migration/full-map/reentry producer tests with independently expected live activity; CP05 explicit nonjoinable unknown/generation histories; CP06 persistent/exactly-once loss; CP10 strict neutral mapping of explicit saturated lanes (do not encode saturated as exact MAX); CP11 independent actual application reducers; CP13/TT source-free installed exact-consumer conformance; MG03 exact-version product adoption and duplicate-retirement checks. No unimplemented stubs are added for these obligations. Retirement of a donor duplicate requires a later actual consumer migration and its original producer/ABI/product policy tests, not this host increment.

## S1. Precise unwind and input-mutation boundary

Replace the original packet's broad “Inputs are unchanged on refusal/unwind” statement with:

> ScopeBase does not mutate the supplied slice, lane wrapper fields or stored count states, on success, Result refusal or unwind. Its marker/arithmetic validation invokes neither payload Clone nor Eq. On a successful validation path it invokes the winning payload's Clone once. That user-defined Clone can mutate the input payload or other state through interior mutability, allocate, block or panic; ScopeBase cannot roll back those effects or promise that the payload is unchanged after unwind. Ownership and access remain subject to ordinary Rust borrowing/unwind rules. No additional payload immutability, UnwindSafe, Send or Sync guarantee is introduced.

The clone-panic test asserts unchanged library-owned marker/count structure and continued borrowed-input access after a caught panic where the test explicitly uses the appropriate Rust unwind boundary. It must not assert that arbitrary payload state was unchanged. Include a payload whose Clone deliberately changes an interior-mutable counter before panicking: the effect remains observable and is documented as caller behavior. Keep the zero-clone-on-Result-error and zero-Eq-call assertions. This is a correction of a guarantee's scope, with no new public API or change to P1/P2 error ordering.

## S2. Optional wrapper and actual standalone archive execution

Extend only the new CP04 helper's `run` command:

```text
run --source-root ABS_PACKAGE --cargo ABS_CARGO --rustc ABS_RUSTC
    --feature-set no-default|default|json --output-dir ABS_NEW_OUTPUT
    [--root-mirror ABS_ROOT_FIXTURE] [--build-wrapper ABS_EXISTING]
```

`--build-wrapper` is optional, explicit and run-only. When supplied, require an absolute existing executable regular file, bind its path and SHA256, and form each Cargo argv as `[wrapper, "--", cargo, ...]`. An invalid supplied wrapper refuses before launching Cargo. When omitted, form argv as `[cargo, ...]`; there is no ancestor-checkout search, PATH wrapper search, environment-variable wrapper fallback, plugin dependency or requirement for `bin/scopebase-build`. In particular, inherited `SCOPEBASE_BUILD_WRAPPER` does not change direct mode. The helper's own imports and fixture/code-generation operations use only shipped files and the Python standard library. Ordinary test executables and compiler-identity reads retain their existing explicit process handling; this option changes Cargo command routing only.

Our coordinated twelve-cell source/archive campaign always supplies the explicit common wrapper. It must not wrap the entire CP04 helper in another build lease in that mode. The accepted baseline policy subphase keeps its existing separately owned outer-lease arrangement; it does not enclose this per-call-wrapped helper. All earlier required actual fixture assertions, semantic mutants and restored twins remain required in their existing cells.

For standalone use, the default executes the selected Cargo/rustc directly, using only the archive, pinned installed tools, Python and explicitly supplied existing offline dependency inputs. No toolchain/dependency installation, network acquisition, `cargo install`, `rustup`, repository search or configuration discovery in a ScopeBase checkout is permitted. The optional JSON dependencies retain their current locked versions and feature semantics. An unavailable required offline dependency is a setup failure, never a semantic control result or reason to install it. Ordinary standalone callers own their build scheduling; direct mode itself does not claim a coordinator lease.

### Private outputs and process custody

Keep the sealed packet's absolute-source, no-donor, fresh-output, outside-source and no-symlink guards. Validate source/corpus/compiler/wrapper arguments before starting Cargo. Never mutate the input archive extraction. Copy the selected package into the fresh owned output subject, record source and copied hashes, and modify only that disposable subject for generated targets/mutants/restoration. Keep targets, generated lockfile, generated Rust, logs, scratch/home and reports under the private output. Preserve failures and all restored-twin records. Never delete another run's outputs or conceal a partial run by reusing its directory.

Offline Cargo input remains an explicit prerequisite as in the existing helper: use the admitted Cargo-home/config/source inputs supplied by the caller, bind their selected paths/config hashes, and keep the task target and subject lockfile private. For our standalone archive proof, provide a private Cargo home whose bound configuration refers to the already admitted offline dependency source inventory; that input is not an unpublished executable/helper checkout dependency. Do not fall back to the user's default Cargo home or ambient checkout `.cargo` configuration when the declared input is unavailable. Run the disposable subject outside repository ancestors and pass explicit manifest/target/compiler paths, so root-workspace configuration cannot make the standalone route succeed accidentally. Dependency cache/index locks, where applicable to a caller-supplied cache, do not authorize changing dependency selections or acquiring missing source.

Launch each command with explicit argv, cwd and the bounded selected environment, no shell. Keep `CARGO_NET_OFFLINE=true`, pinned `RUSTC` and corresponding installed `RUSTDOC`, explicit private target and no toolchain shim selection. Before semantic execution, bind compiler identities/hashes and verify the actual selected package manifest/features in Cargo metadata. The helper remains alive while its child command runs. Each launched command has an owned process group and recorded stdout/stderr, start/end, exit status, timeout and retirement result. Retain the existing bounded command timeout (120 seconds) and bounded retirement wait (10 seconds); timeout or failure to establish retirement is incomplete/INVALID_CONTROL, never a semantic kill. Handle ordinary interruption through cleanup/finalization of the current owned group before returning; if cleanup cannot be established, retain the unresolved record and stop, without retrying or releasing a claimed-success report. Arbitrary host failure or forcibly killed helper is not promised crash-proof cleanup.

### Report and route evidence

The CP04 helper report must add:

- `command_mode`: exactly `direct` or `wrapped`, selected solely by the explicit option.
- `build_wrapper`: null in direct mode; otherwise `{path,sha256}` for the selected wrapper.
- Actual argv and mode on every Cargo command row, plus actual pinned compiler paths/hashes, selected environment/config bindings, subject manifest/features, source/archive hash, authoritative corpus hash and generated-target hash.
- A statement that the helper does not acquire or verify an outer coordinator lease. An outer proof may be attached by the controller, but the helper cannot manufacture one from an environment flag or a report field.

The existing valid-setup, actual-assertion-failure and restored-success criteria remain unchanged. Code generation, compilation, empty execution or text comparison cannot substitute for actual calls into the selected library. Explicit-wrapper invalid-path rejection and direct-mode operation with an inherited unusable `SCOPEBASE_BUILD_WRAPPER` must be checked as routing cases, separate from product semantic mutations. The latter confirms that the old ambient wrapper fallback was not inherited accidentally.

### One additional real archive proof

After the exact candidate archive exists, run **one** additional full CP04 helper campaign from that actual extracted archive with Rust1.88.0/no-default, direct mode, a new private output and no root mirror. Run it under **one outer coordinator lease**, with all child Cargo commands direct. Root's launcher may use the repository wrapper to acquire this outer lease; the archive helper must not locate, import or invoke that wrapper itself. This proves the archive helper's delivery path while respecting our current shared-host scheduling.

The controller supplies existing absolute paths and an already prepared private offline Cargo home. Planned command form:

```sh
"$CP04_COORDINATOR_WRAPPER" -- /usr/bin/python3 "$CP04_ARCHIVE_ROOT/tests/support/check_cp04_controls.py" run --source-root "$CP04_ARCHIVE_ROOT" --cargo /home/user/.rustup/toolchains/1.88.0-x86_64-unknown-linux-gnu/bin/cargo --rustc /home/user/.rustup/toolchains/1.88.0-x86_64-unknown-linux-gnu/bin/rustc --feature-set no-default --output-dir "$CP04_STANDALONE_OUTPUT"
```

These variables name task-specific absolute paths. The controller sets `CARGO_HOME` to the prepared private offline input and launches from a fresh private directory outside all repository ancestors. It deliberately omits `--build-wrapper` and `--root-mirror`; setting `SCOPEBASE_BUILD_WRAPPER` to an unusable path for this proof is allowed and should be recorded to prove it cannot affect mode. The outer launcher binds its wrapper and `tools/build_lock.py` identities and records successful owned invocation/termination. The helper's Cargo rows must contain direct pinned Cargo argv, no wrapper or nested lease. The proof must execute the delivered corpus target, all CP04 required product/model controls and restored twins; it is not a parsing-only smoke test. Preserve its separate report, archive/corpus/client/generated hashes and actual semantic assertions. It supplements, rather than replaces or inflates, the six affected archive cells / twelve normal supplemental cells.

All commands here are planned, **NOT_RUN by this preparation**. A normal direct caller needs no coordinator wrapper at all. Our single outer lease exists solely for the current host's shared-build discipline.

## Unchanged scope and later delivery work

No other CP04 API, source scope, fixture schema, dependency, license or ownership decision changes. The full-map/migration helper remains test-only; no live BP02/BP07 claim follows. Sealed P1-P5 and source grants are untouched. Preserve CP03's existing script and accepted evidence without rerunning its production/control campaign. Root retains its standalone-wrapper limitation under TT07/CP13 until the separately owned delivery repair ships and verifies an actual archive route. This supplement creates no replacement orchestration framework or new product task ID.
