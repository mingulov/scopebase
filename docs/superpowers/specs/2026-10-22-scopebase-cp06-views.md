# CP06 scoped views, required feeds and replacements — ratified exact r3 contract

Date: 2026-10-22. **RATIFIED_DESIGN_ONLY; CP06 remains PLANNED, NOT_PACKET_READY, with implementation not admitted and CP06 product execution NOT_RUN.** Root ratified exact r3 index `802d8b81f2f3acf3a2f331cc0daf07b569955cb270599bca0a5b71b92915be11` after full r2 review `1b430409fc671eb90af0401f3ad5d6c9b9d388731a07418dcd4c3927dd004a48` and scoped r3 follow-up `ad89e98fa5c74a4c79df3ef465509c746cf68261f3eae82ab17049bb8d3551de`. The follow-up closes CP06-DR1-01/02 as authoring obligations: constructor reserve/error/order controls and the V06 outsider ID3 bound. The [support and immutable lineage](cp06-views/README.md) preserve D1–D9, 25 case IDs, fifteen original subsets, 29 source ranges and every finite population. Administrative status/path changes leave the literal API/private-layout/D9 Rust blocks unchanged.

CP03 and CP05 are accepted prerequisites. CP05 is now accepted at `7d992e12bd73519610e5b2eac7866993fe83ac16`, with root acceptance SHA256 `e6f5f5624e831fdf8401f8a7bc3e6d59d2737f60f5f01ddd3b596fd5715e7f9b`; see the [accepted package record](../../reviews/2026-10-22-cp05-generations.md). The byte-exact historical support JSON retains its then-unbound CP05/review wording; this current administrative header records the later acceptance and design ratification without rewriting those receipts. The exact D9 prototype prerequisite is now **SATISFIED ONLY FOR THE NARROW DELTA AND BOUND INPUTS** under the reviewed root successor; actual product/source/archive privacy/API/dyn/compiler checks, quantity-port successors and execution-packet/resource gates remain open. Actual final base, export/shared `quantity.rs` ownership, source-port successors, dependencies/features/lock, fixtures/oracles/clients, tools/cache/resources and outputs remain unbound. Source admission `f4a9a406053bedebb26b501374b106de035df62780e381cdd836ba0d3ea166a2` preserves predecessor e29 as source selection only: no copy, port, PACKET_READY, product acceptance or passing test follows.

**Governing D9 successor and evidence status:** The [narrow D9 supplement](cp06-views/d9-private-unit-successor.md), rooted in exact decision `be515440a286e60201362585243c0350fc548dacf30df31c5dce2ebb52d0e42b`, governs the historical D9 declaration-only allowance, verification Task0 Step3 and U01 allowance wording. It adds only `#[allow(private_interfaces)]` to the exact seven macro-generated `Sealed::unit_tag` implementation method declarations, alongside the original trait-method declaration allowance and existing `private_bounds` allowance. It adds no blanket allowance or public tag/token. The original r3 body and code blocks below, and the fourteen original support JSON files, remain exact historical design snapshots; their declaration-only/UNRUN/UNBOUND D9 wording is superseded only as specified by this supplement. Strict prototype r1 actually failed; default-policy r2 supplies semantic/privacy evidence only. Amended r3 ran 22 commands across Rust 1.88.0/1.98.1, with twelve intended refusals, two positive compiler/runtime cells and two widened-gate compile controls; independent review index `6819cbe016b5f70d4241c49cea03389cc57fe42dd6f7c2b5188a058ada7e815f` supports root adoption. Warnings denial applies to prototype libraries; external clients were warning-free, with no global `-D warnings` claim. This satisfies only the exact-bound-delta prototype prerequisite, not actual package qualification, implementation admission or PACKET_READY.

**Current migration-owner override:** CP11 owns library/reducer regression preservation. Actual OSSLscope migration, protected per-TID correction history and the original real 5,000-foreign-close application control belong to **MG02**; actual KryProbe migration belongs to **MG03**; actual MemVeil migration, pool pressure, independent-copy and retired-history application controls belong to **MG04**, with accepted CP05 as the retired-history prerequisite. Later MG03 shorthand preserved in the ratified body and immutable JSON is historical and does not assign OSSLscope/MemVeil application ownership. All three migration tasks remain planned; their completion does not gate independent CP06 component qualification.

## WHAT and WHY

CP-R07/CP-R11/CP-R13/CP-R18 require three independently usable pure components: per-claim consumed evidence with immutable query overlays, declared required feed cardinality, and checked next-revision replacement of one caller-associated value. The application supplies claim dependencies, identities and correction routes. Empty reasons describe only absence of recorded reasons; feed presence does not prove absence of loss; epoch/revision does not identify an application target.

Preserve M's non-destructive partial-view fix `15e07cd1189da84f4e3fd3e12b793666b44974f3`, K's exactly-once shared feed `b250067f9b604dd7329f1ee37cb7fcf839bd88d1`, and O's delivered-holder correction fix `18ee661ce0247e2c1c2ed1329a9cbb72a6ded149`. M independent-copy fix `24defdd2317bdbd747751951bc2cf5a79cebfb77` stays reference/deferred real-reducer evidence. The frozen source map retains all 10 files/29 proposed ranges and all 15 original subsets; no whole-file grant or port is asserted. Root adopted source selection at integration `3a4b73e94da8f2f4600fe5a33ee84b2a895ef258`: `docs/provenance/admissions/2026-10-22-cp06-scopes.json`, SHA256 `f4a9a406053bedebb26b501374b106de035df62780e381cdd836ba0d3ea166a2`, with navigation `docs/provenance/cp06-scopes-20261022.md`. The earlier e29cc889 admission and all original evidence remain preserved. This binds the same 29 selected ranges/747 lines as source selection only; no source copy, destination correspondence, execution or task acceptance follows. No intake was reconstructed or reapplied here.

The existing public API is retained verbatim in meaning:

```rust
pub enum QualityReason { ConsumedLoss, MissingEvidence, QueryPartial, Ambiguous, Capacity }
pub struct LedgerLimits { pub claims: usize, pub reasons_per_claim: usize, pub loss_facts: usize }
pub struct ClaimAssessment { /* private claim and reasons */ }
impl ClaimAssessment { pub fn claim(&self) -> ClaimId; pub fn reasons(&self) -> &[QualityReason]; }
pub struct QueryOverlay { /* private */ }
impl QueryOverlay {
    pub fn new(partial_claims: &[ClaimId], max_claims: usize) -> Result<Self, ContractError>;
}
pub struct ClaimLedger { /* private */ }
impl ClaimLedger {
    pub fn new(epoch: Epoch, limits: LedgerLimits) -> Result<Self, ContractError>;
    pub fn record_loss<U: Unit>(&mut self, fact: &LossFact<U>, affected: &[ClaimId]) -> Result<(), ContractError>;
    pub fn record_signal(&mut self, fact: &CappedLossSignal, affected: &[ClaimId]) -> Result<(), ContractError>;
    pub fn snapshot(&self, selected: &[ClaimId], overlay: &QueryOverlay) -> Result<Vec<ClaimAssessment>, ContractError>;
}
pub struct FeedRegistry { /* private */ }
impl FeedRegistry {
    pub fn new(epoch: Epoch, required: &[ChannelId], max_feeds: usize) -> Result<Self, ContractError>;
    pub fn feed<U: Unit>(&mut self, fact: &LossFact<U>) -> Result<(), ContractError>;
    pub fn finish(&self) -> Result<(), ContractError>;
}
pub struct Revision(u64);
pub struct Versioned<T> { /* private */ }
pub struct Correction<T> { /* private */ }
impl Revision { pub fn new(value: u64) -> Self; }
impl<T> Versioned<T> {
    pub fn new(epoch: Epoch, value: T) -> Self;
    pub fn revision(&self) -> Revision;
    pub fn value(&self) -> &T;
    pub fn apply(self, correction: Correction<T>) -> Result<Self, (Self, ContractError)>;
}
impl<T> Correction<T> {
    pub fn new(epoch: Epoch, from: Revision, replacement: T) -> Result<Self, ContractError>;
}
```

Declarations in this design are not implemented exports. Add no public UnitKind, dynamic unit conversion, default, setter, serde format, tag-audit accessor, source authority, fact-ID issuer, tracker, correction history, broadcaster, feed total or completeness conversion.

## Exact private representation

Use ordinary Rust layout, no `repr`/wire/ABI promise, no raw-memory serialization, no trait-object fact storage and no unsafe code. These fields define the proposed production state; test-only failpoints are excluded from production layouts.

```rust
// quantity.rs, not re-exported from lib.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnitTag { Events, Records, Bytes, Objects, Attempts, Nonexecutions, DiagnosticSignals }
pub(crate) struct UnitTagAccess(()); // constructor remains private to quantity

// view.rs, all types/fields below private
enum RetainedMagnitude { Exact(u64), AtLeast(u64), Unknown }
enum RetainedObservation {
    Loss { kind: LossKind, magnitude: RetainedMagnitude },
    Signal { observed: u8, cap: u8 },
}
struct RetainedFact {
    source: SourceRef,
    channel: ChannelId,
    unit: UnitTag,
    observation: RetainedObservation,
    affected: Vec<ClaimId>,
}
struct ClaimState { claim: ClaimId, consumed_loss: bool }
// ClaimLedger fields: epoch: Epoch, limits: LedgerLimits,
// claims: Vec<ClaimState> sorted by ClaimId, facts: Vec<RetainedFact> in acceptance order.
// QueryOverlay field: partial_claims: Vec<ClaimId> sorted unique.
// ClaimAssessment fields: claim: ClaimId, reasons: Vec<QualityReason>.
// FeedRegistry fields: epoch: Epoch, required: Vec<ChannelId> sorted unique,
// received: Vec<bool> of exactly the same length/index mapping.
// Versioned<T> fields: epoch: Epoch, revision: Revision, value: T.
// Correction<T> fields: epoch: Epoch, from: Revision, to: Revision, replacement: T.
```

Each loss record copies full SourceRef/channel, the unit discriminator, LossKind, exact/lower-bound/unknown magnitude and the complete affected set. Signal records use UnitTag::DiagnosticSignals and retain observed/cap, without inventing an omitted-event magnitude. No source/binding/origin/channel/kind/unit combination is coalesced. Private rows are proved by delivered unit tests against independent literal tuples. Public tests alone cannot observe these rows.

ClaimLedger stores only one persistent reason kind in this increment: consumed_loss. The other QualityReason vocabulary does not imply a missing mutator. QueryPartial exists only in returned assessments. No stored records, registered claims or received feeds are evicted/reset within an owner epoch. No inference of never-seen identity is made from absent history.

## D9 private sealed-unit mechanism and validation gate

The existing public spelling `pub trait Unit: private::Sealed {}` and its existing private_bounds allowance stay unchanged. Do not add Unit:'static/Sized/Send/Clone/Eq, an associated constant to Unit, a public unit enum, TypeId/type_name inspection or an unsafe cast. Add this exact proposed method to the already private module's Sealed trait:

```rust
mod private {
    pub trait Sealed {
        // Deliberate typed private gate; allow this lint only on this declaration.
        #[allow(private_interfaces)]
        fn unit_tag(_: super::UnitTagAccess) -> super::UnitTag
        where Self: Sized;
    }
}
#[allow(private_bounds)]
pub trait Unit: private::Sealed {}

pub(crate) fn unit_tag<U: Unit>() -> UnitTag {
    <U as private::Sealed>::unit_tag(UnitTagAccess(()))
}
```

Each of the seven existing marker implementations returns exactly its same-named UnitTag; macro output must preserve all existing Unit implementations. The access-token field is private to quantity. Other crate modules call only quantity::unit_tag::<U>(); external crates cannot name the token/tag/helper/private module. There is no default/fallback tag. A future unit requires an explicit new internal mapping and literal tests.

`where Self: Sized` excludes this static method from trait-object dispatch while keeping Unit itself free of a Sized bound. Associated constants and unrestricted static functions would threaten today's trait-object compatibility. Private interfaces and supertrait access require an actual compiler gate; reading these rules does not prove this prototype compiles or is externally inaccessible. See the [Rust privacy reference](https://doc.rust-lang.org/reference/visibility-and-privacy.html) and [trait-object requirements](https://doc.rust-lang.org/reference/items/traits.html#dyn-compatibility).

Before implementation admission, root must authorize and bind an isolated, disposable D9 prototype made from the exact accepted quantity.rs bytes, this narrow delta and separate external probe packages. On Rust 1.88.0 and 1.98.1, require positive generic Unit-only calls, all seven Count types, and `Option<&dyn Unit>` with no new marker bounds. Require refusal for external Unit implementation, private Sealed/tag/token/helper imports, and an inherited-method call using an inferred argument (`fn impossible<T>() -> T { loop {} }`; `U::unit_tag(impossible())`). The last control must fail privacy at the private gate; a setup/import typo or unrelated diagnostic is insufficient. Characterize actual compiler diagnostics before freezing their precise expected primary IDs. If prototype validation fails, return NEEDS_DECISION and revise this private mechanism; do not implement a guessed substitute or weaken a refusal. Compiler validation is **NOT_RUN/UNBOUND**, and no lint suppression beyond this one private-interface declaration is authorized by this proposal.

## Claims, overlays and loss truth

Let C=limits.claims, R=reasons_per_claim, F=loss_facts. New ledger construction is lazy; every usize limit, including zero, is a valid cardinality limit. It does not preallocate C×R or claim all admitted capacities can be allocated. A successful record registers all previously untouched affected IDs, with at most C total registered claims. Snapshot may select untouched IDs without registering them, up to C selected IDs; their reason set is empty unless that call overlays them. Numeric ClaimId/ChannelId zero is valid.

Each accepted record call consumes one shared F slot, including Exact(0), zero signal, repeated equal-valued observations and empty affected lists. There is no observation ID and no value-based deduplication. Caller retransmission dedup is separate from FeedRegistry's exactly-once per-channel presence. A damaging record with empty affected creates no claim reason and can succeed even at C=R=0 if F permits it.

Loss truth is fixed: Exact(0) and signal observed0 add no reason. Exact(nonzero), every AtLeast including AtLeast(0), Unknown and nonzero signal add ConsumedLoss to each affected claim. A zero lower bound is not an absence proof. AtLeast/Unknown keep their original tags. Signal cap255 remains a diagnostic signal. Every input list rejects duplicate IDs, including overlay outsiders that a later selection ignores.

QueryOverlay::new admits length≤max_claims, rejects duplicates, then owns a sorted copy. Snapshot preserves selected input order. It combines the persistent consumed reason with QueryPartial only for selected overlay members. Overlay outsiders are ignored without registering claims. Reasons are unique and returned in enum declaration order, so the only two-reason CP06 result is [ConsumedLoss,QueryPartial]. Previously returned assessments remain immutable. Removing an overlay never removes consumed evidence.

All distinct returned reasons count against R. At R=0 a plain pristine assessment is valid, a non-degrading record is valid, a record creating any affected reason refuses, and an overlaid selected claim refuses. At R=1 a consumed-plus-partial assessment refuses as a whole. Do not truncate reasons, downgrade the result or return a partial prefix.

## Exact normal-error order and transaction boundary

Normal refusal variants contain no raw payload. Epoch comparisons use the complete capture/producer/ordinal value. No expected binding/origin/unit schema is supplied to these constructors, so same-epoch different bindings/origins/units remain distinct retained observations; the caller/profile supplies any stronger schema. Origin is never promoted. Unit extraction is total over the seven sealed markers and invokes no caller callback.

| Operation | First-to-last checks before publication |
|---|---|
| record_loss/record_signal | Full fact epoch→affected length≤C→duplicate affected IDs→projected distinct registered claims≤C→next record cardinality≤F→projected per-claim reason count≤R→checked staging/reservation→commit. |
| QueryOverlay::new | Input length≤max_claims→duplicate IDs→checked copy/reserve/sort. |
| snapshot | Selected length≤C→duplicate selected IDs→all final reason capacities≤R→checked output allocation→construct complete result; ledger never mutates. |
| FeedRegistry::new | Required length≤max_feeds→duplicate IDs→checked required/received allocations. |
| FeedRegistry::feed | Full epoch→declared required member, else InvalidId→already received, else DuplicateFeed→set that one received bit. No allocation. |
| FeedRegistry::finish | All declared bits present→Ok, otherwise MissingFeed. Observational and idempotent. |
| Correction::new | checked from+1; MAX→ArithmeticOverflow. No replacement payload inspection. |
| Versioned::apply | Full epoch, else DomainMismatch→exact from==current revision, else StaleRevision→complete replacement with checked constructor-supplied to. |

Length/projected-capacity/checked collection-size failure and try_reserve failure return CapacityExceeded; duplicate lists return DuplicateKey. Reserve uses checked usize arithmetic and try_reserve_exact for admitted buffers. Ordinary allocator/OOM/abort behavior is not universally recoverable. The exact allocation-error choice is a ratified r2 refinement; it adds no new error variant. Record0/MAX magnitudes and Revision0/MAX input remain valid values.

Record staging owns one affected copy and a complete prospective sorted ClaimState vector. Before the first logical publication, all fallible work, including facts.try_reserve_exact(1), is complete. Commit appends the staged fact and swaps the staged claims using only infallible moves of fixed library-owned values; no allocation or caller code occurs in that section. Normally returned errors leave old facts, tags, order, registered IDs, reason state and feed bits unchanged. Existing Vec capacity may have grown during successful precommit reservation; capacity/address identity is not a public state guarantee. No arbitrary unwind/abort rollback is claimed. Test-only owner-local reserve failpoints exercise every precommit reserve branch. At a selected site the test path obtains a deterministic TryReserveError from Vec::<u8>::new().try_reserve_exact(usize::MAX) and feeds it through that site's normal result-to-CapacityExceeded mapping before publication. This does not provoke or qualify actual allocator exhaustion. It adds no production callback, global, public feature or allocator-recovery claim.

Constructor verification extends the existing A01 family with `overlay_owned_copy`, `feed_required_ids` and `feed_received_bits` reserves. With each selected fault armed, unique[1,0]/limit2 must reach that site and return normal Err(CapacityExceeded), no normally returned owner and unchanged borrowed input. Overlength unique[1,0,2], overlength duplicate[1,1,0] and within-limit duplicate[1,1] must return CapacityExceeded/CapacityExceeded/DuplicateKey respectively with **zero visited reserve sites**. Disarming the fault restores the same unique positive. Unsorted required[1,0] must map to sorted required[0,1], received[false,true] after feed1, MissingFeed until feed0, then received[true,true]/Ok. Early-reserve, wrong ArithmeticOverflow/panic mapping and wrong ID-to-bit mutants fail these exact assertions. These are required future product checks, not executed constructor evidence. V06 alone admits literal claim ID3 for its existing outsider; both selected and overlay cardinalities remain2 and all fixed journals remain unchanged.

## Corrections, identity and user effects

Versioned::new starts at revision0. Correction::new stores from and exact to=from+1; no skip/wrap/saturation. Apply moves the entire replacement, not a field merge, and invokes no T Eq/Clone/Debug. On a normally returned metadata refusal, the returned original owner retains its epoch/revision/value. The rejected Correction is consumed, not returned.

Ordinary Drop can run user effects or panic: constructor overflow drops its replacement; refused apply drops the rejected replacement; successful apply retires the old value. If those drops panic, the normal result/returned owner is not promised, and ordinary unwinding can drop other owned values. No catch_unwind, rollback, destructor interception or abort recovery appears in production. Tests catch only in their harness and avoid double-panicking destructors.

Versioned/Correction carry no target key. Two different values with equal epoch/revision can accept the same envelope if the caller misroutes it. Reference clients keep Vec<Entry> with complete CP05 ObjectKey<FixtureKey> association, never assume ObjectKey:Ord/Hash/Copy, reject Unknown/foreign/missing/ambiguous target routes, and match complete epoch/generation/raw namespace/device/token. That routes a correction to each original report/export holder. The primitive cannot certify routing or distribution. Multi-holder failure remains explicit incomplete propagation; no atomic broadcast or hidden retry is promised.

Traits: Revision/QualityReason/LedgerLimits implement Debug/Clone/Copy/PartialEq/Eq; ClaimAssessment/QueryOverlay implement Debug/Clone/PartialEq/Eq. No additional Versioned/Correction or ledger/registry clone/serde/Debug export is required. Generic metadata operations add no T bounds. Automatic field-based Send/Sync remains; no manual unsafe impl or hidden synchronization.

## Finite independent oracle, bounds and support

Keep every original CP06 case ID from r1; new local case IDs do not renumber H/UC/G. The frozen authoring oracle has three distinct populations, all **NOT_RUN**:

| Population | Exact alphabet/length and state cap | Size / independent expectation |
|---|---|---|
| View journal | L1_UNKNOWN, L2_EXACT1, L1_EXACT0, QUERY_BOTH_OVERLAY1, QUERY_BOTH_PLAIN, QUERY_BOTH_OVERLAY_BOTH; lengths0..5; C2/R2/F5. | 9,331 scripts/44,790 actions. Expected reasons derive from preceding accepted occurrence indices and that call's overlay, never production output. At most5 facts/2 claims/2 reasons per returned claim. |
| Feed inventory | FEED0_EXACT0, FEED0_EXACT11, FEED1_UNKNOWN, FINISH; lengths0..4, each of required sets[],[0],[1],[0,1],max2. | 1,364 scripts/5,008 actions total. Independent declared membership/first accepted input indices supply expected presence. |
| Revision journal | APPLY_E_FROM0_A, APPLY_E_FROM1_B, APPLY_E_FROM0_C, APPLY_FOREIGN_FROM0_D, CONSTRUCT_FROM_MAX_E; lengths0..4, one holder and literal values. | 781 scripts/2,930 actions. Independent accepted-attempt journal with literal revisions0..4 determines replacement; source holder never supplies expected truth. |

Generate one script at a time from fixed ordered alphabets; do not retain all scripts/results in memory. Current script length≤5, journal rows≤5, selected claims≤2. Separate literal rows cover constructor errors, bounds, all seven units, MAX-1/MAX, source-context fields, ignored-overlay duplicates, allocation/drop failures and actual complete-key multi-holder clients. Fix populations before environment discovery. A bad control must reach valid nonempty setup and fail the intended semantic assertion; setup/compile failure is not semantic RED. External privacy/trait negatives require their intended diagnostics and valid twins, not a semantic execution claim.

Persistent cardinalities are ≤F fact rows, ≤C claim states, ≤F×C affected IDs, and ≤M required plus M received bits. Snapshot output is ≤S assessments and ≤S×min(R,2) reasons, S≤C. Staging retains at most one C-state vector, one A-ID copy and one pending fact in addition to the old state. Vector spare capacity/allocator overhead and generic T allocations have no strict-byte/peak-memory bound. No hard time, syscall interruption, cleanup, durability or concurrency guarantee follows.

**Ratified disclosed work refinement:** duplicate-before-allocation on immutable arbitrary-ID slices uses pairwise preflight, so duplicate validation is O(A²)/O(S²)/O(Q²)/O(M²), not the earlier broad linear-input claim. Staging/sorted-copy work adds O(C+A log A), snapshot lookup O(S(log C+log Q)+S×min(R,2)), feed O(log M), finish O(M). Extra duplicate-check memory is O(1); lengths are admitted first. This explicit scoped exception is ratified with this contract; do not hide a pre-refusal allocation or retain a false linear claim. No new public hard maxima are invented.

Core remains std-only, default=[], additive existing json, host-only/no native dependencies. Proposed qualification is Rust1.88.0/1.98.1 on x86_64-unknown-linux-gnu, no-default/default/json source and actual archive; no claim about other platforms/32-bit/compiler cells absent predeclared real checks. The existing absolute shared lock/resource and fresh targets must be bound before any future compiler command.

## Delivery, receipts and explicit remaining TODO

Deliver all production modules, source/unit/integration tests, literal fixture source, semantic/privacy controls, two materially different reference clients and bounded helper in the actual package allowlist. Users must run them from the extracted archive without private donors, root tools, issue docs or repository paths. Ordinary dependency cargo test does not execute package tests; no complete capture conformance profile is certified here.

The quantity.rs private change is shared/root-owned and affects already mapped bytes. Preserve `docs/provenance/ports/CP02-20261018-initial.json` (observed SHA256 `c55a3c5879bfd7df0f1ce52022ab8071e637b5dec758f362bf317d517d52fb39`) unchanged. Root must append a CP02 successor receipt keeping the same task/admission/source-slice identity and rebinding new quantity.rs destination hashes for Count::checked_add and CountBounds. Run affected CP02 quantity/conservation/trait and CP03 loss/counter/unit checks on changed bytes. Unchanged CP03 receipt bytes retain their original historical scope; create a successor for any mapped CP03 destination that actually changes. CP06 receives its separate current-source admission/selected-port receipt. No old green receipt validates changed bytes.

Root must add these explicit open TODO routes when promoting normative docs: D8 public provenance audit/export and neutral serialization remain CP10; exact-consumer/installed delivery remains CP13/TT07; full real reducers and holder/history policy remain CP11; actual migration/duplicate retirement remains MG03 [superseded shorthand: MG02/MG04 per the override at the head of this contract]. Payload-free ContractError never claims to encode tags. O per-TID correction retention and its real5,000-foreign-close control remain preserved CP11/MG03 obligations, not a new bounded CP06 queue. Accepted package increments, pure tests, source/archive consumers, installed qualification and runtime authority stay separate.
