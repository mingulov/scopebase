# ScopeBase capture and provenance design

Normative 2026-10-18 amendment: [decisions and reasons](2026-10-18-scopebase-decisions.md), [executor contract](2026-10-18-scopebase-executor-contract.md), and [task-origin / repair plan](../plans/2026-10-18-scopebase-plan-repair.md). Porting and task readiness follow these amendments; no new implementation or support claim follows.
Date: 2026-10-17. Status: complete proposed subsystem specification for review and later implementation. Nothing in this document describes an implemented ScopeBase package, a passing check, a product integration or a live authority. The proposed Rust package is `scopebase-capture`; ScopeBase is the brand, and registry availability/licensing are separate publication decisions.

## Purpose and boundaries

Build independently useful, host-only Rust evidence primitives for stream processors, profilers and scope tools: explicit observation domains, insertion provenance, generations, typed loss, checked count bounds, immutable report assessments, interval proofs, strict replay and protocol evidence checking. A plain Rust program can use every core operation without Linux, BPF, a compiler backend, privileges, a product workspace or a central SDK.

This is the full capture/provenance subsystem, rather than a universal runtime. It deliberately leaves event meanings, crypto/DMA object reducers, policy, privacy, external product schemas, admission effects, kernel synchronization, ring reading and thread/process shutdown with their owners. It shares the proof obligations and portable oracles without requiring identical state machines. The companion [implementation plan](../plans/2026-10-17-scopebase-capture.md) defines future files, tasks and commands. Those commands do not exist in the current documentation-only repository.

Cross-component direction is `scopebase-bpf` adapters → capture value types; capture has no dependency on `scopebase-bpf`, `scopebase-linux`, Aya, libbpf, Mojo, a runtime or the testkit. Linux owns observation/control/file/mount/image authority. BP owns per-CPU geometry, wire layout, writer partitions, producer loss paths, drain cursors, attachment and native closure. Capture records their assertions with provenance and checks consistency; it cannot mint either component's authority. A replay/test result cannot become a retained image, live fence or runtime capability.

## Evidence and donor basis

The source findings below are taken from the existing research, not a new donor source refresh or new runtime experiment. Before implementation CP01 must refresh selected files and descendants read-only, record hashes for moving WIP, inspect notices, and choose an accepted baseline. No fetch, checkout change, build or live probe is authorized by this specification.

| Donor observation | Selected research pin and source seam | Reusable contribution and limit |
|---|---|---|
| KryProbe insertion provenance | `d153f3aaf9a3931337b47c9e1b046c692da55083`; `crates/kryprobe-abi/src/kcrypto_agg.rs` (`try_fold_vwho`, `identity_present`); fixes `8d99023f4c65ca8539bcde2319591383fef5c92a`, stride follow-up `31a1f198077406054b073952719e3a02c294163d` | Exactly one successful inserting lane freezes identity. Real UID/stack zero is valid, secondary zero-filled lanes do not own identity. Fold/count host contract belongs here; 88-byte ABI and real migration proof belong to BP/product. |
| KryProbe independent loss channels | Same pin; ABI `kattrloss_fold`; fix `6c4d335eb57bed2a2a43c9e5a3c2cf8274e23f28` | Preallocated loss storage survives the identity map being full. Cap 255 is a degradation signal, not exact omitted events. Producer implementation stays BP/product. |
| KryProbe shared loss integrity | Same pin; `crates/kryprobe-core/src/evidence/integrity.rs`, `backend/driver.rs` | A required shared transport feed must be consumed exactly once, including an explicit measured-zero feed; absent and duplicate feeds refuse. Backend-specific facts remain separate. |
| KryProbe identity/lifecycle/replay | Same pin; `workload/{identity,evidence,scope,observation}.rs`, lifecycle tests; fixes `4481d84597cf3f891082e929f1d1366b4693db83`, `ac6322e72a42977032e684580d045b85796724ca`, `e529862ea898ca9918b1b64548505e34bd45f8e2` | Structured keys, explicit unknown lifetime, checked partitions, temporal coherence and submit-generation matching. Keep cgroup/container/transform/request rules in donor-shaped adapters. |
| KryProbe qualification operands/startup | Same pin; `scripts/kcrypto_perf/successorvalidity.py`; fixes `87aee36abb923ea57601087a615858209f72bcb8`, `fed6cdc08b2b928942d671c153d7654ca11353c0` | Reject duplicate members/terminals and missing operands. Baseline must precede first admitted production. Product truth equations and live setup stay local. |
| MemVeil independent facts and generations | `8307a17d4c1d01d2e6fa66679f0e7bed113fa416`; reader/mappings tests; fixes `550118d5dea2ee7b4becbdded3f279464708624f`, `24defdd2317bdbd747751951bc2cf5a79cebfb77` | Unknown IDs never collide on a default key. Independently known bytes/failures survive missing correlation; occupancy can remain unknown. DMA reducer stays local. |
| MemVeil ordering and views | Same pin; fixes `6ea5ffc43fafd0e67690be3b2da7192ecbaf2573`, `15e07cd1189da84f4e3fd3e12b793666b44974f3` | Release-before-map half-open ties, explicit ordering proof for peak; query-local partial is an overlay, actual consumed loss persists. |
| MemVeil stop model | Same pin; `src/memveil/capture/stop.mojo`, `tests/unit/test_stop.mojo` | Admission close, writer quiescence, drain and post-drain sample are distinct predicates; late submit invalidates sample. Existing model is not wired live settlement qualification. |
| libbpf-mojo conservation/vectors | Source head `ff6ea5087cb6cab3db51a9ffaf99922f880da8c9`; ring conformance tests; MemVeil consumes older `681096cb588379307d0c8e94e1d77e53de4be22f`, bundle SHA-256 `c5a3fd69e0afc00a5dcb16909bad5ad65f8d583e7e0f80936aeab8fd3b836253` | Received = delivered + held + malformed + dropped, with explicit units and independent rows. Reuse neutral vectors, not native transport ownership or a claim that the newer code is shipped in MemVeil. |
| OSSLscope bounds/corrections | Preview pin `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a`; `src/evidence.rs`, count deadline countermodel and scan oracle | One physical observation supports alternative candidate bounds; it is not copied into each alias. Late corrections must reach every holder; quiet final drain is insufficient closure. |
| p11scope shared reservations | Research integration refresh `eb6bbe1df910a3cf40b6b7e8965cc65c69f203ae`; prior `cf413029dc9e092925a00b7eabdd8acbe02fa3fb`, shared-ledger WIP and later N1c successor described in donor notes | Evaluate cross-stage move-only reservation conservation. Historical `byte_limit=None` proves no retained-byte bound. Do not extract an unreviewed WIP interface as stable. |

Full references: [KryProbe](../../research/2026-10-17-shared-libraries/kryprobe.md), [MemVeil/libbpf-mojo](../../research/2026-10-17-shared-libraries/memveil.md), [OSSLscope](../../research/2026-10-17-shared-libraries/osslscope.md), [p11scope](../../research/2026-10-17-shared-libraries/p11scope.md). Preserve per-file SPDX/authorship and fixture provenance. A semantic rewrite still requires a provenance record and intended package-license review; this design does not relicense donor code.

## Global constraints

- Brand: ScopeBase; Rust package: `scopebase-capture`; library import: `scopebase_capture`.
- Core uses stable Rust, edition 2021, `rust-version = "1.88.0"`, and the standard library; `default = []`.
- Feature `json` adds only `serde` and `serde_json` for the neutral replay format; feature activation is additive and cannot change core semantics.
- No BPF/compiler/build-script requirement, platform syscalls, hidden logging, automatic effects or product dependency in this package.
- All public invariant-bearing fields are private; validating constructors also run on replay and version conversion.
- All public error/outcome enums are `#[non_exhaustive]`; errors expose structured codes, never required text matching.
- All collections are admitted against explicit limits before mutation; rejected operations preserve previous state.
- A count bound is not a retained-byte, peak-memory, time, syscall-interruptibility or native-cleanup bound.
- Product migrations are LATER; standalone ScopeBase consumers and real donor-shaped adapters qualify this package without implying product integration.

Initial package version is `0.1.0`; initial qualified host target is `x86_64-unknown-linux-gnu` and little-endian. Alternate byte-order/width fixtures exercise pure decoding semantics, without advertising Arm, musl or cross-host runtime support. Additional supported host targets require explicit cells under the master specification. User-owned userspace source follows the provisional Apache-2.0 policy in [D03](2026-10-18-scopebase-decisions.md#d03--license-by-code-ownership-and-actual-build-destination). Preserve historical source observations, author authorization and actual third-party terms separately; no project MIT option is introduced.

MSRV 1.88.0 is a proposed supported floor to test during implementation, not an observed build result. Dependencies must resolve on it; a dependency requiring more Rust is rejected or deliberately changes this contract before release. Initial pre-1.0 coordinated releases require exact capture/testkit contract-major compatibility; changing meaning, required evidence or Rust API incompatibly increments the minor version. Patch changes cannot reinterpret an existing fixture verdict. MSRV changes are documented minor changes.

## Requirements and traceability

H, UC, G and TODO identifiers below refer to the stable existing inventories. They are not renamed, completed or new claims. A reference means this component implements the stated subset, not the full live/installed family.

| ID | Required behavior | Existing obligation | Implementation task |
|---|---|---|---|
| CP-R01 | Explicit source/capture/producer/epoch/clock domains; provenance never confers authority | Q01; L09; H03/H24; G12/G17/G18/G20 | CP01, CP02 |
| CP-R02 | Unit-safe checked arithmetic, partitions and conservation; unknown ≠ zero | Q01; H23/H24/H26; G03/G16 | CP02, CP03 |
| CP-R03 | Exactly one insertion owner, valid zero-valued identity, counts from secondary lanes | Q01; H15; B01/B08 | CP04 |
| CP-R04 | Independent loss units/channels, exact/lower-bound/unknown/capped-signal distinctions; survives-full-map producer contract | Q01; H14/H17; B08 | CP03, CP04 |
| CP-R05 | Checked sample/baseline/delta semantics; epoch replacement/reset/wrap never silently subtract | Q01; H03/H24; G16/G23 | CP03 |
| CP-R06 | Explicit generation match and bounded retained provenance; no unknown-ID collision or successor retirement | Q01; H03/H25; L09 | CP05 |
| CP-R07 | Separate immutable query overlays from persistent per-claim consumed loss | Q02; H26/H27 | CP06 |
| CP-R08 | Physical observations conserved once; alternatives and incomplete candidate sets yield justified bounds | Q01/Q04; H24/H26 | CP07 |
| CP-R09 | Clock-tagged half-open intervals and scoped ordering proof; stable sweep-unique event IDs preserve valid generation-local ordinal reuse; per-generation durations survive unrelated peak refusal | Q02; H24/H27; G17 | CP05, CP08 |
| CP-R10 | Checked closure evidence/profile and late invalidation without universal state machine or authority | Q03; H18; B07/B08; G12/G14/G23 | CP09 |
| CP-R11 | Exactly-once required shared loss feeds; missing and measured zero distinct | Q01/Q04; H13/H26 | CP06 |
| CP-R12 | Strict bounded neutral replay and shared cross-language-ready vectors; constructors enforce the same semantics | Q05; H23/H24/H25; G18/G20/G22 | CP10 |
| CP-R13 | Versioned corrections update every participating holder; stale/out-of-order correction refuses | Q02/Q04; H27 | CP06, CP11 |
| CP-R14 | Evaluate cross-stage count/byte reservations against two independent consumers before stable extraction | Q06; T02/T04/T06; G04/G05/G07/G09/G10 | CP12 |
| CP-R15 | Independent positive/active-negative oracles and semantic known-bad controls for every promoted mechanism | F04/F05; T01–T04; H15/H17/H18/H23–H27 | CP04–CP13 |
| CP-R16 | Embeddable exact-consumer conformance plus installed offline operator route; bounded evidence/disclosure | T05–T07; UC14; G18–G20/G22 | CP11, CP13 |
| CP-R17 | Independently useful examples/adapters retain crypto/DMA policy and product schema ownership | Q04; T06; G14/G18 | CP11 |
| CP-R18 | Explicit bounds, failure atomicity, panic/trait and concurrency contracts | T02/T04; G03–G05/G07/G09/G10/G18/G22 | CP02–CP13 |

Nonapplicable to the core package: H01/H02/H04–H12/H16/H19–H22/H28–H32, UC01–UC13 and G01/G02/G06/G08/G11/G13/G15/G21 describe file/process/BPF/native/compiler mechanisms. H12/H13/H14/H15/H17/H18 here supply portable evidence/arithmetic/vector subsets only; actual reader, producer ABI, CPU migration, writer race and live settlement evidence remain BP/product obligations. UC12 cannot be closed by a CP09 model. UC14 applies to the selected pure capture profile, without filesystem prerequisites. G04/G05/G07/G09/G10 affect the reservation pilot's stronger claims only where stated.

## Exact proposed core interface

All items below are proposed exports from `scopebase_capture` through the named modules. Omitted struct storage is private, rather than unspecified public API. Derived traits are `Debug`, `Clone`, `PartialEq`, `Eq` for value types, with IDs also `Copy`, `Ord`, `Hash`. State owners are not `Clone`; references/snapshots contain no native authority. Private fields keep checked constructors meaningful. `Debug` prints ID kinds and structured reason codes, not opaque identity payloads or event bytes.

### Domains, quantities and errors

```rust
// lib.rs: root error reexport consumed by native adapters.
pub use error::ContractError;
// domain.rs
pub struct CaptureId([u8; 16]);
pub struct ProducerId([u8; 16]);
pub struct BindingId([u8; 32]);
pub struct ClockDomain([u8; 16]);
pub struct Epoch { /* capture, producer, ordinal */ }
pub struct ChannelId(u32);
pub struct ClaimId(u32);
pub struct PhysicalSiteId(u64);
pub struct SourceRef { /* epoch, binding, origin */ }
pub enum Origin { AdapterReported, Synthetic, Replayed }
impl CaptureId { pub fn new(value: [u8; 16]) -> Result<Self, ContractError>; }
impl ProducerId { pub fn new(value: [u8; 16]) -> Result<Self, ContractError>; }
impl BindingId { pub fn new(value: [u8; 32]) -> Result<Self, ContractError>; }
impl ClockDomain { pub fn new(value: [u8; 16]) -> Result<Self, ContractError>; }
impl Epoch {
    pub fn new(capture: CaptureId, producer: ProducerId, ordinal: u64) -> Self;
    pub fn successor(&self) -> Result<Self, ContractError>;
    pub fn capture(&self) -> CaptureId;
    pub fn producer(&self) -> ProducerId;
    pub fn ordinal(&self) -> u64;
}
impl ChannelId { pub fn new(value: u32) -> Self; }
impl ClaimId { pub fn new(value: u32) -> Self; }
impl PhysicalSiteId { pub fn new(value: u64) -> Self; }
impl SourceRef {
    pub fn new(epoch: Epoch, binding: BindingId, origin: Origin) -> Self;
    pub fn epoch(&self) -> &Epoch;
    pub fn origin(&self) -> Origin;
    pub fn binding(&self) -> BindingId;
}
// quantity.rs; Unit is sealed to this initial set.
pub trait Unit: private::Sealed {}
pub enum Events {} pub enum Records {} pub enum Bytes {}
pub enum Objects {} pub enum Attempts {} pub enum Nonexecutions {}
pub enum DiagnosticSignals {}
pub struct Count<U: Unit> { /* u64 + PhantomData<U>; Copy for every Unit */ }
impl<U: Unit> Count<U> {
    pub fn new(value: u64) -> Self;
    pub fn get(&self) -> u64;
    pub fn checked_add(self, rhs: Self) -> Result<Self, ContractError>;
    pub fn checked_sub(self, rhs: Self) -> Result<Self, ContractError>;
}
pub struct CountBounds<U: Unit> { /* lower, optional upper */ }
impl<U: Unit> CountBounds<U> {
    pub fn new(lower: Count<U>, upper: Option<Count<U>>) -> Result<Self, ContractError>;
    pub fn lower(&self) -> Count<U>;
    pub fn upper(&self) -> Option<Count<U>>;
}
// error.rs; public errors carry no payload bytes, pointers or product identities.
pub enum ContractError {
    InvalidId, DomainMismatch, ArithmeticOverflow, ReversedBounds, ConservationMismatch,
    MissingProvenance, ConflictingProvenance, DuplicateKey,
    EpochExhausted, GenerationMismatch, CapacityExceeded,
    MissingFeed, DuplicateFeed, StaleRevision, InvalidInterval,
    InvalidSample, InvalidProfile, IncompatibleVersion, InvalidReplay,
}
```

Byte-array IDs reject all-zero as an absent binding marker; numeric channel/claim/site/epoch ordinals including zero are valid. IDs scope observations, not Linux process/file authority. A caller chooses distinct IDs for distinct domains and retains responsibility for a coherently false assertion. The library rejects detectable contradictions and records `Origin`; it cannot prove that a claimed artifact was loaded from its own hash. All count arithmetic is checked and same-unit; no `Add`, numeric cast or implicit `Count<Records>`→`Count<Events>` conversion is exported. Domain adapters explicitly perform and test any conversion. `CountBounds` upper `None` means unbounded/unknown upper, not zero. Ordinal exhaustion refuses; restart uses a new `CaptureId` rather than reusing an old epoch.

### Samples, loss and conservation

```rust
// counter.rs
pub enum CounterPolicy { Monotonic, Saturating { maximum: u64 }, Modulo { width: u8 } }
pub struct Sample<U: Unit> { /* source, channel, policy, interval, value */ }
pub struct AdvanceBound<U: Unit> { /* owned baseline/current samples and asserted maximum */ }
#[non_exhaustive]
pub enum Delta<U: Unit> { Exact(Count<U>), AtLeast(Count<U>), Unknown(DeltaUnknown) }
#[non_exhaustive]
pub enum DeltaUnknown { MissingBaseline, ResetOrWrap, PartialRead, Saturated, UnboundedWrap }
impl<U: Unit> Sample<U> {
    pub fn new(source: SourceRef, channel: ChannelId, policy: CounterPolicy,
               interval: TimeInterval, value: Count<U>) -> Result<Self, ContractError>;
    pub fn source(&self) -> &SourceRef;
    pub fn channel(&self) -> ChannelId;
    pub fn policy(&self) -> CounterPolicy;
    pub fn value(&self) -> Count<U>;
    pub fn interval(&self) -> &TimeInterval;
}
impl<U: Unit> AdvanceBound<U> {
    pub fn new(baseline: &Sample<U>, current: &Sample<U>, maximum: Count<U>)
        -> Result<Self, ContractError>;
    pub fn baseline(&self) -> &Sample<U>;
    pub fn current(&self) -> &Sample<U>;
    pub fn maximum(&self) -> Count<U>;
}
pub fn sample_delta<U: Unit>(baseline: Option<&Sample<U>>, current: &Sample<U>,
    bound: Option<&AdvanceBound<U>>) -> Result<Delta<U>, ContractError>;
// loss.rs
pub enum LossKind {
    Discovery, Transport, KernelNonexecution, Attribution,
    QueueOverflow, MalformedInput, DiagnosticTruncation,
}
#[non_exhaustive]
pub enum LossMagnitude<U: Unit> {
    Exact(Count<U>), AtLeast(Count<U>), Unknown,
}
pub struct LossFact<U: Unit> { /* source, channel, kind, magnitude */ }
impl<U: Unit> LossFact<U> {
    pub fn new(source: SourceRef, channel: ChannelId, kind: LossKind,
               magnitude: LossMagnitude<U>) -> Result<Self, ContractError>;
    pub fn source(&self) -> &SourceRef;
    pub fn channel(&self) -> ChannelId;
    pub fn kind(&self) -> LossKind;
    pub fn magnitude(&self) -> &LossMagnitude<U>;
}
pub struct CappedLossSignal { /* source, channel, observed, cap */ }
impl CappedLossSignal {
    pub fn new(source: SourceRef, channel: ChannelId, observed: u8, cap: u8)
        -> Result<Self, ContractError>;
    pub fn source(&self) -> &SourceRef;
    pub fn channel(&self) -> ChannelId;
    pub fn observed(&self) -> u8;
    pub fn cap(&self) -> u8;
}
pub fn fold_capped_signals(values: &[u8], cap: u8) -> Result<u8, ContractError>;
// conservation.rs
pub struct ScopePartition<U: Unit> { /* total, matched, nonmatched, unknown */ }
impl<U: Unit> ScopePartition<U> {
    pub fn new(total: Count<U>, matched: Count<U>, nonmatched: Count<U>,
               unknown: Count<U>) -> Result<Self, ContractError>;
    pub fn total(&self) -> Count<U>;
    pub fn matched(&self) -> Count<U>;
    pub fn nonmatched(&self) -> Count<U>;
    pub fn unknown(&self) -> Count<U>;
}
pub fn check_conservation<U: Unit>(total: Count<U>, disjoint_parts: &[Count<U>])
    -> Result<(), ContractError>;
```

All fields of these structs are private. `Sample::new` first validates policy configuration (saturating maximum nonzero; modulo width 1–64), then its value (saturating value ≤ maximum; modulo value < 2^width using u128). Failures are `InvalidSample`; Monotonic accepts every u64. A sample requires an actual valid observation and clock interval; an adapter must not manufacture a sample from a missing current value, missing clock or cached previous sample.

**Same context** means full `SourceRef` equality, including capture, producer, epoch ordinal, binding and origin, plus channel, complete policy and clock domain equality. Interval ticks and sampled values are separate exact-pair fields. `AdvanceBound::new` checks same context first (`DomainMismatch`), then Modulo policy (`InvalidSample`), then current.start ≥ baseline.start (`InvalidSample`). It owns clones of both samples and the independently supplied maximum, without allocation or retained borrows. Forward overlap and every maximum from zero to u64::MAX are admitted. Construction performs no modular-difference calculation or maximum-versus-residue validation.

The bound asserts that this exact pair spans no reset and at most the independently supplied advance. It prevents accidental reuse with a different pair; it cannot verify the producer assertion or distinguish repeated real observations with identical caller metadata. Equal-by-value cloned pairs may reuse it. A different pair needs a new assertion even when the same external numerical limit applies. Never derive the bound from the observed residue, the library's result or elapsed time alone. Its stored baseline never replaces the explicit optional baseline argument.

`sample_delta` has the following fixed validation order:

1. If a bound is supplied, compare actual current with its retained current: differing context returns `DomainMismatch`; differing interval ticks/value returns `InvalidSample`.
2. Missing explicit baseline returns `Unknown(MissingBaseline)`, even with a matching bound.
3. Require actual baseline/current same context, otherwise `DomainMismatch`.
4. If bounded, require actual baseline equals the retained baseline by value, otherwise `InvalidSample`. Its context is already equal by the earlier checks.
5. A current start before baseline start returns `InvalidSample`; otherwise a current start before baseline end returns `Unknown(PartialRead)`. End equality is ordered; identical zero-duration intervals are allowed.
6. Apply the policy outcomes below. A non-Modulo actual current cannot match a valid bound; no silent bound-ignore branch exists.

| Policy after context and interval checks | Result |
|---|---|
| Monotonic current ≥ baseline | `Exact(current - baseline)` |
| Monotonic decrease | `Unknown(ResetOrWrap)` |
| Saturating decrease, including from maximum | `Unknown(ResetOrWrap)` |
| Saturating baseline == current == maximum | `Unknown(Saturated)` |
| Saturating baseline < maximum and current == maximum | `AtLeast(current - baseline)` |
| Saturating baseline ≤ current < maximum | `Exact(current - baseline)` |
| Modulo without bound, or bound ≥ modulus | `Unknown(UnboundedWrap)` |
| Modulo bound < modulus and residue > bound | `InvalidSample` |
| Modulo bound < modulus and residue ≤ bound | `Exact(residue)` |

The modulo residue is `(current + modulus - baseline) % modulus` in u128, including modulus 2^64. Zero bound admits only residue zero; u64::MAX is below the width64 modulus. No result converts unknown loss to zero.

`CounterPolicy`, `DeltaUnknown` and `LossKind` implement Debug/Clone/Copy/PartialEq/Eq. Sample, AdvanceBound, Delta, LossMagnitude and LossFact implement Debug/Clone/PartialEq/Eq under only `U: Unit`, without additional marker trait bounds; they need not implement Copy. CappedLossSignal implements Debug/Clone/PartialEq/Eq. Delta, DeltaUnknown and LossMagnitude are non-exhaustive outcomes; CounterPolicy/LossKind are exhaustive input vocabulary for this increment. Debug retains SourceRef redaction. No default, setter, implicit delta-to-loss conversion or signal-to-event conversion is added.

`LossFact::new` retains every valid source/channel/kind/magnitude combination and returns Ok; each kind permits any sealed unit and Exact(0), AtLeast(0) or Unknown. Kind neither implies a unit nor classifies an activity counter automatically. `CappedLossSignal` rejects zero cap or observed > cap. `fold_capped_signals` rejects cap0 even for an empty slice and any lane > cap, including a late lane after the accumulator reaches cap. Empty valid-cap input returns zero. Fold saturates at the declared cap without wrapping, allocation or an imposed input-length limit; callers admit slice length. Work is O(n), extra memory O(1); constructors/comparisons use fixed-size O(1) metadata. No severity count or “lost total” is synthesized across channels. See [D10's CP03 decisions](2026-10-18-scopebase-decisions.md#cp03-counter-and-loss-rulings) for rationale and later task boundaries.

`ScopePartition::new` and `check_conservation` return `ConservationMismatch` when checked parts do not equal the declared total. `check_conservation` verifies arithmetic only; disjointness and shared physical provenance remain an explicit adapter assertion checked by independent fixtures. Ring delivery categories are records, not kernel operation loss. Details and independent counters for the same physical work are alternative observations, not disjoint addends. Missing operands cannot be supplied as default zero.

### Insertion identity, generation and time

```rust
// provenance.rs
#[non_exhaustive]
pub enum ObservedIdentity<I> { Known(I), Unknown(IdentityUnknown) }
#[non_exhaustive]
pub enum IdentityUnknown { NotObserved, Ambiguous, Exhausted }
pub enum LaneIdentity<I> { InsertionOwner(I), Secondary }
pub struct ProvenanceLane<I, U: Unit> { /* identity marker, count */ }
pub struct InsertionFold<I, U: Unit> { /* frozen identity and total */ }
impl<I, U: Unit> ProvenanceLane<I, U> {
    pub fn new(identity: LaneIdentity<I>, count: Count<U>) -> Self;
    pub fn saturated(identity: LaneIdentity<I>) -> Self;
}
impl<I, U: Unit> InsertionFold<I, U> {
    pub fn identity(&self) -> &I;
    pub fn total(&self) -> Count<U>;
}
pub fn fold_insertion_identity<I: Eq + Clone, U: Unit>(lanes: &[ProvenanceLane<I, U>])
    -> Result<InsertionFold<I, U>, ContractError>;
// generation.rs
pub struct ObjectKey<K> { /* epoch, raw key, generation */ }
impl<K> ObjectKey<K> {
    pub fn new(epoch: Epoch, raw: K, generation: u64) -> Self;
    pub fn epoch(&self) -> &Epoch;
    pub fn raw(&self) -> &K;
    pub fn generation(&self) -> u64;
    pub fn next_generation(&self) -> Result<Self, ContractError> where K: Clone;
    pub fn matches(&self, other: &Self) -> bool where K: Eq;
}
pub fn require_generation<K: Eq>(submitted: &ObjectKey<K>, current: &ObjectKey<K>)
    -> Result<(), ContractError>;
// time.rs; timestamp zero is valid; units are nanoseconds in the named clock.
pub struct Timestamp { /* clock, ticks */ }
pub struct TimeInterval { /* start <= end */ }
pub struct StateEdge { /* timestamp, kind, event ID unique within this sweep */ }
pub enum EdgeKind { Release, Acquire }
pub struct SweepProof { /* validated domain and ordering */ }
impl Timestamp {
    pub fn new(clock: ClockDomain, ticks: u64) -> Self;
    pub fn clock(&self) -> ClockDomain;
    pub fn ticks(&self) -> u64;
}
impl TimeInterval {
    pub fn new(start: Timestamp, end: Timestamp) -> Result<Self, ContractError>;
    pub fn duration_ns(&self) -> u64;
    pub fn start(&self) -> &Timestamp;
    pub fn end(&self) -> &Timestamp;
}
impl StateEdge {
    pub fn new(at: Timestamp, kind: EdgeKind, sweep_event_id: u64) -> Self;
}
pub fn validate_sweep_order(edges: &[StateEdge]) -> Result<SweepProof, ContractError>;
```

Insertion fold first requires exactly one owner even if two owner payloads happen to be equal; no owner is `MissingProvenance`, multiple owners are `ConflictingProvenance`. This marker pass performs no count arithmetic, payload equality or clone. Then scan counts in lane order: explicit saturation returns the new payload-free `SaturatedCount`; exact checked addition returns `ArithmeticOverflow` at its first overflowing prefix. Only success clones the unique identity once. `new` accepts every exact Count, including MAX; `saturated` retains the marker without inventing an exact count or lower bound. Donor raw MAX maps to saturated, while smaller exact lanes may legitimately sum to MAX. Secondary lanes may carry positive counts and a unique owner may have zero count. Zero-valued identity fields are ordinary payloads. The [exact CP04 contract](2026-10-18-scopebase-cp04-insertion.md) freezes traits, redacted Debug, caller Clone effects, full-map fixtures, strict delivered vectors and all affected checks. This primitive does not overwrite a product's latest-task display fields or validate wire layout; [P1–P5 and S1–S2](2026-10-18-scopebase-decisions.md#cp04-insertion-provenance-rulings) record why.

`ObservedIdentity::Unknown` cannot be used as one shared `ObjectKey`. Applications retain explicit nonjoinable observations with their own event IDs instead. No generic lifetime tracker infers that an allocation proves prior retirement; trackers and cookie allocation stay local. Adapters implement bounded tombstone/retired-key retention, and on eviction they return unknown continuity instead of reusing provenance. `next_generation` refuses u64 max. Matching includes epoch and generation; an old completion cannot match a new allocation with the same raw key.

Intervals are half-open `[start,end)`, permit zero duration, reject clock mismatch/reversed timestamps. No wall/Instant/kernel/time-namespace conversion is supplied. Adapters must name suspend semantics and conversion uncertainty or refuse it. Sweep order requires one clock domain, nondecreasing timestamps and Release before Acquire at ties. `sweep_event_id` is unique within the submitted sweep, not a generation-local ordinal or a universal object identity. The adapter maintains a stable injective mapping from each source `(ObjectKey<K>, generation-local event ordinal)` to a u64 sweep event ID: distinct source events receive distinct IDs, while a repeated source event retains its original ID. IDs need not be numerically ordered and confer no causal or lifetime authority. Exhausting assignment space refuses instead of wrapping. Two distinct generations may both legitimately have local event ordinal0; for example `(generation7, ordinal0)` and `(generation8, ordinal0)` map to IDs41 and42 and are accepted when their timestamps/order are valid. Passing ordinal0 directly for both edges is an adapter bug. Repeating ID41 in the same sweep returns `DuplicateKey`; invalid temporal order returns `InvalidInterval`. The library can check submitted ID uniqueness but cannot independently recover a lying adapter's source-event mapping; the adapter conformance oracle must check that correspondence. The function validates the supplied stream and never sorts unrelated events to invent causal order. It returns only the sufficient ordering proof, not a peak or occupancy metric. Product reducers calculate those metrics only with the other required dependencies. Ordering refusal must not discard a separately validated per-generation duration.

### Scoped report views, feed integrity and corrections

```rust
// view.rs
pub enum QualityReason { ConsumedLoss, MissingEvidence, QueryPartial, Ambiguous, Capacity }
pub struct ClaimAssessment { /* claim + bounded reason set */ }
impl ClaimAssessment {
    pub fn claim(&self) -> ClaimId;
    pub fn reasons(&self) -> &[QualityReason];
}
pub struct QueryOverlay { /* selected transient reasons */ }
pub struct ClaimLedger { /* one epoch, bounded claims/reasons, consumed facts */ }
pub struct LedgerLimits { pub claims: usize, pub reasons_per_claim: usize, pub loss_facts: usize }
impl QueryOverlay {
    pub fn new(partial_claims: &[ClaimId], max_claims: usize) -> Result<Self, ContractError>;
}
impl ClaimLedger {
    pub fn new(epoch: Epoch, limits: LedgerLimits) -> Result<Self, ContractError>;
    pub fn record_loss<U: Unit>(&mut self, fact: &LossFact<U>, affected: &[ClaimId])
        -> Result<(), ContractError>;
    pub fn record_signal(&mut self, fact: &CappedLossSignal, affected: &[ClaimId])
        -> Result<(), ContractError>;
    pub fn snapshot(&self, selected: &[ClaimId], overlay: &QueryOverlay)
        -> Result<Vec<ClaimAssessment>, ContractError>;
}
// feeds.rs
pub struct FeedRegistry { /* epoch, bounded required/feed sets */ }
impl FeedRegistry {
    pub fn new(epoch: Epoch, required: &[ChannelId], max_feeds: usize) -> Result<Self, ContractError>;
    pub fn feed<U: Unit>(&mut self, fact: &LossFact<U>) -> Result<(), ContractError>;
    pub fn finish(&self) -> Result<(), ContractError>;
}
// correction.rs
pub struct Revision(u64);
pub struct Versioned<T> { /* epoch, revision, value */ }
pub struct Correction<T> { /* epoch, from, to, replacement */ }
impl Revision { pub fn new(value: u64) -> Self; }
impl<T> Versioned<T> {
    pub fn new(epoch: Epoch, value: T) -> Self; // initial revision = 0
    pub fn revision(&self) -> Revision;
    pub fn value(&self) -> &T;
    pub fn apply(self, correction: Correction<T>) -> Result<Self, (Self, ContractError)>;
}
impl<T> Correction<T> {
    pub fn new(epoch: Epoch, from: Revision, replacement: T) -> Result<Self, ContractError>;
}
```

Claims are explicit, bounded IDs selected by the application. The application supplies a fact-dependency map: a lost release relationship can affect occupancy while copy bytes remain independently observed. The generic library neither supplies those domain dependencies nor treats an empty reason set as global completeness. Persistent losses are append-only within the ledger epoch, and every insertion is transactional; capacity refusal is returned so the application can withhold dependent claims. A new explicit epoch gets a new ledger. Measured-zero loss does not degrade claims; unknown magnitude does. A zero capped signal does not degrade claims; nonzero does, without counting omitted events. `QueryOverlay::new` rejects duplicate selected IDs rather than silently consuming a different quota. A partial query produces new immutable assessments only. Removing the overlay yields the previous persistent assessment; it cannot erase consumed loss.

A feed must be declared required or is rejected as `InvalidId`; duplicate required IDs in construction refuse. A second feed for a channel refuses regardless of magnitude. Missing feed differs from an explicit exact zero. The registry guarantees feed cardinality, not a consumer-wide “complete” result. Private ledger storage erases unit representation only after preserving source/channel/unit tags; errors and serialization retain those tags.

Corrections are complete replacements of one immutable application value. `to = from + 1` is checked, replay cannot invent a skipped revision, and wrong epoch/from revision returns the unchanged original owner and `StaleRevision`/`DomainMismatch`. A holder applying the same correction twice refuses. The library does not distribute corrections automatically; the standalone multi-holder adapter proves both report and export holders apply them, while a dropped correction mutant fails their equality to independently expected truth. Bounded retained correction history and backpressure are application policy.

### Alternatives and bounds

```rust
// bounds.rs
pub enum CandidateCoverage<C> { Complete(Vec<C>), Unknown }
pub enum MatchClass { Definite, Possible, Excluded }
pub struct SiteCount<C> { /* epoch, site, count, candidate coverage */ }
impl<C: Eq> SiteCount<C> {
    pub fn new(epoch: Epoch, site: PhysicalSiteId, count: Count<Events>,
        candidates: CandidateCoverage<C>, max_candidates: usize) -> Result<Self, ContractError>;
    pub fn epoch(&self) -> &Epoch;
    pub fn site(&self) -> PhysicalSiteId;
    pub fn count(&self) -> Count<Events>;
    pub fn candidates(&self) -> &CandidateCoverage<C>;
}
pub fn classify_alternatives<C>(site: &SiteCount<C>, classes: &[MatchClass])
    -> Result<CountBounds<Events>, ContractError>;
pub fn combine_disjoint_sites<C>(sites: &[SiteCount<C>], bounds: &[CountBounds<Events>])
    -> Result<CountBounds<Events>, ContractError>;
```

A complete nonempty set of candidate alternatives and exactly one class per candidate is required. Every candidate Definite gives `[n,n]`; every candidate Excluded gives `[0,0]`; any remaining combination gives `[0,n]`. Complete empty candidate sets are rejected, including when `n=0`; a deliberately unknown set yields `[0,None]` without pretending the observed count bounds unknown missing activity. `Possible` is explicit deliberate ambiguity, not silently upgraded because another retained property matches. Product classifiers decide candidate predicates; ScopeBase decides only bounds on supplied alternatives. Unknown candidates cannot prove absence, including zero observed activity. Combining distinct sites adds lower bounds and known upper bounds with checked arithmetic; one unknown upper makes the combined upper unknown. Duplicate physical-site IDs and mixed epochs refuse. Classification never replicates `n` into each alias, and a second counter view of the same site is not a new physical site.

### Closure evidence, without a shutdown framework

```rust
// closure.rs
pub struct PredicateId(u16);
pub struct BoundarySerial(u64);
pub struct ClosureProfile { /* version, required predicates, ordered edges */ }
pub struct PredicateObservation { /* predicate, source, serial, drain generation */ }
pub struct ClosureRecord { /* bounded observations and late evidence */ }
pub struct ClosureAssessment { /* satisfied/missing/invalidated sets + origin */ }
impl ClosureAssessment {
    pub fn satisfied(&self) -> &[PredicateId];
    pub fn missing(&self) -> &[PredicateId];
    pub fn invalidated(&self) -> &[(PredicateId, ClosureGap)];
    pub fn source(&self) -> Option<&SourceRef>;
}
pub enum ClosureGap { Missing, LateEvidence, StaleSample, UnresolvedCleanup, ContextChanged }
impl PredicateId { pub fn new(value: u16) -> Self; }
impl BoundarySerial { pub fn new(value: u64) -> Self; }
impl ClosureProfile {
    pub fn new(version: u32, required: &[PredicateId],
        before: &[(PredicateId, PredicateId)], max_predicates: usize) -> Result<Self, ContractError>;
}
impl PredicateObservation {
    pub fn new(id: PredicateId, source: SourceRef, serial: BoundarySerial,
        drain_generation: u64) -> Self;
}
impl ClosureRecord {
    pub fn new(epoch: Epoch, max_observations: usize) -> Result<Self, ContractError>;
    pub fn observe(&mut self, item: PredicateObservation) -> Result<(), ContractError>;
    pub fn invalidate(&mut self, affected: &[PredicateId], gap: ClosureGap)
        -> Result<(), ContractError>;
}
pub fn assess_closure(profile: &ClosureProfile, record: &ClosureRecord)
    -> Result<ClosureAssessment, ContractError>;
```

The caller selects a versioned acyclic dependency graph, not a universal session enum. A profile binds required predicate IDs, including baseline-before-admission where counters require it. Profiles reject duplicate/foreign/unknown IDs, cycles, version zero and >64 predicates. Observations are same epoch/binding/origin, have strictly ordered serials for required edges and a consistent drain generation for dependencies. This validates reported ordering; it cannot establish that the stated boundary occurred. A duplicate predicate observation refuses; renewed drain/sample uses a new `ClosureRecord` for a new evidence attempt, keeping the previous record available to the caller. Late evidence invalidates the named drain/sample dependency closure before reassessment; missing or invalidated prerequisites withhold dependent predicates. Unknown cleanup remains explicit. No `is_complete()` or global aggregate completeness flag is exported; accessors return the three predicate sets and source provenance.

Shipped named scripts demonstrate baseline → readiness → admission → close → writer quiescence → bounded drain → final sample, KryProbe's every-program/every-CPU obligations, the OSSLscope delayed admitted hit, and MemVeil's late submit. They are models of those contracts, not a replacement implementation. A profile may intentionally require only a weaker bounded-drain observation. It receives only that scoped assessment. Quiet poll, elapsed timeout, detach, zero activity and terminal JSON do not supply missing predicates. Neither `Origin::Synthetic` nor `Origin::Replayed` can be relabeled adapter-reported by a conversion. Live native receipt constructors stay private to the owning BP/product implementation.

### Strict neutral replay

Feature `json` exports the following exact surface. `ReplayRecord`/`ReplayValue`/`ReplayTerminal` are raw input values; only opaque `ReplayDocument` is validated. Public enum construction cannot bypass document admission. JSON variants use the displayed snake_case Rust variant names as `kind`; struct fields use the displayed snake_case names, and every struct/tag rejects unknown members. `ReplayDocument` JSON fields are exactly `schema`, `version`, `binding`, `records`.

```rust
// replay.rs, feature = "json"
pub struct ReplayLimits {
    pub bytes: usize, pub records: usize, pub nesting: usize,
    pub collection_items: usize, pub string_bytes: usize,
}
pub struct ReplayRecord { pub id: u32, pub value: ReplayValue }
pub enum ReplayValue {
    Observation(NeutralObservationV1),
    Counter { source: SourceRef, channel: ChannelId, unit: UnitTag,
        policy: CounterPolicy, interval: TimeInterval, value: u64 },
    Loss { source: SourceRef, counter: NeutralCounterV1, kind: LossKind },
    InsertionLane { source: SourceRef, lane: u32,
        identity: LaneIdentity<u64>, count: Count<Events> },
    GenerationCheck { submitted: ObjectKey<u64>, current: ObjectKey<u64> },
    Interval { source: SourceRef, interval: TimeInterval },
    Partition { source: SourceRef, unit: UnitTag, total: u64,
        matched: u64, nonmatched: u64, unknown: u64 },
    AlternativeCount { source: SourceRef, site: SiteCount<u64>, classes: Vec<MatchClass> },
    Closure { profile: ClosureProfile, record: ClosureRecord },
    Correction { epoch: Epoch, from: u64, to: u64, replacement: NeutralObservationV1 },
    Terminal(ReplayTerminal),
}
pub struct ReplayTerminal {
    pub required: Vec<u32>, pub observed: Vec<u32>, pub unresolved: Vec<ClaimId>,
}
pub struct ReplayDocument { /* private binding + records */ }
pub enum ReplayErrorKind {
    Limit, DuplicateMember, InvalidNumber, InvalidSyntax, InvalidSemantics,
    VersionMismatch, MissingTerminal, DuplicateTerminal,
}
pub struct ReplayError { /* structured kind + byte offset, no raw input */ }
impl ReplayError { pub fn kind(&self) -> ReplayErrorKind; pub fn offset(&self) -> usize; }
impl ReplayDocument {
    pub fn new(binding: BindingId, records: Vec<ReplayRecord>, limits: ReplayLimits)
        -> Result<Self, ReplayError>;
    pub fn records(&self) -> &[ReplayRecord];
    pub fn binding(&self) -> BindingId;
    pub fn origin(&self) -> Origin; // always Replayed for this document container
}
pub fn decode(bytes: &[u8], limits: ReplayLimits) -> Result<ReplayDocument, ReplayError>;
pub fn encode(document: &ReplayDocument) -> Result<Vec<u8>, ReplayError>;
```

Every document record ID is unique; terminal required/observed inventories contain unique prior record IDs and must agree, with unresolved claims retained explicitly. Ordinary records never receive semantic PASS merely because their ID appears in a terminal. Source bindings must match the document binding. Generation-check records validate the same explicit match as `require_generation`; a negative conformance vector therefore expects document rejection. Insertion lanes are grouped by source/channel script in the conformance invocation, rather than combining unrelated record IDs by timestamp. Scope partitions use dynamic unit dispatch to the same `ScopePartition<U>` constructor. Counter, loss, observation, interval, alternative and closure records similarly reuse their owning checked constructors/assessment. Correction requires matching replacement epoch, checked `to=from+1`, and cannot erase synthetic/replayed origin. Neutral insertion fixtures use integer identities only; product identities remain product schema. The document is a strict neutral evidence/vector format, not a universal product-event recorder or generic crypto/DMA reducer.

`ReplayLimits` is checked before parsing; documented installed profile values are 1 MiB bytes, 4,096 records, nesting 16, 4,096 collection items and 256 bytes per text field. The neutral format is `schema="scopebase.capture.replay"`, `version=1`, exact binding as 64 lowercase hex characters, records array, and exactly one final terminal record with required operand inventory. Counts/timestamps/ordinals are canonical decimal **strings** matching `0|[1-9][0-9]*`, capped at u64 max; never JSON floating point. IDs are fixed-size lowercase hex without trailing whitespace/newlines. Unknown members/tags, duplicate members at any depth, NaN/Infinity, bool counts, duplicate/missing terminal, records after terminal, contradictions, overflow, malformed identity/generation and mixed domains refuse. No trailing bytes except ASCII JSON whitespace; duplicate detection uses a streaming Serde visitor before constructing a map/`Value`. Allocation/collection/depth limits apply during parse, not after a full unbounded DOM has been made. Invalid input cannot partly publish a document.

Every source-bearing record stores `origin`; its JSON source object also has `synthetic` (true exactly when origin is Synthetic), checked consistently. Epoch/source JSON objects have exactly the corresponding constructor fields; SourceRef additionally carries that synthetic flag. `ReplayDocument::origin()` is always `Replayed`. Source origins inside its records are historical metadata describing the recorded assertion, including its synthetic flag; they never describe a newly observed live boundary. `records()` returns those historical operands for checking, without a conversion into current live authority. Import neither rewrites a historical synthetic flag nor presents a historical adapter assertion as a newly performed observation. A caller deliberately constructing a new adapter assertion remains responsible for that claim, exactly as for any safe raw backend. Terminal operands name required case outputs; a terminal does not erase earlier failures or unresolved predicates. Encode/decode self-roundtrip is supplementary only. Independent authored `.jsonl` input/expected vectors include `2^53+1`, u64 max/overflow, missing versus zero, crossed domains, duplicate/late records and synthetic origin. C/Mojo consumers may later use the same vector bytes; no FFI or native ABI is part of v1.

## Canonical neutral validation seam for selective interoperability

Capture owns semantic validation, while `scopebase-ffi` owns any bounded native envelope and byte codec. No C/Mojo/native dependency enters this crate. This seam is useful independently of JSON replay and does not interpret a product event frame. An exact-v1 caller supplies the following raw, unvalidated observation; all fields are ordinary data, not runtime authority:

```rust
// neutral.rs; all input structs have the shown public fields.
pub enum UnitTag { Events, Records, Bytes, Objects, Attempts, Nonexecutions, DiagnosticSignals }
pub enum NeutralMagnitudeV1 {
    Exact(u64), AtLeast(u64), Unknown,
    CappedSignal { observed: u8, cap: u8 },
}
pub struct NeutralCounterV1 {
    pub channel: u32, pub unit: UnitTag, pub magnitude: NeutralMagnitudeV1,
}
pub struct NeutralClaimV1 { pub claim: u32, pub reasons: Vec<QualityReason> }
pub struct NeutralObservationV1 {
    pub capture: [u8; 16], pub producer: [u8; 16], pub epoch: u64,
    pub binding: [u8; 32], pub origin: Origin,
    pub counters: Vec<NeutralCounterV1>, pub claims: Vec<NeutralClaimV1>,
}
pub struct NeutralLimits {
    pub counters: usize, pub claims: usize, pub reasons_per_claim: usize,
}
pub struct ValidatedNeutralV1 { /* private checked source/counters/claims */ }
pub fn validate_v1(input: &NeutralObservationV1, limits: NeutralLimits)
    -> Result<ValidatedNeutralV1, ContractError>;
impl ValidatedNeutralV1 {
    pub fn source(&self) -> &SourceRef;
    pub fn counters(&self) -> &[NeutralCounterV1];
    pub fn claims(&self) -> &[NeutralClaimV1];
}
```

`NeutralLimits::default()` is counters=4,096, claims=4,096, reasons_per_claim=16; a caller may lower each, but may not exceed these v1 maxima. Zero limits permit an empty corresponding collection. Check cardinality before cloning, reject duplicate channels/claims/reasons, all-zero byte-array IDs, and capped signals in units other than `DiagnosticSignals`. Capped signals use the same nonzero-cap/observed≤cap invariant as `CappedLossSignal`. Exact zero and Unknown are distinct accepted inputs. Zero numeric IDs/epoch are valid. Reasons describe only their named claim; QueryPartial remains a view reason and cannot be fed back as persistent consumed loss. SDK uses the three validated accessors as report metadata, never infers global completeness or trusted closure. Metadata summary omits raw payloads and grants no new authority.

This validator cannot bound an input `Vec` already allocated by its caller. The native codec must preflight input byte extent, counts, discriminants and checked count×stride before allocation, then call this one validator for semantic acceptance. Its binary version/discriminants are owned by the native plan, with an explicit mapping to these fixed Rust variants. Capture does not maintain a second binary codec. Replay uses this seam when importing the corresponding neutral observations, avoiding a separate weakened semantic path. CP10 owns its implementation and tests; CP-R01/CP-R02/CP-R12/CP-R16 apply.

## Bounds, errors and concurrency

Core operations are synchronous, deterministic and side-effect free except explicit `&mut self` state changes. No callbacks, async tasks, cancellation handlers, global registries, stdout/stderr writes or implicit clock reads are supplied. Value types inherit `Send`/`Sync` only if generic payloads do; state owners use ordinary exclusive `&mut self` access and are `Send`/`Sync` when all fields are, with no interior mutable global. The reservation pilot is deliberately separate and initially single-owner. Panic in a payload's user-supplied `Eq`/`Clone` may unwind; the package does not catch arbitrary user panic or promise abort recovery. Stage candidate state before commit so normal error/panic cannot publish half-updated ledger entries; `panic=abort` has ordinary process-abort semantics.

Every input collection has a caller or profile limit; no persistent collection grows past that limit, including reasons, feed IDs, predicates and correction retention in adapters. `fold_insertion_identity`, signal folding and conservation stream over caller slices and allocate no per-lane copies except the winning payload clone. Work is linear in admitted inputs except profile DAG checking bounded at 64 predicates, and site/sweep-event duplicate checking with an ordered set bounded by the admitted input length (`O(n log n)` work and `O(n)` duplicate-set storage). Snapshot output is bounded by selected admitted claims × per-claim reasons. Maximum reserved bytes and allocator accounting are not claimed for generic identity/candidate payloads: the application owns those allocations; collection limits bound cardinality. Vector clone/serde allocation follows ordinary Rust OOM behavior, with `try_reserve` for detectably oversized or admission-controlled library buffers; no universal recoverable OOM claim. Rust `usize` conversion is checked on 32-bit hosts. Clock conversion, syscall timeouts, native cleanup, durable persistence and hostile whole-process memory containment are outside this core.

Structured errors omit raw payloads and write nothing implicitly. Optional CLI diagnostics use bounded escaped IDs/codes, one diagnostic per rejected vector plus a capped truncation signal; no event contents/pointers/pathnames by default. Failures preserve original state and return owned inputs where ownership would otherwise be lost (`Versioned::apply`). Counters never use saturating arithmetic unless the declared counter/signal policy calls for it.

## Resource reservation evaluation

CP12 is a required evaluation deliverable, not automatic addition of a stable allocator API. Compare existing bounded channels/semaphores with p11scope's accepted refreshed shared-ledger successor against two concrete standalone consumers: an event decode → staging → retained-view pipeline and a snapshot ingest → correction/export pipeline. These exercise real allocations/ownership in the new package examples, without claiming the donor product has migrated.

Use an internal test-only move-only `Reservation` with `reserve(count: u64, bytes: u64)`, consuming `transfer(stage: StageId)`, and idempotent internal retirement. A ticket is charged globally until payload storage actually drops; moving queues never refunds/recharges it, cloned shared storage retains one charge, independent copies charge again, failed transfer returns the original ticket, cancellation leaves one owner, and both count and bytes are checked before growth. Oracle conservation is `reserved = live ticket charges`, not the implementation's own total. A missing byte bound yields only a count-bounded conclusion. Test overlap/transient copies separately from retained bytes. Record evidence for accepting a public module only if both consumers share semantics and the ownership/memory accounting is reviewed. Otherwise retain findings and keep production reservations deferred; this does not defer any other CP requirement or invent a memory-bound claim. The plan names an exact proposed pilot interface but no production public reservation export.

## User delivery, validation and completion

Deliver a package README, independent examples `provenance_fold`, `bounded_counts`, `partial_views`, `closure_assessment` and replay-enabled `replay_check`. The examples consume the production library, not test-only mirror implementations. Testkit capture conformance must call a consumer-supplied adapter over that consumer's resolved production code and record its library/version/features/build binding. The shared seam is `scopebase_testkit::adapter::ConformanceAdapter { fn subject(&self) -> SubjectBinding; fn execute(&mut self, invocation: &CaseInvocation, fixture: &FixtureAccess) -> Result<Observation, CaseError>; }`. Invocation is a versioned bounded script; observation is schema-tagged bounded bytes decoded by the independent case oracle; the adapter never returns expected truth. Testkit remains a dev/consumer dependency only. TT01/TT02/TT06/TT07/TT08/TT09/TT10 provide the applicable registry, harness, control, packaging, affected-check, cost and release-profile services; TT03–TT05 filesystem/live work does not gate this pure profile. One offline installed operator route is `scopebase-conformance run --profile capture-core-v1 --fixture-root <installed-dir> --output <writable-dir>`; shared testkit owns runner/exit/verdict plumbing. Canonical runnable profile IDs are `capture-core-v1` and `capture-json-v1`; the latter adds strict replay when advertised. The operator may also pass `--fixture-manifest PATH`. Case/profile identifiers use the shared TT01 constructors: first character ASCII alphanumeric, remaining characters ASCII alphanumeric, dot, underscore or hyphen; no slash; CaseId maximum 96 bytes and ProfileId maximum 64 bytes. No capture-specific identifier parser or slash-bearing case selector is introduced. Required case selection is fixed before discovery: no available-case filtering, required SKIP/BLOCKED/NOT_RUN remains incomplete. Correct expected-refusal can pass its assertion while the capability remains unknown/denied. No Linux fixture or compiler is required by this pure profile.

Qualify two independent standalone consumer binaries, one KryProbe-shaped insertion/loss/counter adapter and one MemVeil-shaped fact-dependency/view/interval adapter, plus an OSSL-shaped alternatives/late-correction adapter. They are actual package consumers with separate `Cargo.toml`/lockfiles and distinct domain reducers, not thin calls into one generic expected-result reducer. Independent ledgers supply expected values; adapter output never supplies its own oracle. Their names and documentation explicitly say “donor-shaped standalone adapter; product migration LATER.” Final product rollout remains LATER in master MG01–MG05 with exact changed-tip producer/object/live and product policy checks. No duplicate is retired from a donor during package qualification.

Completion requires CP-R01–CP-R18 mapped to accepted task outputs; core/default/json/doctests and packaged archives on declared Rust hosts; every required neutral vector and known-bad semantic control; two independent actual consumer builds; source-free offline installed route; bounded/reportable cleanup; artifact/feature/suite matching; provenance notices; and no unchanged design item relabeled implemented. H15/H17/H18 source/models cannot close producer/live gates. BP can later consume these neutral contracts without capture acquiring an SDK dependency. A stable reservation export requires a separate reviewed CP12 decision; its absence must be accurately disclosed.

Unexecuted today: all package compilation, conformance APIs, vectors, adapters, operator commands, MSRV/cross-host checks and runtime qualification. Implementation success will be recorded against actual bytes in issue records and the regression catalog; this specification itself closes no Q/H/UC/G/TODO implementation item.
