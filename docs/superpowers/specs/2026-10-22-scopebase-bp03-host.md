# BP03 descriptive host capability contract

Date: 2026-10-22. **RATIFIED DESIGN ONLY; IMPLEMENTATION NOT_RUN.**
Sixteen tasks are accepted, including BP02. Independent r2 review resolved
R1–R4 and root ratified all eight choices. This canonical adoption preserves
that exact descriptive host/model increment; it does not accept BP03 or make
an executor packet ready. Actual execution base, accepted API/dependency/source/
archive closure, current TT02 maintenance, tool/cache and writer/resource/output
bindings remain UNBOUND. No complete runtime/conformance profile is qualified.

The requested outcome is a useful host library increment: construct and import
bounded descriptive observations, compare exact contexts, preserve error/stage
facts, assess supplied filter counts, and explicitly execute delivered model
checks against the actual linked package. It supplies no native-observed issuer,
runtime owner or support attestation. Live H22/H33 and installed operator delivery
remain with their existing later owners.

## Approach, alternatives and source basis

Recommended: retain std-only core values/assessment, add an optional bounded JSON
codec using the already admitted exact serde versions, and expose the model
adapter through optional testkit integration. This keeps the core independent of
the testkit and native/BPF toolchains. It adds one narrow codec and a domain
adapter, not a verdict engine. Full native capability probing now would require
unselected objects, causes, cleanup and support cells; it is a later packet.
Unconditional JSON dependencies would simplify feature wiring but enlarge every
host consumer. A new binary format would avoid serde but introduce a second wire
ecosystem without an observed interoperability need. Neither is recommended.

The exact source selection is
the [centrally adopted source admission](../../provenance/admissions/2026-10-22-next-host-scopes.json): P w003 at
`2c2713e66292b0d2688508a25f79e813ae823d81`, bpf-multi `lib.rs:591–605,1179–1192`
and `uretprobe_hazard.rs:34–50`. Its three ranges / 46 lines supply ADAPT material
for the fixed filter predicate/original pure populations and descriptive
hazard/denial/unknown distinctions. Root centrally admitted these exact scopes
with CP05/LX08 at `40ef090`, in
`docs/provenance/admissions/2026-10-22-next-host-scopes.json`, SHA256
`e29cc889d99b73d3790a48fe555f4f74c60c4f718f7e184bd000f142a01e7bc1`.
The immutable admission's two P adoption objects were read and matched here.
This source-only predecessor is now available; it does not ratify the public
API, fixtures or execution base. The older private source patch must not be
applied or used to replace the current ledger.

NEW glue is needed because those selected fragments supply no generic
context-bound observation, checked constructor/provenance, bounded wire format,
four-count decision table, receiving-domain ID bridge or actual-client delivery.
The replacements are fully proposed below. K product gates, O stage/log facts,
M passive profile evidence and P native fixtures are comparisons, without new
copy grants. The K fork/_exit row and zero-cookie self-link remain rejected
behavioral oracles. Existing grant choices, historical GPL provenance, selected
host Apache terms and actual third-party options remain separate records.

## Public surface and value rules

Keep every existing specified name and field unchanged:

```rust
#[non_exhaustive]
pub enum CapabilityState { Supported, Unsupported, Denied, Unknown, Incompatible }
#[non_exhaustive]
pub enum EvidenceStage { Metadata, Object, Load, Attach, Behavior }
#[non_exhaustive]
pub enum HazardState { Clean, Affected, Unknown }

pub struct ProfileId(String);
impl ProfileId {
    pub fn new(value: &str) -> Result<Self, OperationError>;
    pub fn as_str(&self) -> &str;
}

pub struct ProbeContext {
    pub kernel_build: [u8; 32],
    pub btf: Option<ArtifactId>,
    pub architecture: String,
    pub namespace_context: [u8; 32],
    pub security_context: [u8; 32],
    pub topology: [u8; 32],
}

pub struct ProbePopulation {
    pub expected_owned_hits: u64,
    pub observed_owned_hits: u64,
    pub independently_executed_excluded: u64,
    pub observed_excluded_hits: u64,
}
pub fn assess_filter_probe(population: &ProbePopulation)
    -> Result<CapabilityState, OperationError>;
```

Consume the one BP02 root `ArtifactId(pub [u8;32])`; do not redeclare it. All
three enums and ProbePopulation are Debug/Clone/Copy/PartialEq/Eq and Send+Sync.
ProbeContext is Clone/PartialEq/Eq/Send+Sync, with a redacted Debug that prints no
digest or architecture payload. ProfileId is Clone/PartialEq/Eq/PartialOrd/Ord/Hash
and Send+Sync with redacted Debug. There is no Default, Deref, unchecked ID
constructor or mutable checked-observation getter. New ordinary public enums
below are non-exhaustive and Debug/Clone/Copy/PartialEq/Eq/Send+Sync. No numeric
discriminant is a wire contract.

```rust
pub enum ObservationOrigin { CallerDescribed, Imported }
pub enum ObservationOutcome { Completed, Refused, Incomplete }
pub enum DescribedCause {
    Permission, Verifier, License, UnsupportedOperation, Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationErrorSnapshot { /* private scalar fields */ }
impl OperationErrorSnapshot {
    pub fn from_error(error: &OperationError) -> Self;
    pub fn kind(&self) -> ErrorKind;
    pub fn stage(&self) -> Stage;
    pub fn raw_os_error(&self) -> Option<i32>;
    pub fn required_size(&self) -> Option<usize>;
}

pub struct CauseDescriptionInput<'a> {
    pub cause: DescribedCause,
    pub method: &'a str,
    pub evidence_ids: &'a [&'a str],
}
pub struct CapabilityObservationInput<'a> {
    pub object: &'a ArtifactId,
    pub profile: &'a ProfileId,
    pub context: &'a ProbeContext,
    pub state: CapabilityState,
    pub stage: EvidenceStage,
    pub hazard: Option<HazardState>,
    pub operation: &'a str,
    pub step_id: Option<&'a str>,
    pub outcome: ObservationOutcome,
    pub error: Option<OperationErrorSnapshot>,
    pub reason: &'a [u8],
    pub diagnostic: &'a [u8],
    pub cause: CauseDescriptionInput<'a>,
}

pub struct CapabilityObservation { /* private, immutable, descriptive */ }
impl CapabilityObservation {
    pub fn new(input: CapabilityObservationInput<'_>, limits: &Limits)
        -> Result<Self, OperationError>;
    pub fn state(&self) -> CapabilityState;
    pub fn stage(&self) -> EvidenceStage;
    pub fn hazard(&self) -> Option<HazardState>;
    pub fn origin(&self) -> ObservationOrigin;
    pub fn claimed_origin(&self) -> ObservationOrigin;
    pub fn object(&self) -> &ArtifactId;
    pub fn profile(&self) -> &ProfileId;
    pub fn context(&self) -> &ProbeContext;
    pub fn operation(&self) -> &str;
    pub fn step_id(&self) -> Option<&str>;
    pub fn outcome(&self) -> ObservationOutcome;
    pub fn operation_error(&self) -> Option<&OperationErrorSnapshot>;
    pub fn reason(&self) -> &[u8];
    pub fn diagnostic(&self) -> &[u8];
    pub fn cause(&self) -> DescribedCause;
    pub fn cause_method(&self) -> &str;
    pub fn cause_evidence_ids(&self) -> &[String];
    pub fn retained_bytes(&self) -> usize;
    pub fn applies_to(&self, object: &ArtifactId, profile: &ProfileId,
                      context: &ProbeContext) -> bool;

    #[cfg(feature = "json")]
    pub fn to_json(&self, limits: &Limits) -> Result<Vec<u8>, OperationError>;
    #[cfg(feature = "json")]
    pub fn from_json(bytes: &[u8], limits: &Limits)
        -> Result<Self, OperationError>;
}
```

CapabilityObservation is move-only, PartialEq/Eq/Send+Sync, without Clone.
Equality includes local and claimed origin plus every descriptive payload field;
it excludes capacity/accounting details and differs from applicability. Debug
emits at most 256 ASCII bytes, containing state/stage/origin/outcome and payload
presence only; it never formats identities, names, reason, diagnostics or caller
error sources. There is no Hash, Default, Serialize or Deserialize implementation
on the checked observation. Serialization is through the bounded public methods.
Input structs implement Clone/Copy/Send/Sync, without Debug/Default; they are
borrowed plain data with no runtime/serializable authority. Retaining observations
in a caller Arc/cache is permitted; no infallible unmetered payload clone is added.

`new` always sets both origins to CallerDescribed. `from_json` always sets local
origin to Imported and retains the wire `claimed_origin` separately, including
when the wire says caller_described. `to_json` writes claimed_origin, so import
can preserve original wire provenance without recreating a local issuer.
`native_observed` is not a supported origin label. No caller factory, decoder,
test report, trait implementation or public callback can create a more trusted
origin. A future built-in issuer needs a separate reviewed owner contract.

## Exact validation, errors and resource accounting

ProfileId accepts exactly 1..128 ASCII bytes `[a-z0-9][a-z0-9._/-]*`.
Validation order is empty, length, first byte, remaining bytes, allocation.
Empty/length/grammar failures return InvalidInput/Admission with no errno/source
or required_size. Fallible allocation failure returns Backend/Allocate. Before
returning, require the owned String capacity≤128; observed excess returns
LimitExceeded/Allocate with Some(actual capacity), preserving a finite bound
for adapter composition without adding a public footprint API. Never
trim, lowercase, normalize, truncate or substitute a hash. Construction scans at
most 128 admitted bytes; it does not consult a clock, kernel or environment.

For observations, architecture is a descriptive 1..64-byte ASCII token
`[A-Za-z0-9][A-Za-z0-9._-]*`; it is not a supported-architecture whitelist.
Operation, optional step_id, cause method and each cause evidence ID use the
existing testkit Label grammar: 1..96 ASCII bytes, first alphanumeric, remaining
alphanumeric/dot/underscore/hyphen. Evidence IDs number 0..16 and are strictly
byte-sorted without duplicates. Reason permits 0..4096 arbitrary bytes;
diagnostic permits 0..16384 arbitrary bytes. The original error is never traversed
or formatted; `from_error` copies only its four public scalar getters, preserving
all i32 errno values, required_size and the exact BP01 stage/kind. The caller
retains the original source/error object independently.

Constructor preflight reads lengths only, with at most 16 evidence IDs after the
count guard. Let `V` be the sum of profile/architecture/operation/optional step/
cause method/evidence-ID/reason/diagnostic lengths. The operation's logical input
charge is `P = 256 + V + (32 if context.btf.is_some() else 0)`; this fixed charge
covers scalar/digest structure without claiming a C/Rust wire layout. Use checked
usize arithmetic and a checked u64 conversion. Require P ≤ min(input_bytes,65536).
Prepay `W = 128 + 8*P + 8*evidence_id_count` work steps using checked arithmetic.
Require W ≤ work_steps. Work steps are this operation's documented admission
units, not CPU instructions, elapsed nanoseconds or an allocator time bound.

Then validate, in this exact order:

1. Profile bytes (recheck receiving value), architecture, operation, optional
   step_id, cause method, evidence-ID grammar and strict order.
2. Outcome/error shape: Completed requires no error; Refused requires an error;
   Incomplete permits either. Other state/hazard/cause combinations are retained
   verbatim as descriptions. No cause-to-state inference or qualification occurs.
3. Fallibly allocate bounded owned copies and check actual capacities before
   publishing the object. Never retain a caller's over-capacity String/Vec.

Before that semantic sequence, failures occur in the following order: evidence-ID
count maximum16; profile/architecture/operation/optional-step/cause-method/reason/
diagnostic byte maxima in that field order; each evidence-ID byte maximum in
slice order; checked P arithmetic; input cap; checked W arithmetic; work
cap; minimum retained structure charge. Hard maximum or cap failures return
LimitExceeded/Admission; arithmetic/conversion failures return Overflow/Admission;
grammar/order/outcome failures return InvalidInput/Admission. Byte-cap errors set
required_size to the checked required byte count; work/count/grammar failures do
not. Pre-allocation checks use Admission. Allocation failure is Backend/Allocate;
observed-capacity overflow/refusal uses Overflow/Allocate or
LimitExceeded/Allocate as specified in codec-resources.md. All generated errors have errno=None
and source=None and retain no observation payload. Existing OperationError rules
and the independent Limits fields remain unchanged.

Retained charge is `size_of::<CapabilityObservation>()` plus the actual capacities
of each owned String/byte Vec and `evidence_ids.capacity()*size_of::<String>()`
plus capacities of its strings. Count all owned private copies exactly once,
using checked arithmetic. Require charge ≤ min(retained_bytes,131072). Do not
keep borrowed input or temporary decoded copies. Allocator metadata, allocator
rounding beyond reported capacity, input owned by the caller and fixed parser
stack are explicitly outside this retained-payload measure. Thus it is not a
process RSS guarantee. Context/ID/input values retain their stated clone traits,
but the owned observation has no payload Clone bypass. No cumulative global
quota or OOM/unwind guarantee is added. Move-only is an allocation policy, not
a native-authority property; a caller may explicitly share an immutable value
through Arc without cloning its payload.

Sites/live_links/pending_retirements are unused by these operations; zero is
valid. The core performs no I/O or explicit OS observation/control syscall,
fork, signals, seccomp, privilege changes, threads, native handles or elapsed
deadline. Allocator behavior, including its own OS memory acquisition, is the
only library-owned effect. Operations are finite in admitted bytes/work but make
no wall-time promise. All representable Limits configurations remain valid under
BP01; zero caps refuse corresponding positive charges.

## Applicability, separate hazards and stage/cause preservation

`applies_to` is true iff object bytes, unchanged ProfileId bytes, kernel_build,
btf presence/value, architecture bytes, namespace_context, security_context and
topology all equal. It scans only the bounded profile/architecture strings and
fixed digest arrays, allocates nothing and performs no native revalidation.
Some(ArtifactId([0;32])) is distinct from None. Different local/claimed origins,
state/outcome/cause/hazard do not alter matching; an Imported description may
match its descriptive context but cannot authorize anything. There is no API
that skips native checks on this result. Current native denial wins at the
effectful caller regardless of cached Supported data.

Hazard and capability are independently retained. In particular, Denied plus
Some(Clean) remains Denied plus Clean, and Unknown plus Some(Affected) remains
Unknown plus Affected. There is no override/decide API, no Clean→Supported
conversion, no arbitrary signal→Affected classifier and no change to caller
fallback or target policy.

EvidenceStage and BP01 Stage stay distinct. Snapshot every BP01 stage as its own
stable string: admission, metadata, allocate, read, attach, drain, retire,
btf_query, compile, inspect, execute. Preserve that value independently from
EvidenceStage's metadata/object/load/attach/behavior. For a native load error,
EvidenceStage::Load and original Stage::Execute are both retained; neither is
reconstructed from the other. No BP01 Load variant is added. A future unknown
BP01 variant must return Unsupported/Inspect from this version's encoder, rather
than normalize to Execute. Snapshot errno/kind/required_size likewise stay exact.

DescribedCause and all witness IDs/methods remain caller/imported assertions.
Permission/Verifier/License/UnsupportedOperation/Unknown have the same spelling
as TT02 but do not grant its truth or authority. Keep imported causes in the
bounded descriptive payload. Do not add an unused generic cause-to-qualified-
refusal bridge. Adapter operation errors have Unknown actual cause; the model
adapter uses T0 and actual-environment Unknown. TT02's independently bound oracle,
positive twin, equivalence/coverage and intent matrix remain decisive. There is
no generic errno classifier, diagnostic-string cause parser or second qualifier.

## Complete four-count filter table

All u64 combinations are valid descriptive inputs. The existing Result signature
is preserved; at this version no representable population returns Err. There is
no sum, multiplication, division, allocation or overflow. Let E=expected own,
O=observed own, X=independently executed excluded, H=observed excluded hits.
Apply the first matching row:

| Priority | Predicate | Result |
|---|---|---|
| 1 | H > 0 | Incompatible |
| 2 | H == 0 and O > 0 and O != E | Incompatible |
| 3 | H == 0 and not row 2, and E == 0 or O == 0 or X == 0 | Unknown |
| 4 | Otherwise: H == 0, E == O > 0 and X > 0 | Supported |

Parenthesize row 3's disjunction as one predicate after its earlier conditions.
No Unsupported/Denied result is inferred from counts. Thus E=0/O>0, nonzero
short own counts and extra own counts are Incompatible; zero own activity is
Unknown; any excluded hit wins even when another prerequisite is missing; H>X
is still Incompatible, not a fabricated arithmetic/malformed error. MAX values
are compared exactly. The literal rows in filter-cases.json include all priority
intersections and numeric boundaries.

This deliberately retains known supplied failures before missing unrelated
support prerequisites, matching the existing independent-failure rule. It assumes
the supplied expected/observed counts mean what the caller says. It does not
validate an owned operation ledger, per-thread identity, trigger, exclusion or
actual completion. A pure Supported value is a model result. A live support
oracle must additionally establish all those facts, including independent own
completion and actual excluded execution; missing live prerequisites remain
NotJudged/incomplete. The full pure result table is ratified descriptive/model truth,
with no live support ruling.

## Bounded JSON route and explicit feature delta

Propose `scopebase-bpf` feature `json = ["dep:serde", "dep:serde_json"]`, keeping
default=[] and the new core implementation std-only. The inherited Linux package
graph still contains BP02 cfg dependencies, as fixed in delivery.md. Optional
dependencies are exactly:

```toml
serde = { version = "=1.0.229", default-features = false,
          features = ["std"], optional = true }
serde_json = { version = "=1.0.151", default-features = false,
               features = ["std"], optional = true }
```

These match the already admitted capture/TT02 versions and defaults-off host
patterns. No derive, arbitrary_precision, preserve_order, raw_value,
unbounded_depth, native backend or new package/version is required. Root must
approve the changed package feature/notice/dependency closure and lock before
execution; existing closure admission is evidence, not a test of changed code.
Retain actual transitive third-party terms. No fetch/install follows here.

The wire is one UTF-8 JSON object with required schema_version=1,
kind="scopebase-bpf-capability-observation", schema_revision=1, claimed_origin,
object, profile, context, state, stage, hazard, operation, step_id, outcome, error,
reason, diagnostic and cause. The complete literal example is in
observation-fixtures.json. All keys are required; nullable keys must appear.
Context uses exactly the existing six fields. Error uses exactly kind/stage/
raw_errno/required_size. Cause uses exactly kind/method/evidence_ids. Enums use
snake_case, arbitrary bytes/digests use even lowercase hex, raw_errno is an i32
JSON integer or null, required_size is canonical decimal text or null. Unknown
fields/enums, duplicate members, missing fields, floats, numeric byte arrays,
uppercase hex, noncanonical decimals, trailing values and malformed UTF-8 reject.

The writer emits fixed schema field order and no insignificant whitespace.
The reader permits JSON member reordering and JSON whitespace but requires ASCII
without backslash escapes; all legitimate text fields are ASCII and binary
fields are hex. This deliberate canonical-string restriction avoids allocating
unbounded escaped-string scratch. It rejects an escaped alias rather than
normalizing it. Existing input restrictions/values remain representable.

The complete codec phase/error/length contract is [codec-resources.md](#codec-resource-contract).
Its exact metadata-only equations calculate encoded_len before any payload scan,
writer or serializer. Byte, work and minimum retained admission precede encoding;
Backend/Allocate remains distinct on import. This replaces r1's unprepaid counting
writer. Both this contract and that repair text must be read together.

## Testkit bridge and delivered developer route

Propose optional testkit features:

```toml
bpf-host = ["dep:scopebase-bpf"]
bpf-host-json = ["bpf-host", "scopebase-bpf/json"]
scopebase-bpf = { version = "=0.1.0", path = "../scopebase-bpf",
                  default-features = false, optional = true }
```

The dependency line belongs under dependencies, the two feature lines under
features. Testkit remains independent of BPF by default; BPF never depends on
testkit. Do not introduce a bpf dev-dependency cycle. Root owns exports/Cargo/
lock/policy changes. The adapter is `scopebase_testkit::bpf::BpfHostAdapter` in
`src/bpf/adapter.rs` and the exact checked bridge is:

```rust
pub fn profile_to_testkit(value: &scopebase_bpf::ProfileId)
    -> Result<scopebase_testkit::ProfileId, scopebase_testkit::IdError>;
pub fn profile_from_testkit(value: &scopebase_testkit::ProfileId)
    -> Result<scopebase_bpf::ProfileId, scopebase_bpf::OperationError>;

pub struct BpfHostAdapter { /* subject, explicit BPF Limits and RunLimits */ }
impl BpfHostAdapter {
    pub fn new(subject: SubjectBinding,
               bpf_limits: scopebase_bpf::Limits,
               run_limits: RunLimits) -> Result<Self, HarnessError>;
}
impl ConformanceAdapter for BpfHostAdapter { /* existing exact three methods */ }
```

Both bridge functions call the receiving parser on unchanged bytes. BPF→testkit
rejects slash and length65..128. Testkit→BPF rejects uppercase. The intersection
is lowercase/digits/._-, alphanumeric first, at most64 bytes. A differing name
does not become another ID by lowercasing, aliasing or truncation.

The supplied subject is a descriptive post-build binding, not runtime authority.
The exact constructor minima, invocation RunLimits matching, parsing/work charges,
and joint record/output/prefix peak accounting are in
[adapter-resources.md](#adapter-resource-contract). No RunLimits→BPF Limits mapping or
new budget type is introduced. The explicit source/archive feature graph,
inherited BP02 closure, registered targets and complete client manifests are in
[delivery.md](../plans/2026-10-22-scopebase-bp03-verification.md#delivery-resource-contract). Source, compiler, package/version/features, backend,
actual objects, consumer and direct/adapter package identity must match that
externally measured binding. The same-version second-copy negative remains
required; the testkit's copy cannot stand in for the caller's actual dependency.

The exact testkit modes are default, minimal, core-default, core-minimal and
json-union, for both source/archive and both pinned compilers:20 affected cells.
No BPF node is active in baseline resolve graphs. The enabled empty default
still appears as raw testkit [default]; core-default has [bpf-host,default],
core-minimal has [bpf-host], and JSON union has [bpf-host,bpf-host-json]. Isolated
testkit core BPF features are []; the new core-default client's direct BPF edge
adds raw [default]. JSON union has BPF [json]. Preserve both actual graphs. The12
activated cells have24 explicit BP03 client runs. Existing four TT01/TT02 clients
run in all20 cells. Preserve raw isolated/combined resolved dependency features,
including the inherited BP02 Linux union and TT02 serde/derive activation.

These host/model cases have no final BPF object: the context's object ID is
fixture data and is registered as FixtureInput, never FinalObject. SubjectBinding
objects must still match the independently prepared consumer contract exactly.
If a later selected caller case uses real final objects/backends, the caller
must bind their actual final bytes/backend/version/features and required profile;
this T0 adapter/catalog cannot qualify that new case by reusing its own copy or
relabeling a fixture hash. This proposal adds no such object/backend case.

The dialect `bp03-host-v1` has one step, one input slot and no parameters for
assess-filter/to-testkit-profile/from-testkit-profile. The JSON-enabled dialect
`bp03-host-json-v1` additionally permits import-observation (one input) and
context-applies (two inputs). Exact byte formats/cases and typed preflight are in
verification.md. Adapter execution produces only current-key Observation bytes
or CaseError; it never sees ExpectedEvidence. It does not implement CaseOracle
judgment or a capability qualifier. All cases use AssertionOnly/T0 and the oracle
returns CapabilityEvidence::Unknown for the actual environment, even when the
pure returned value is the string supported.

`retire` follows the existing request identity/owner/scope. Normal runs register
no effects and return empty discovered/transitions/pending, complete=true. If a
request unexpectedly contains pending effects, return them unchanged with
complete=false; if uncertainty IDs are present, complete=false. Never erase
pending custody or infer retirement from a no-op. TT02 computes final cleanup.

Deliver primary BPF fixture assets under scopebase-bpf/fixtures/capability-v1.
The two BPF Cargo examples use only BPF APIs. Complete testkit-dependent client
templates and the portable consumer helper ship under testkit/tests/fixtures/bp03;
root client copies must equal the shipped source bytes. Read delivery.md for the
exact path/template/patch/target mapping and explicit toolchain/cache/config roots.
The FixedBeforeExecute vector ledger declares independent fixed expectations and
input/coverage data; it observes no actual adapter entry/return. Measured source,
actual outcomes, direct clients and re-bound semantic controls establish the
separate model-execution evidence, without a new observer or verdict engine.

## Adopted choices and remaining gates

| Group | Proposed review resolution | Cost or remaining admission |
|---|---|---|
| Host API/bounds | Borrowed constructor, move-only allocation policy with Arc sharing, immutable scalar snapshots, exact caps/order | Changed-byte implementation checks remain; no authority follows from move-only |
| Filter truth | Complete priority table above; all typed counts valid; no Err in v0.1 | A pure result trusts descriptions and cannot validate ledger completeness; users must retain later live oracle gates |
| Cause/stage bridge | Preserve both domains, scalar error snapshot, descriptive cause refs | Original source error stays with caller; no generic load classifier or authenticated witness supplied |
| Hazard semantics | Independent optional HazardState, no application policy API | Active hazard fixture/cleanup remains later native work |
| Source admission | The exact three P ranges are centrally admitted in the common immutable next-host-scopes snapshot above | Bind this actual admission and preserve its other-task grants; O/K/M/native/target code remains ungranted for this increment |
| Delivery/registration | Exact local T0 subsets, explicit BPF+RunLimits/joint accounting, inherited targets, complete shipped clients and20 testkit/12 BPF cells | Review adapter-resources.md, codec-resources.md and delivery.md; actual base/cache/outputs remain unbound |
| Live/H33 target closure | Preserve existing later owners and full intent matrix | Finite distro/object/helper/backend/runtime-license/cleanup admissions remain genuinely open, not optionalized |
| Final base | Bind accepted TT02/LX05/BP01/BP02 outputs and current TT02 maintenance | Actual execution SHA/API/source/archive/resource bindings remain UNBOUND; design ratification cannot execute |

Root adopted all eight choices in the r1 review: minimum descriptive/model scope,
filter truth unchanged, move-only plus Arc, restricted JSON, explicit BPF Limits
with joint accounting, FixedBeforeExecute literal ledger limit, stage/cause/
hazard/ID separation and inherited-manifest delivery. The r2 review resolved the
four findings within those choices; root ratified the exact design. Root still
binds accepted post-BP02 artifacts, actual manifests/closure/cache/toolchains/
resources, current TT02 maintenance and final product execution SHA.
No product command, executor/reviewer dispatch, native support/distro choice or
PACKET_READY declaration follows from this documentation adoption.


## Ratification, prerequisite evidence and document map

The immutable reviewed proposal index is SHA256
`50296a4735174931706ef701586785993e7519e61a6ca69233cb0b31b6d858e4` (48 files).
Independent r2 review JSON is
`44cee027f1b81336437c6798bea8d2a6d433197bef05c054a9b5da4132e53da0`, report
`25c06ed50bcd99de0c34da756e66cc2341c956c8fd2aaa0a3effabf82365534d`;
verdict READY_FOR_ROOT_RATIFICATION. Root design ratification JSON is
`c25fbba014a18c2cf3adc2d3350ab9998825689e32c1bc988aedfcc7cfbd9fe7`.
These are design/custody identities, with no product qualification.

[BP02 accepted evidence](../../reviews/2026-10-22-bp02-maps.md) binds task commit
`b2d37fb073ed5132279e7e092662f2de0a8a4faa`, integrated subject
`8f10d948bdd6cf92007870a838d258ee35333eb8`, ledger commit
`6050f379e9990284a8b75a8d20a38b8ef84f9b89` and root acceptance JSON
`8e4b198337d8979088fa4c63be9c058fa14c6f0baa16eaec300ba6404fefa06d`.
Those historical accepted receipts do not bind BP03's future source/archive/API,
dependency/feature/lock, tool/cache, resources or current TT02 maintenance.
Documentation preparation reference base is `fbfaae7ee81d1b5627ff81109b67c6650969fae8`;
it is not a new execution-base authority. Root binds actual current inputs in
the executor packet. Full BP03/native/operator/profile obligations remain open.

Reviewed shorthand names resolve to the following canonical sections/assets.
All resource equations and closed delivery recipes remain normative together.

| Reviewed name | Canonical location |
|---|---|
| contract.md | This contract |
| adapter-resources.md | [Adapter resource contract](#adapter-resource-contract) |
| codec-resources.md | [Codec resource contract](#codec-resource-contract) |
| verification.md | [Verification plan](../plans/2026-10-22-scopebase-bp03-verification.md) |
| plan.md | [Implementation sequence](../plans/2026-10-22-scopebase-bp03-verification.md#implementation-sequence) |
| delivery.md | [Delivery resource contract](../plans/2026-10-22-scopebase-bp03-verification.md#delivery-resource-contract) |
| finite JSON, raw literals, manifest fragments and templates | [Normative support assets](bp03-host/README.md) |

All eight ratified choices are fixed: descriptive/model minimum scope; unchanged
complete filter table; move-only allocation policy with Arc sharing; restricted
ASCII/no-backslash JSON; explicit BPF Limits plus RunLimits and joint accounting;
FixedBeforeExecute declaration without entry/return observation; separate stage/
cause/hazard/ID domains; inherited accepted BP02 manifest/source/archive delivery.
R1 adapter composition, R2 codec admission/errors, R3 literal-ledger limits and
R4 complete target/client/cell/tool/cache recipes are adopted exactly. The
support assets remain authoring seeds/templates until implemented and measured.


## Adapter resource contract

Status: ratified R1 repair under the adopted explicit-BPF-Limits choice.
This specifies the existing TT02 adapter implementation only. It adds no public
budget type, observer, fixture engine or verdict mechanism.

```rust
impl BpfHostAdapter {
    pub fn new(subject: SubjectBinding,
               bpf_limits: scopebase_bpf::Limits,
               run_limits: RunLimits) -> Result<Self, HarnessError>;
}
```

Store all three values immutably. There is no RunLimits→BPF Limits conversion,
implicit unlimited work, milliseconds→work conversion or environment-derived cap.
No public setter/lowering method is added. Sites/live_links/pending_retirements
are stored unchanged but unused. Zero BPF input/work/retention caps are valid
configuration; the corresponding adapter operation refuses positive charges.

## Constructor and invocation binding

new has this order: validate subject against run_limits; call bpf_limits.validate;
check fixed response minima below; compute the checked actual stored footprint B;
check the checked reservation B+F against run_limits.retained_bytes; then store.
Subject bound errors retain the accepted HarnessError kind. Inadequate minima,
footprint overflow or reservation return HarnessErrorKind::LimitExceeded, bounded
diagnostic `bp03 adapter admission`, with no partial report. No public operation
input is read. The typed subject is moved, not cloned; oversized caller capacities
are included in B and refused rather than silently retained uncharged.

| RunLimits field | Minimum for this adapter | Purpose |
|---|---:|---|
| name_bytes | 256, the current accepted maximum | Represent every admitted invocation cell string in a binding-error response |
| label_bytes | 32 | Fixed schema, stage and method labels |
| diagnostic_bytes | 128 | All fixed error tokens plus exact scalar demand |
| observation_bytes | 128 | All core result forms |
| input_slots | 2 | The complete declared core/JSON adapter vocabulary |
| steps_per_invocation | 1 | Its one-step dialect |
| retained_bytes | B+F, checked | Stored value and response reserve |

Other RunLimits fields retain their ordinary checked constraints; these are
adapter minima, not changes to RunLimits. Larger JSON results are admitted per
invocation below. The 256-byte name minimum is deliberately explicit: current
CaseKey admission uses name_bytes≤256, while CaseId/RunId have their own fixed
bounds. This lets the adapter return a checked current-key binding error even
for a legal invocation declaring different smaller or larger selected limits.

execute first compares all invocation.limits values with the stored run_limits.
Any inequality returns CaseErrorCategory::InvalidOutput at stage `binding`,
method `bp03-model`, diagnostic `run-limits-mismatch`, step_id=None, errno=None,
Unknown cause, no completed steps/partial observation and empty complete effects.
It uses the stored run_limits for this response, never the rejected invocation
limits. No script/input content is read and no BPF work is admitted. The current
key must be a valid TT02 key, as provided by accepted RunContract/run_profile;
the response reserve covers its current hard string bounds. No response is
claimed valid under a different rejected limit selection. Constructor tests
also prove a smaller otherwise legal RunLimits selection is rejected before
any adapter can promise labels/diagnostics it cannot construct.

With equality established, whole-script schema/op/feature/arity/parameter
preflight precedes fixture input access. Unsupported dialect is the existing
typed UnsupportedSchema shape, stage `preflight`, method `bp03-model`, diagnostic
`unsupported-dialect`; no attempted step/progress/errno/cause/effects. Fixed
labels are at most32 bytes. Generated diagnostics use only a fixed token table,
known enum tokens and at most20 decimal digits; they never exceed128 bytes or
format untrusted payload/error sources. Library refusals use `bpf:<kind>/<stage>`
and optionally `;required=<decimal>`, preserving the raw errno separately.

The current one-step key/schema/step metadata is copied into responses under
the stored checked ceiling. Name/label/diagnostic allocation is part of the
reserve F. Standard TT02 record construction retains its existing allocator/OOM
limits; this contract does not promise recovery from process-wide allocator
failure. Injected operation-allocation tests keep the separately reserved
response path available and assert the logical checked record is constructible.

## One private per-invocation ledger

B is size_of::<BpfHostAdapter>() plus actual heap capacities recursively owned by
the stored SubjectBinding, without counting inline fields twice. Include each
String capacity, Vec element storage capacity and nested string capacity in
features/backend/consumer/artifacts/provenance. RunLimits/BPF Limits are inline.
F is `8192 + max(size_of::<CaseError>(), size_of::<Observation>(),
size_of::<RetirementReport>())`, checked; it is a conservative response
reservation, not an assertion that this much memory was allocated.

For every execute call start a new private ledger with:

`H = min(bpf_limits.retained_bytes, 262144,
         checked_usize(run_limits.retained_bytes)-B-F)`.

The subtraction is checked at constructor admission. J is the sum of the
currently live operation-owned payload charges: every BPF observation's
retained_bytes; temporary ID storage; each standalone Vec struct plus its actual
capacity; owned result/prefix bytes and any other operation-owned copy. Borrowed
FixtureAccess bytes, immutable invocation metadata, caller-owned input storage,
allocator metadata and fixed parsing stack are excluded. No source input is
cloned. The actual response header is bounded by F; its moved payload is removed
from J at handoff, never counted as a second owned copy. Before publication/drop
or another allocation, check B+F+J≤run_limits.retained_bytes and J≤H.

Before an allocation reserve its minimum requested charge; after it succeeds
replace that request by actual capacity and recheck before writing/publishing.
All ledger arithmetic is checked. Deallocation removes an actual live charge,
but consumed work is never refunded. On failure, drop operation temporaries and
use F to construct the exact CaseError; no partial observation escapes. The
ceiling is joint across records/buffers, never reset per record or native call.

The required trait method subject() returns the existing TT02 SubjectBinding
clone. The returned metadata belongs to the caller/runner and is outside the
execute-only J ledger; the adapter retains no second subject copy. This retains
the existing TT02 metadata-allocation/OOM contract and confers no native authority.
No claimed execute memory ceiling includes the caller's metadata/report history.

The BPF APIs already return observation.retained_bytes. For short-lived ProfileId
calls reserve size_of::<BPF ProfileId>()+128 and
size_of::<testkit ProfileId>()+64 before either parser. The proposed BPF ID
constructor must check its reported String capacity≤128 before return (observed
excess is LimitExceeded/Allocate). A crate-private testkit IDs helper may inspect
its own existing private String capacity for actual charging; it changes no
public ID API/grammar. The exact narrow helpers, defined in ids.rs only under
cfg(feature="bpf-host"), are:

```rust
pub(crate) fn bp03_profile_capacity(value: &ProfileId) -> usize;
pub(crate) fn bp03_label_capacity(value: &Label) -> usize;
pub(crate) fn bp03_case_id_capacity(value: &CaseId) -> usize;
pub(crate) fn bp03_run_id_capacity(value: &RunId) -> usize;
```

Each returns only the existing private String's capacity. Size_of additions and
overflow/ceiling checks stay in the adapter's private ledger, not in new public
traits. The latter three helpers permit actual subject/response capacity charges
without guessing string capacity from length. Check actual TT ID capacity before
publishing it. Its
owned-copy behavior remains the accepted unchanged receiving parser. No new
public trait, allocator hook or fallible-copy API is introduced.

## Input, work and output rules

After dialect admission, borrow the required slots. Missing slots return
InvalidOutput/input with diagnostic `missing-input`, Unknown cause and current
step, without calling a public operation. Length-only checks precede byte scans:

| Operation | Hard input bound / framing | Known prepaid charges before input scan |
|---|---|---|
| assess-filter | 84 bytes; exactly4 canonical decimal-u64 LF lines | Wp=64+4*L plus8 assessment units plus56 output-copy units |
| to-testkit-profile / from-testkit-profile | 130 bytes; one UTF-8 ID and terminal LF, no interior LF/CR | Wp=64+4*L plus512 parser/bridge units plus166 output-copy units |
| import-observation | One slot≤65536 bytes | Wp=64+4*L plus Wdecode(L)=1024+32*L |
| context-applies | Two slots≤65536 each, base then candidate | Wp=64+4*(Lbase+Lcandidate) plus both Wdecode charges plus1024 comparison/output units |

For every operation require each slot≤run_limits.vector_bytes and the checked
sum L≤min(run_limits.input_bytes,bpf_limits.input_bytes,hard operation bound).
Core framing/numeric errors are InvalidOutput/input with `invalid-input`, no
completed step; all BPF calls remain unentered. An accepted UTF-8 profile with
invalid source/receiving ID grammar instead returns the specified pure
source-id-error/receiving-id-error value, preserving r1 semantics.

Maintain one checked u64 consumed-work counter, capped by the explicit
bpf_limits.work_steps. Prepay all table-known charges before the first byte
scan. For import, after decoding compute E by the fixed length-only algebra,
then additionally prepay `Wencode(E)=1024+32*E` plus
`Wprefix(E)=32+2*(E+9)` before encoding or prefix copying. Neither a library
call's local Limits nor a later buffer resets this counter. Direct filter logic
still accepts all u64 populations; its adapter may refuse reporting/parsing
resources independently. No count-derived cause or support authority is added.

Before each decoder pass a Limits copy with the already-admitted call work
allowance and retained_bytes≤the remaining joint H/J allowance (also bounded by
the direct record's131072 cap). Keep original non-work/resource values. This
prevents a second decoder from independently reusing the full joint allowance.
No implicit work allowance comes from RunLimits or execution_ms.

For context-applies the live peak is `Dbase+Dcandidate+result Vec struct/capacity`.
Pre-admit the result Vec struct plus five bytes; fallibly reserve exactly five
bytes once, measure/check that capacity and keep this same Vec through output
handoff, including for the four-byte true result. Then decode base, retain/charge Dbase, and
lower the second call's retained allowance to the remaining joint budget.
Refuse before comparison if the sum cannot fit. A budget admitting each record
alone but not their sum must not publish two records or a successful result.

For import-observation output is exactly9 ASCII bytes `imported\n` followed by
the E-byte canonical JSON. Require E+9≤run_limits.observation_bytes before
encoding. The live peak is:

`J = D + (size_of::<Vec<u8>>()+Cjson)
       + (size_of::<Vec<u8>>()+Cprefixed)`.

Before to_json, admit the requested peak with Cjson=E and Cprefixed=E+9. Reserve
the future prefixed Vec charge while passing to_json a local retained limit
including its receiver D and the available JSON Vec charge, at most131072.
After to_json returns replace Cjson by actual capacity and recheck before
allocating the prefixed Vec. Recheck actual Cprefixed before copying any bytes.
Drop the decoded record and original JSON Vec, then move the prefixed Vec into
Observation. Never keep a hidden third copy or prepend with an unchecked grow.

Core results require their exact byte length≤run_limits.observation_bytes and
charge their Vec struct/capacity under J before output copying. Profiles' valid
result is at most67 bytes; fixed error values are shorter. Context results are
true/false, filter values supported/incompatible/unknown. No truncation occurs.

## Refusal priority and selected fixture caps

For a matched invocation, priority is whole-dialect preflight; missing slots;
per-slot hard/vector bounds in script input order; checked total/input ceiling;
checked known work/prepayment; joint minimum payload reserve; input framing;
public operation phases; dynamic JSON encode/prefix admission; publication.
Resource failures are CaseErrorCategory::Refused at `admission` (or the actual
library Inspect/Allocate stage after a call), current step set, Unknown cause,
errno=None unless a real library error supplies one, empty completion/partial/
effects. Diagnostic overflow never replaces an intended refusal: the fixed
128-byte construction path was admitted by new. Checked composition arithmetic
uses `bpf:overflow/admission`; work uses `bpf:limit_exceeded/admission` with no
required byte demand. Byte/retention caps include exact required bytes in the
bounded diagnostic. A library Backend/Allocate remains visible, not Malformed.

The shipped positive model recipe passes explicit BPF Limits:
input_bytes=131072, retained_bytes=262144, work_steps=8388608,
sites=0, live_links=0, pending_retirements=0. These are finite fixture choices,
not defaults or native support policy. Each external run records these exact
values separately from the complete RunLimitValues. New tests lower one bound
at a time and assert the intended refusal/zero-activity counter/restored twin.

retire retains the existing TT02 identity/pending/uncertainty behavior. Normal
model runs own no native resources. A request with insufficient remaining TT02
retirement budget is judged by the existing runner's CalledOverBudget/Incomplete
rules; a provider complete flag cannot override that result. This design changes
no TT02 engine accounting, report origin or retirement qualification.

## Codec resource contract

Status: ratified R2 repair under the root-adopted restricted-JSON choice;
final execution base/resource binding remains open. This normative section
replaces r1's counting pass.
The public to_json/from_json signatures, schema1, required nullable fields,
ASCII/no-backslash rule and all descriptive-origin rules are unchanged.

## Length-only encoding preflight

Calculate E, the exact encoded byte length, from immutable field lengths, enum
tokens, presence bits and bounded integer widths. Do not invoke serde, a writer,
collect_str, a byte iterator, a payload validator or a counting serializer to
calculate E. Constructor/import already admitted the payload. Exactly17 top
fields,6 context fields,4 error fields,3 cause fields and16 evidence IDs are
visited; strlen/Vec::len is O(1). Decimal width uses at most20 numeric divisions;
i32::MIN uses unsigned_abs before measuring its10 digits plus sign. No payload
byte is examined before work admission.

Use these exact checked equations; every addition/multiplication and usize/u64
conversion is checked before using the result:

| JSON value | Encoded length |
|---|---|
| Raw ASCII string of length n | 2+n |
| Binary/ArtifactId value of n bytes, lowercase hex string | 2+2*n |
| null | 4 |
| JSON unsigned integer v | decimal_digits(v), with digits(0)=1 |
| Raw i32 errno v | decimal_digits(v.unsigned_abs()) + (1 if v<0 else0) |
| Optional required_size=None | 4 |
| Optional required_size=Some(v) | 2+decimal_digits(checked_u64(v)) |
| Array with n string values of encoded lengths L_i | 2 + (n-1 if n>0 else0) + sum(L_i) |
| Object with n fixed keys k_i and value lengths L_i | 2 + (n-1) + sum(3+len(k_i)+L_i) |

Top object keys, in writer order, are schema_version,kind,schema_revision,
claimed_origin,object,profile,context,state,stage,hazard,operation,step_id,outcome,
error,reason,diagnostic,cause. Version/revision are raw1 integers; kind and all
enum tokens use their exact declared spelling. Context keys are kernel_build,
btf,architecture,namespace_context,security_context,topology. Error is null or
kind,stage,raw_errno,required_size. Cause is kind,method,evidence_ids. reason and
diagnostic are hex. Every string representation is unescaped ASCII. In particular
quotes, separators and nulls are included by the equations; no capacity is used
as a semantic field length.

The testkit adapter uses this same frozen length algebra over the public getters
for its composition preflight. It may implement a private length-only routine;
no new public length API or generic serializer/budget trait is added. Its result
must equal the actual returned to_json length and independent literal lengths.
Bind both routines' source bytes in the case/preservation map; do not reuse the
production codec as the independent expected-length oracle.

## Entry-point phase order

to_json performs these phases exactly:

1. Read only bounded field lengths/presence/scalars; reject a future enum token
   this schema cannot represent as Unsupported/Inspect. Calculate E with checked
   arithmetic. No semantic re-scan of already admitted payload takes place.
2. Require E≤min(limits.input_bytes,65536).
3. Calculate W=1024+32*E with checked u64 arithmetic; require W≤work_steps.
4. Calculate M=record.retained_bytes()+size_of::<Vec<u8>>()+E. Require
   M≤min(limits.retained_bytes,131072), before allocating or visiting payload.
5. try_reserve_exact(E) once. Recalculate M using actual output capacity; check
   the same retained ceiling. A fixed-capacity writer may fill only that buffer.
6. Serialize once in fixed field order. Reject an internal length mismatch or
   attempted growth without returning a partial Vec. Never silently truncate.

The bounded metadata arithmetic in phases1–4 is permitted at work_steps=0;
no payload-counting, formatting, hex loop or serializer entry is permitted. The
zero-work test counter observes these payload paths separately from the fixed
metadata preflight. Lower input byte caps win before zero work; zero work wins
before retained-byte caps if wire bytes fit.

from_json performs the existing phases, now with complete failure mapping:

1. Borrow bytes; require len≤min(input_bytes,65536).
2. Checked W=1024+32*len; require W≤work_steps before ASCII or JSON scans.
3. Scan ASCII/no-backslash; reject invalid UTF-8/non-ASCII/escapes.
4. Fixed borrowed typed shape admission: exact known members/types, duplicate
   bitsets, fixed reference slots, maximum nesting depth3 and a fixed container stack. No ignored unknown value,
   generic Value tree or payload ownership. Structural faults take precedence
   over schema/semantic faults in either member order.
5. Check all required fields, then schema_version/kind/schema_revision.
6. Decode enums/hex/canonical decimals/receiving IDs in fixed schema field order,
   then the shared constructor semantic/copy sequence. The wire-based work charge
   already includes this work; do not reset or double-charge it.
7. Set local Imported and preserve claimed_origin; publish only the complete
   immutable record.

Shape admits raw integral errno through i64/u64 before the phase6 checked i32
conversion; floats are a shape error. A JSON integer outside serde_json's admitted
i64/u64 representation is Malformed/Inspect during shape admission. Decimal
required_size remains a borrowed string through phase5. Noncanonical decimal text
is Malformed/Inspect; canonical decimal overflow/platform narrowing is
Overflow/Inspect. Schema failure precedes these semantic errors once shape fits.
Missing required null is a shape error. Unknown enum strings are semantic errors.

Borrowed visitors reject shape faults with fixed static error tokens. Do not
format a caller key/value through serde unknown_field/invalid_value helpers,
collect_str or an error source. Discard serde errors without retaining their
text; expose only the mapped BP01 scalars. No untrusted error message becomes
an extra payload copy or diagnostic. Standard serde/std allocation failure and
process-wide OOM limitations remain; retained_bytes measures the owned returned
payload, not allocator metadata or all transient library error machinery.

## Complete codec error table

Every generated codec error has errno=None and source=None. No error yields a
partial record/Vec. required_size is exact checked byte demand for a byte ceiling;
it is absent for work/count/schema/grammar or arithmetic errors. Never format an
error source while constructing these errors.

| Entry / condition | ErrorKind / Stage | required_size |
|---|---|---|
| Either: metadata/length/work/retention arithmetic or platform conversion overflow before allocation | Overflow / Inspect | None |
| to_json: unknown future enum token | Unsupported / Inspect | None |
| to_json: E above selected/hard wire cap | LimitExceeded / Inspect | Some(E) |
| to_json: prepaid W above selected work cap | LimitExceeded / Inspect | None |
| to_json: minimum record+output M above selected/hard retained cap | LimitExceeded / Inspect | Some(M) |
| from_json: raw len above selected/hard wire cap | LimitExceeded / Inspect | Some(len) |
| from_json: prepaid W above selected work cap | LimitExceeded / Inspect | None |
| from_json: ASCII/escape/UTF-8, shape, required member or noncanonical semantic field | Malformed / Inspect | None |
| from_json: supported shape but wrong schema_version/kind/schema_revision | Unsupported / Inspect | None |
| from_json: canonical numeric conversion overflow | Overflow / Inspect | None |
| from_json: hard evidence-count maximum exceeded | LimitExceeded / Inspect | None |
| from_json: hard field byte maximum exceeded | LimitExceeded / Inspect | Some(field decoded byte length) |
| from_json: minimum owned-record retention above selected/hard cap | LimitExceeded / Inspect | Some(minimum owned charge) |
| Either: try_reserve_exact fails | Backend / Allocate | None |
| Either: observed capacity/charge arithmetic overflows after allocation | Overflow / Allocate | None |
| Either: actual capacity charge exceeds admitted retained cap | LimitExceeded / Allocate | Some(actual charge) |
| to_json: internal serializer length/growth disagreement after successful admission | Backend / Inspect | None |

The shared constructor's grammar/order/shape InvalidInput maps to
Malformed/Inspect for import. Preserve Backend/Allocate and the post-allocation
Overflow/Allocate or LimitExceeded/Allocate; do not remap allocation failures to
Malformed. Typed new continues its Admission-stage semantic/preflight errors;
its observed-capacity refusal likewise uses Allocate. This clarification changes
no native operation stage or caller-supplied error snapshot.

Minimum owned charge is computed before allocation from fixed record size,
requested string/byte lengths and requested evidence-ID slot storage. After each
fallible allocation, replace requested capacity by actual reported capacity in
the same checked ledger. Allocator metadata/stack and caller-owned input remain
outside retained payload. Nothing claims a process RSS or wall-time bound.

## Required discriminating controls

Add direct encoder tests using an already valid record: input cap E-1 wins over
work0; at input E, work0 fails with no required_size and payload_counter=0;
at W, retained M-1 fails with Some(M) before encoding; at exact minima the valid
twin succeeds. A writer/hex-loop-before-prepayment mutant must increment the
counter or perform a forbidden payload action and fail the intended assertion.

Use malformed member-reordering twins from codec-cases.json: duplicate or unknown
field plus unsupported revision is Malformed in either order; supported shape
with unsupported revision plus bad enum/hex is Unsupported in either order;
supported schema plus bad semantic fields is Malformed. Add injected allocation
failure after valid shape/schema/semantics and sufficient budgets; expected is
Backend/Allocate with no payload, not a setup crash. All are PLANNED/NOT_RUN.
