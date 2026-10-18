# Shared interface registry

Contract revision 1, 2026-10-18. Owner: SB01. These frozen implementation contracts copy the selected signatures from the normative subsystem specifications. No Rust package or symbol is implemented by this record. A change to a signature, ownership/effect rule or schema updates its specification, this registry, consumers, tests and traceability before dependent work proceeds. Package version `0.1.0`, contract revision, neutral schema version and test case/profile versions are separate identities.

| Contract | Package / module | Implementing owner | Required consumers | Authority and version |
|---|---|---|---|---|
| Retained file owner | `scopebase_linux::file` | LX01/LX02; SB01 freezes handoff | BP04 attachment custody, LX03–LX08 reads/mapping, LX11 clients, SDK04 file observer; NX uses existing bridge ownership | [Linux file API](../superpowers/specs/2026-10-17-scopebase-linux-design.md#public-file-interfaces), revision 1 |
| Consumer conformance adapter | `scopebase_testkit::adapter` and testkit profile runner | TT01/TT02 | LX/BP/CP domain adapters, TT07 installed runner, SDK/NX consumers | [Testing seam](../superpowers/specs/2026-10-17-scopebase-testing-design.md#exact-public-adapter-seam), revision 1; per-invocation schema/case/fixture versions |
| Canonical neutral semantic validation | `scopebase_capture::neutral` | CP10 | CP replay import, SDK metadata, NX07 byte-envelope adapter, independent C/Mojo clients through NX | [Capture seam](../superpowers/specs/2026-10-17-scopebase-capture-design.md#canonical-neutral-validation-seam-for-selective-interoperability), exact neutral v1 |

The registry records provenance and design contracts; it cannot instantiate any runtime authority. Dependencies in the [master plan](../superpowers/plans/2026-10-17-scopebase.md) remain controlling. These entries do not move tasks or profiles to implemented/qualified states.

## Held file

The exact selected public declarations are:

```rust
// scopebase_linux::file
pub struct HeldFile { /* private File and acquisition evidence */ }
pub struct ProcFdResolver { /* private held /proc/self/fd directory */ }
pub enum SymlinkPolicy { Follow, RejectFinal }
impl ProcFdResolver {
    pub fn open_self() -> Result<Self, LinuxError>;
}
impl HeldFile {
    pub fn open(path: &Path, resolver: &ProcFdResolver,
                symlinks: SymlinkPolicy) -> Result<Self, LinuxError>;
    pub fn from_file(file: std::fs::File) -> Result<Self, AdoptFileError>;
    pub fn stat(&self) -> Result<StatObservation, LinuxError>;
    pub fn read_all(&self, limits: ReadLimits,
                    control: &OperationControl) -> Result<FileRead, LinuxError>;
}
impl AsFd for HeldFile {
    fn as_fd(&self) -> BorrowedFd<'_>;
}
```

`AdoptFileError` exposes `error: LinuxError` and `file: File`; refusal returns the submitted owner. `from_file` admits a readable regular descriptor after setting CLOEXEC, preserves open-description status flags and cursor, and reports partial descriptor-flag effects. `open` validates an O_PATH-held regular inode, reopens only through the retained validated proc-fd resolver and revalidates the resulting inode. There is no fallback to the input pathname. `RejectFinal` concerns the final symlink only. Resolver reuse after caller fork without exec is unsupported.

`HeldFile` has no public Clone, raw-owning conversion, mutable File access, Deref or serde implementation. Callers share `Arc<HeldFile>`; attachments retain that Arc alongside backend ownership through successful retirement or explicit unresolved custody. `AsFd` is borrowed integration access, not a universal identity or protection against deliberate raw-FD misuse. `HeldFile`, `ProcFdResolver` and immutable read results are Send+Sync. Positional concurrent reads do not share a cursor; successful reads remain interval observations, not immutable snapshots. File Drop does not produce a fallible native-retirement receipt or promise a hard latency bound.

Dependent read signatures remain the Linux specification's `ReadLimits`, `FileRead`, `ReadObservations`, `ReadCharges` and `OperationControl`; they are not replaced with a testkit reader trait. LX01/LX02 qualify acquisition and reads independently. LX05–LX08 separately implement calibrated mapping/retained range evidence and real filesystem/namespace cells. A file-only increment cannot close mapped-image capability.

## Testkit adapter and runner

The exact seam is:

```rust
pub trait ConformanceAdapter {
    fn subject(&self) -> SubjectBinding;
    fn execute(
        &mut self,
        invocation: &CaseInvocation,
        fixture: &FixtureAccess,
    ) -> Result<Observation, CaseError>;
}

pub fn run_profile(
    plan: &ProfilePlan,
    adapter: &mut dyn ConformanceAdapter,
    fixtures: &mut FixtureSession,
    oracle: &dyn CaseOracle,
) -> Result<RunReport, HarnessError>;
```

`SubjectBinding` names the actual consumer's package/version/features/backend/target/source/build identities. The testkit's separately resolved implementation cannot become the subject. Invocation carries versioned bounded operation data, limits and run/operation IDs; it cannot carry arbitrary shell commands. Fixture access supplies only owned handles/paths/synchronization endpoints for that case. FixtureSession owns separate teardown and workload truth.

Observation supplies a SchemaId and bounded actual bytes; expected evidence comes from an independent fixture or model. `CaseOracle::evaluate(&self, case: &CaseSpec, expected: &ExpectedEvidence, observed: &Observation) -> AssertionVerdict` remains outside the production adapter. `CaseError` retains observed stage/category/partial effects; `HarnessError` means the harness cannot judge. Neither means pass by default. Custom adapter/oracle declarations remain explicitly self-reported.

`CaseId::parse(&str) -> Result<CaseId, IdError>` accepts 1–96 bytes, and ProfileId the same grammar up to 64 bytes: initial ASCII alphanumeric followed by ASCII alphanumeric, dot, underscore or hyphen. There is no trimming, normalization or slash selector. H04 family membership does not by itself produce a runnable subcase. TT01 selects required cases, tiers and cells before discovering environments; TT02 computes independent execution/assertion/capability/coverage/harness/cleanup/qualification outcomes. Required missing evidence remains incomplete.

Production packages do not depend on testkit. Developer adapters, independently installed operator tooling and real distributed consumers use this seam; ordinary downstream cargo test does not execute a dependency's tests. A report deserializer never yields a live process/file/map/link owner.

## Neutral semantic validation

The exact v1 declarations are:

```rust
// scopebase_capture::neutral
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

CP10 owns validation once. Default/max v1 limits are 4,096 counters, 4,096 claims and 16 reasons per claim; callers may lower them, including zero for empty collections. Check counts before cloning; reject duplicate channels/claims/reasons, all-zero byte-array IDs, invalid capped signals and capped signals outside DiagnosticSignals. Exact zero and Unknown remain distinct accepted values; numeric IDs and epoch may be zero. QueryPartial is transient view evidence, not persistent consumed loss.

NX07 owns bounded binary preflight, count×stride arithmetic, discriminants and version mapping before constructing these raw values, then calls `validate_v1`. Capture does not gain a second native codec or competing validation algebra. SDK uses the three validated accessors for metadata; the result creates no trusted completeness, closure, file or process authority. The validator cannot bound Vec allocations already performed by its caller. Replay imports route through the same semantic validator where applicable and retain historical origin; deserialization is not a live observation.

## Cross-owner change gate

Changes to HeldFile invalidate dependent acquisition/read/mapping/attachment/native-owner checks as affected. Changes to the adapter invalidate binding/oracle/runner and all consuming adapters. Changes to neutral v1 semantics invalidate CP10, replay, SDK metadata and NX codec/client vectors. Keep case/profile/schema support revisions and exact consumer/object bindings visible. Root TODO/traceability changes belong to the integration owner; task authors report newly found obligations before dependent implementation proceeds.
