// SPDX-License-Identifier: Apache-2.0
//! SDK03 consumer-side production adapter.
//!
//! [`ConsumerAdapter`] is the actual consumer path under test: it binds one
//! production capture component into an [`AppContext`], validates every raw
//! observation through CP10 [`validate_v1`](scopebase_capture::neutral::validate_v1),
//! and retains the validated result with
//! [`AppContext::capture`](scopebase_sdk::context::AppContext::capture).
//! There is intentionally no unchecked entry: a consumer that skips
//! validation cannot use this adapter.
//!
//! Linkage uses real testkit types. [`ConsumerAdapter::subject`] builds a
//! [`SubjectBinding`] from the actually bound component coordinate, so the
//! production build digest under test is the adapter's own, never the
//! oracle's wish. [`ConsumerAdapter::observation`] emits a real testkit
//! [`Observation`] (schema `sdk03-capture-v1`, revision 1) whose bytes are
//! the deterministic summary below. [`check_conformance`] compares both
//! against the independent [`OracleExpectation`], which the test authors
//! from literals without calling this adapter.
//!
//! Summary layout (all integers little-endian; the oracle reimplements this
//! layout from literals, it never calls [`ConsumerAdapter::observation`]):
//!
//! ```text
//! 0..8    magic "SDK03C1\0"
//! 8..16   epoch ordinal u64
//! 16      origin tag: AdapterReported=1, Synthetic=2, Replayed=3
//! 17      unit tag: Events=1, Records=2, Bytes=3, Objects=4, Attempts=5,
//!         Nonexecutions=6, DiagnosticSignals=7
//! 18..22  counter count u32, then per counter in input order:
//!           channel u32, policy tag u8 (Monotonic=1, Saturating=2,
//!           Modulo=3), policy param u64 (0, maximum, width),
//!           start u64, end u64, value u64
//!         loss count u32, then per loss in input order:
//!           channel u32, kind tag u8 (Discovery=1, Transport=2,
//!           KernelNonexecution=3, Attribution=4, QueueOverflow=5,
//!           MalformedInput=6, DiagnosticTruncation=7), magnitude tag u8
//!           (Unknown=0, Exact=1, AtLeast=2), magnitude u64 (0 for Unknown)
//!         signal count u32, then per signal in input order:
//!           channel u32, observed u8, cap u8
//!         claim count u32, then per claim in input order:
//!           claim u32, reason count u32, reason tags u8 each
//!           (ConsumedLoss=1, MissingEvidence=2, QueryPartial=3,
//!           Ambiguous=4, Capacity=5)
//!         partition count u32, correction count u32
//! ```
//!
//! Opaque capture/producer/binding identities have no byte accessors by
//! design; the summary carries the epoch ordinal and validated rows, while
//! identity equality is asserted separately through the typed ID values.

use scopebase_capture::domain::Origin;
use scopebase_capture::neutral::{
    validate_v1, NeutralLimits, NeutralLossKind, NeutralMagnitude, NeutralObservationV1,
    NeutralPolicy, NeutralReason, NeutralUnit, ValidatedNeutralV1,
};
use scopebase_capture::ContractError;
use scopebase_sdk::context::{AppContext, ComponentBinding, ContextError};
use scopebase_testkit::{
    BackendBinding, BackendBindingValues, BindingProvenance, CaseId, CaseKey, CaseKeyValues,
    ConsumerBinding, ConsumerBindingValues, Digest256, EffectBatch, HarnessError, InvocationKey,
    InvocationKeyValues, Label, Observation, ObservationValues, RunId, RunLimits, SubjectBinding,
    SubjectBindingValues,
};

/// Schema id of the emitted capture-consumption observations.
pub const CONSUME_SCHEMA_ID: &str = "sdk03-capture-v1";
/// Schema revision of the emitted capture-consumption observations.
pub const CONSUME_SCHEMA_REVISION: u32 = 1;
/// Completed-step label recorded on every consumed observation.
pub const CONSUME_STEP_ID: &str = "consume";

/// Consumer-side failure. Validation refusals keep their CP10 [`ContractError`]
/// and capture refusals keep their [`ContextError`]; neither layer is
/// reworded or merged.
#[derive(Debug)]
pub enum ConsumerError {
    /// CP10 refused the raw observation before anything was retained.
    Contract(ContractError),
    /// The context refused the validated snapshot.
    Context(ContextError),
    /// A testkit subject/observation/key value refused construction.
    Harness(HarnessError),
    /// The consumer executable could not be read for its binding hash.
    Io(std::io::ErrorKind),
    /// The bound component carries no artifact digest, so no exact subject
    /// binding can be built from it.
    MissingDigest,
    /// No snapshot has been consumed yet, so no observation can be emitted.
    MissingSnapshot,
}

/// Independent oracle expectation: the production digest the subject must
/// carry and the exact summary bytes its retained snapshot must encode.
/// Authored from literals in the test; never computed by this adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleExpectation {
    /// Expected production artifact digest.
    pub expected_digest: Digest256,
    /// Expected deterministic summary bytes per the layout above.
    pub expected_bytes: Vec<u8>,
}

/// Typed conformance outcome of [`check_conformance`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConformanceFailure {
    /// The adapter's actual production digest differs from the oracle's.
    DigestMismatch {
        expected: Digest256,
        found: Digest256,
    },
    /// The adapter's observation bytes differ from the oracle's, with the
    /// first differing offset when lengths agree on a shared prefix.
    ObservationMismatch {
        expected_len: usize,
        found_len: usize,
        first_diff: Option<usize>,
    },
    /// The adapter could not supply its subject side (no snapshot, no
    /// digest, or a testkit value refusal). The boolean reports whether a
    /// snapshot was present, distinguishing refusal causes without
    /// rewording them.
    AdapterIncomplete { snapshot_present: bool },
}

/// The actual consumer: one bound production component plus its context.
/// Consuming validates first and retains second; both refusals stay typed.
pub struct ConsumerAdapter {
    context: AppContext,
    binding: ComponentBinding,
    limits: RunLimits,
    key: InvocationKey,
    executable_sha256: Digest256,
}

impl ConsumerAdapter {
    /// Bind the actual production component into `context` and fix this
    /// adapter's invocation key and consumer-executable hash. Binding
    /// refusals keep their [`ContextError`].
    pub fn attach(
        mut context: AppContext,
        binding: ComponentBinding,
    ) -> Result<Self, ConsumerError> {
        context
            .bind(binding.clone())
            .map_err(ConsumerError::Context)?;
        let limits = RunLimits::default();
        let key = InvocationKey::new(
            InvocationKeyValues {
                run_id: RunId::parse("0123456789abcdef0123456789abcdef")
                    .map_err(|_| ConsumerError::Io(std::io::ErrorKind::InvalidInput))?,
                case_key: CaseKey::new(
                    CaseKeyValues {
                        case_id: CaseId::parse("SDK03.capture_conformance")
                            .map_err(|_| ConsumerError::Io(std::io::ErrorKind::InvalidInput))?,
                        case_version: 1,
                        cell_id: "host".to_owned(),
                    },
                    &limits,
                )
                .map_err(ConsumerError::Harness)?,
                attempt: 1,
                operation_id: 1,
            },
            &limits,
        )
        .map_err(ConsumerError::Harness)?;
        // The consumer executable is this integration test binary: hash the
        // actual running file rather than inventing a build identity.
        let executable =
            std::env::current_exe().map_err(|error| ConsumerError::Io(error.kind()))?;
        let bytes = std::fs::read(&executable).map_err(|error| ConsumerError::Io(error.kind()))?;
        Ok(ConsumerAdapter {
            context,
            binding,
            limits,
            key,
            executable_sha256: Digest256::of_bytes(&bytes),
        })
    }

    /// Validate `raw` through CP10, then retain the validated snapshot in
    /// the context. Either refusal leaves any prior snapshot unchanged.
    pub fn consume(&mut self, raw: &NeutralObservationV1) -> Result<(), ConsumerError> {
        let validated =
            validate_v1(raw, NeutralLimits::default()).map_err(ConsumerError::Contract)?;
        self.context
            .capture(&validated)
            .map_err(ConsumerError::Context)?;
        Ok(())
    }

    /// The borrowed application context.
    pub fn context(&self) -> &AppContext {
        &self.context
    }
}

impl std::fmt::Display for ConsumerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsumerError::Contract(error) => write!(f, "capture validation refused: {error:?}"),
            ConsumerError::Context(error) => write!(f, "capture retention refused: {error}"),
            ConsumerError::Harness(error) => write!(f, "testkit value refused: {error}"),
            ConsumerError::Io(kind) => write!(f, "consumer executable unreadable: {kind:?}"),
            ConsumerError::MissingDigest => write!(f, "binding carries no artifact digest"),
            ConsumerError::MissingSnapshot => write!(f, "no snapshot consumed yet"),
        }
    }
}

impl std::error::Error for ConsumerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConsumerError::Context(error) => Some(error),
            ConsumerError::Harness(error) => Some(error),
            _ => None,
        }
    }
}

impl ConsumerAdapter {
    /// Whether a snapshot has been consumed.
    pub fn has_snapshot(&self) -> bool {
        self.context.capture_snapshot().is_some()
    }

    /// Build the real subject binding from the actually bound component:
    /// package coordinate strings verbatim, `source_sha256` exactly the
    /// bound artifact digest, and a documented descriptor hash for the
    /// build-inputs slot. Refuses digest-less bindings typed instead of
    /// inventing a digest.
    pub fn subject(&self) -> Result<SubjectBinding, ConsumerError> {
        let digest = self
            .binding
            .artifact_sha256
            .ok_or(ConsumerError::MissingDigest)?;
        let source_sha256 = digest256_from_bytes(&digest)?;
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(self.binding.package.as_bytes());
        descriptor.push(0);
        descriptor.extend_from_slice(self.binding.version.as_bytes());
        descriptor.push(0);
        for feature in &self.binding.features {
            descriptor.extend_from_slice(feature.as_bytes());
            descriptor.push(0);
        }
        if let Some(backend) = &self.binding.backend {
            descriptor.extend_from_slice(backend.as_bytes());
        }
        let build_inputs_sha256 = Digest256::of_bytes(&descriptor);
        let backend = match &self.binding.backend {
            None => None,
            Some(name) => Some(
                BackendBinding::new(
                    BackendBindingValues {
                        name: name.clone(),
                        version: self.binding.version.clone(),
                        source_sha256,
                    },
                    &self.limits,
                )
                .map_err(ConsumerError::Harness)?,
            ),
        };
        SubjectBinding::new(
            SubjectBindingValues {
                package_name: self.binding.package.clone(),
                package_version: self.binding.version.clone(),
                source_sha256,
                build_inputs_sha256,
                features: self.binding.features.clone(),
                backend,
                host: "sdk03-integration".to_owned(),
                target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
                consumer: ConsumerBinding::new(
                    ConsumerBindingValues {
                        name: "sdk03-integration-consumer".to_owned(),
                        build_inputs_sha256,
                        executable_sha256: self.executable_sha256,
                    },
                    &self.limits,
                )
                .map_err(ConsumerError::Harness)?,
                objects: Vec::new(),
                provenance: BindingProvenance::SelfReported {
                    reason: "sdk03-integration-subject".to_owned(),
                },
            },
            &self.limits,
        )
        .map_err(ConsumerError::Harness)
    }

    /// Emit the real observation for the retained snapshot: schema
    /// `sdk03-capture-v1`/1, completed step `consume`, empty effects, and
    /// the deterministic summary bytes. Refuses typed when no snapshot has
    /// been consumed.
    pub fn observation(&self) -> Result<Observation, ConsumerError> {
        let snapshot = self
            .context
            .capture_snapshot()
            .ok_or(ConsumerError::MissingSnapshot)?;
        let bytes = summary_bytes(snapshot);
        Observation::new(
            ObservationValues {
                key: self.key.clone(),
                schema_id: Label::parse(CONSUME_SCHEMA_ID)
                    .map_err(|_| ConsumerError::Io(std::io::ErrorKind::InvalidInput))?,
                schema_revision: CONSUME_SCHEMA_REVISION,
                completed_steps: vec![Label::parse(CONSUME_STEP_ID)
                    .map_err(|_| ConsumerError::Io(std::io::ErrorKind::InvalidInput))?],
                bytes,
                effects: EffectBatch::empty(&self.limits),
            },
            &self.limits,
        )
        .map_err(ConsumerError::Harness)
    }
}

/// Compare produced summary bytes against oracle bytes. Length and first
/// differing offset are reported without copying either side's payload.
pub fn check_observation_bytes(found: &[u8], expected: &[u8]) -> Result<(), ConformanceFailure> {
    if found != expected {
        let first_diff = found
            .iter()
            .zip(expected.iter())
            .position(|(left, right)| left != right)
            .or_else(|| {
                if found.len() != expected.len() {
                    Some(found.len().min(expected.len()))
                } else {
                    None
                }
            });
        return Err(ConformanceFailure::ObservationMismatch {
            expected_len: expected.len(),
            found_len: found.len(),
            first_diff,
        });
    }
    Ok(())
}

/// Compare the adapter's actual subject digest and observation bytes against
/// the independent oracle. Digest mismatch and byte mismatch are distinct
/// typed failures; an adapter that cannot supply its side reports
/// [`ConformanceFailure::AdapterIncomplete`] instead of passing.
pub fn check_conformance(
    adapter: &ConsumerAdapter,
    oracle: &OracleExpectation,
) -> Result<(), ConformanceFailure> {
    let snapshot_present = adapter.has_snapshot();
    let subject = adapter
        .subject()
        .map_err(|_| ConformanceFailure::AdapterIncomplete { snapshot_present })?;
    if *subject.source_sha256() != oracle.expected_digest {
        return Err(ConformanceFailure::DigestMismatch {
            expected: oracle.expected_digest,
            found: *subject.source_sha256(),
        });
    }
    let observation = adapter
        .observation()
        .map_err(|_| ConformanceFailure::AdapterIncomplete { snapshot_present })?;
    check_observation_bytes(observation.bytes(), &oracle.expected_bytes)
}

fn digest256_from_bytes(bytes: &[u8; 32]) -> Result<Digest256, ConsumerError> {
    let mut hex = String::with_capacity(64);
    for byte in bytes {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    Digest256::parse(&hex).map_err(|_| ConsumerError::Io(std::io::ErrorKind::InvalidInput))
}

fn origin_tag(origin: Origin) -> u8 {
    match origin {
        Origin::AdapterReported => 1,
        Origin::Synthetic => 2,
        Origin::Replayed => 3,
    }
}

fn unit_tag(unit: NeutralUnit) -> u8 {
    match unit {
        NeutralUnit::Events => 1,
        NeutralUnit::Records => 2,
        NeutralUnit::Bytes => 3,
        NeutralUnit::Objects => 4,
        NeutralUnit::Attempts => 5,
        NeutralUnit::Nonexecutions => 6,
        NeutralUnit::DiagnosticSignals => 7,
    }
}

fn policy_tag_param(policy: NeutralPolicy) -> (u8, u64) {
    match policy {
        NeutralPolicy::Monotonic => (1, 0),
        NeutralPolicy::Saturating { maximum } => (2, maximum),
        NeutralPolicy::Modulo { width } => (3, u64::from(width)),
    }
}

fn loss_kind_tag(kind: NeutralLossKind) -> u8 {
    match kind {
        NeutralLossKind::Discovery => 1,
        NeutralLossKind::Transport => 2,
        NeutralLossKind::KernelNonexecution => 3,
        NeutralLossKind::Attribution => 4,
        NeutralLossKind::QueueOverflow => 5,
        NeutralLossKind::MalformedInput => 6,
        NeutralLossKind::DiagnosticTruncation => 7,
    }
}

fn magnitude_tag_value(magnitude: NeutralMagnitude) -> (u8, u64) {
    match magnitude {
        NeutralMagnitude::Unknown => (0, 0),
        NeutralMagnitude::Exact(value) => (1, value),
        NeutralMagnitude::AtLeast(value) => (2, value),
    }
}

fn reason_tag(reason: NeutralReason) -> u8 {
    match reason {
        NeutralReason::ConsumedLoss => 1,
        NeutralReason::MissingEvidence => 2,
        NeutralReason::QueryPartial => 3,
        NeutralReason::Ambiguous => 4,
        NeutralReason::Capacity => 5,
    }
}

/// Deterministic summary encoding of one validated snapshot. Reads only the
/// validated accessors; unknown magnitudes and per-claim reasons pass
/// through unchanged.
fn summary_bytes(validated: &ValidatedNeutralV1) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"SDK03C1\0");
    out.extend_from_slice(&validated.source().epoch().ordinal().to_le_bytes());
    out.push(origin_tag(validated.source().origin()));
    out.push(unit_tag(validated.unit()));
    out.extend_from_slice(&(validated.counters().len() as u32).to_le_bytes());
    for counter in validated.counters() {
        out.extend_from_slice(&counter.channel().to_le_bytes());
        let (tag, param) = policy_tag_param(counter.policy());
        out.push(tag);
        out.extend_from_slice(&param.to_le_bytes());
        out.extend_from_slice(&counter.start().to_le_bytes());
        out.extend_from_slice(&counter.end().to_le_bytes());
        out.extend_from_slice(&counter.value().to_le_bytes());
    }
    out.extend_from_slice(&(validated.losses().len() as u32).to_le_bytes());
    for loss in validated.losses() {
        out.extend_from_slice(&loss.channel().to_le_bytes());
        out.push(loss_kind_tag(loss.kind()));
        let (tag, value) = magnitude_tag_value(loss.magnitude());
        out.push(tag);
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&(validated.signals().len() as u32).to_le_bytes());
    for signal in validated.signals() {
        out.extend_from_slice(&signal.channel().to_le_bytes());
        out.push(signal.observed());
        out.push(signal.cap());
    }
    out.extend_from_slice(&(validated.claims().len() as u32).to_le_bytes());
    for claim in validated.claims() {
        out.extend_from_slice(&claim.claim().to_le_bytes());
        out.extend_from_slice(&(claim.reasons().len() as u32).to_le_bytes());
        for reason in claim.reasons() {
            out.push(reason_tag(*reason));
        }
    }
    out.extend_from_slice(&(validated.partition_count() as u32).to_le_bytes());
    out.extend_from_slice(&(validated.correction_count() as u32).to_le_bytes());
    out
}
