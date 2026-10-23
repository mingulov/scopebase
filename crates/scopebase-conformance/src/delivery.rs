// SPDX-License-Identifier: Apache-2.0
//! TT07 delivery execution: measured subjects, bound contracts, engine runs.
//!
//! NEW (TT07): no donor lines copied.
//!
//! The operator never trusts a frozen contract: every `run` regenerates the
//! run contract and vector manifest from the verified closure template plus
//! the linked adapter's measured subject. The template pins the expected
//! package coordinates; anything else is refused before the engine starts, so
//! a differently resolved downstream library is never certified here.

use crate::closure::{self, MANIFEST_FILE};
use crate::error::{OperatorError, OperatorErrorKind};
use crate::receipt;
use scopebase_testkit::{
    ArtifactMeasurer, ArtifactRole, AssertionCheck, AssertionCheckValues, AssertionVerdict,
    AssertionVerdictValues, BindingProvenance, CapabilityEvidence, CapabilityEvidenceValues,
    CapabilityState, CaseCatalog, CaseError, CaseErrorCategory, CaseErrorValues, CaseInvocation,
    CaseOracle, CaseOutcome, CaseSpec, CatalogLimits, CheckStatus, ConformanceAdapter,
    ConsumerBinding, ConsumerBindingValues, Digest256, EffectBatch, EvidenceTier, ExpectedEvidence,
    FixtureAccess, HarnessValidity, Label, Observation, ObservationValues, OpenedVector,
    OracleBinding, OracleBindingValues, ProfileId, ProfilePlan, Qualification, RefusalCause,
    RefusalEvidence, RefusalEvidenceValues, RetireRequest, RetirementReport,
    RetirementReportValues, RunContract, RunLimits, SubjectBinding, SubjectBindingValues,
    VectorBundle, VectorFixtureSession, VectorManifest,
};
use std::ffi::CString;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Delivery profile served by the linked reference adapter.
pub const DELIVERY_PROFILE: &str = "operator-delivery-v1";
/// Contract template file inside a fixture root.
pub const TEMPLATE_FILE: &str = "contract-template.json";
/// Registered adapter source, embedded so the subject pin is exact.
const ADAPTER_SPEC: &str = include_str!("../delivery/adapter-spec.md");
/// Registered oracle source, embedded so the oracle pin is exact.
const ORACLE_SPEC: &str = include_str!("../delivery/oracle-spec.md");
/// Delivery adapter package coordinates.
const ADAPTER_PACKAGE: &str = "scopebase-conformance";
/// Delivery consumer name.
const CONSUMER_NAME: &str = "scopebase-conformance";

/// The mapping policies the operator route understands.
pub const MAPPING_POLICIES: [&str; 2] = ["no-new-target-mappings", "allow-private-calibration"];

/// Reject unknown mapping policies before any planning or execution.
pub fn check_mapping_policy(policy: &str) -> Result<(), OperatorError> {
    if MAPPING_POLICIES.contains(&policy) {
        Ok(())
    } else {
        Err(OperatorError::new(
            OperatorErrorKind::Usage,
            format!("unknown mapping policy: {policy}"),
        ))
    }
}

fn label(text: &str) -> Result<Label, OperatorError> {
    Label::parse(text).map_err(|_| {
        OperatorError::new(
            OperatorErrorKind::Engine,
            format!("internal label rejected: {text}"),
        )
    })
}

/// The reference delivery adapter: serves the TT07 closure/binding cases.
///
/// Its subject is measured at construction: fixed package coordinates and
/// registered-source pins plus the actual host/target and the sha256 of the
/// running executable.
pub struct DeliveryAdapter {
    subject: SubjectBinding,
    // R02: refusal metadata labels, parsed once at construction and
    // truncated per invocation ceiling at use. Fixed strings would
    // overrun small-but-legal label ceilings and panic construction.
    stage_schema: Label,
    stage_operation: Label,
    method_dialect: Label,
    method_operation: Label,
}

impl DeliveryAdapter {
    /// R40: (script schema, step operation, observation kind)
    /// triples, stated where the adapter admits its dialect. The
    /// observation kinds must agree with the oracle's admitted set;
    /// the positive delivery tests prove the agreement end to end.
    const SCRIPT_DIALECT: [(&'static str, &'static str, &'static str); 2] = [
        (
            "tt07-closure-v1",
            "sha256-hex",
            "tt07-closure-v1-observation",
        ),
        (
            "tt07-binding-v1",
            "subject-coords",
            "tt07-binding-v1-observation",
        ),
    ];

    /// Measure the linked delivery subject.
    pub fn new() -> Result<Self, OperatorError> {
        let limits = RunLimits::default();
        let source = Digest256::of_bytes(ADAPTER_SPEC.as_bytes());
        let build_inputs = Digest256::of_bytes(
            format!("tt07-delivery-build-inputs-v1:{}", source.as_str()).as_bytes(),
        );
        let exe = std::env::current_exe().map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::MissingInput,
                format!("cannot locate the running executable: {e}"),
            )
        })?;
        let exe_bytes = std::fs::read(&exe).map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::MissingInput,
                format!("cannot measure the running executable: {e}"),
            )
        })?;
        let executable = Digest256::of_bytes(&exe_bytes);
        let host = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
        let subject = SubjectBinding::new(
            SubjectBindingValues {
                package_name: ADAPTER_PACKAGE.into(),
                package_version: env!("CARGO_PKG_VERSION").into(),
                source_sha256: source,
                build_inputs_sha256: build_inputs,
                features: Vec::new(),
                backend: None,
                host: host.clone(),
                target: host,
                consumer: ConsumerBinding::new(
                    ConsumerBindingValues {
                        name: CONSUMER_NAME.into(),
                        build_inputs_sha256: build_inputs,
                        executable_sha256: executable,
                    },
                    &limits,
                )
                .map_err(|e| engine_error(format!("consumer binding rejected: {e}")))?,
                objects: Vec::new(),
                // Generated from the registered-source pin, measured as the
                // running executable; the engine treats self-reported
                // bindings as incomplete evidence.
                provenance: BindingProvenance::GeneratedBuild {
                    manifest_sha256: source,
                    measurement_sha256: executable,
                },
            },
            &limits,
        )
        .map_err(|e| engine_error(format!("subject binding rejected: {e}")))?;
        Ok(Self {
            subject,
            stage_schema: label("adapter-schema")?,
            stage_operation: label("operation")?,
            method_dialect: label("adapter-dialect")?,
            method_operation: label("delivery-operation")?,
        })
    }

    fn unsupported(&self, i: &CaseInvocation, diagnostic: &[u8]) -> CaseError {
        let l = i.limits();
        CaseError::new(
            CaseErrorValues {
                key: i.key().clone(),
                step_id: None,
                // R02: refusal metadata labels are convenience metadata, not
                // identity. Held labels are truncated to the live ceiling so
                // small-but-legal label ceilings refuse instead of panicking.
                stage: self.stage_schema.truncate(l.label_bytes()),
                category: CaseErrorCategory::UnsupportedSchema,
                errno: None,
                diagnostic_bytes: fit_diagnostic(diagnostic, l),
                cause: RefusalEvidence::new(
                    RefusalEvidenceValues {
                        cause: RefusalCause::Unknown,
                        method: self.method_dialect.truncate(l.label_bytes()),
                        evidence_ids: vec![],
                        tier: EvidenceTier::T0,
                    },
                    l,
                )
                .expect("pre-fitted evidence fits admitted limits"),
                completed_steps: vec![],
                partial_observation: None,
                effects: EffectBatch::empty(l),
            },
            l,
        )
        .expect("pre-fitted refusal fits admitted limits")
    }

    fn failed(
        &self,
        i: &CaseInvocation,
        category: CaseErrorCategory,
        step: Option<Label>,
        completed: Vec<Label>,
        diagnostic: &[u8],
    ) -> CaseError {
        let l = i.limits();
        CaseError::new(
            CaseErrorValues {
                key: i.key().clone(),
                step_id: step,
                // R02: fitted refusal metadata (see unsupported).
                stage: self.stage_operation.truncate(l.label_bytes()),
                category,
                errno: None,
                diagnostic_bytes: fit_diagnostic(diagnostic, l),
                cause: RefusalEvidence::new(
                    RefusalEvidenceValues {
                        cause: RefusalCause::Unknown,
                        method: self.method_operation.truncate(l.label_bytes()),
                        evidence_ids: vec![],
                        tier: EvidenceTier::T0,
                    },
                    l,
                )
                .expect("pre-fitted evidence fits admitted limits"),
                completed_steps: fit_steps(completed, l),
                partial_observation: None,
                effects: EffectBatch::empty(l),
            },
            l,
        )
        .expect("pre-fitted refusal fits admitted limits")
    }
}

/// F10: a ledger file id becomes one path segment under the staging dir,
/// so it must be exactly one normal component (no separators, no parent
/// or self references, no backslash even where the platform would treat
/// it as a plain character).
fn admit_ledger_file_id(file_id: &str) -> Result<(), OperatorError> {
    use std::path::Component;
    let mut components = std::path::Path::new(file_id).components();
    let single_normal = matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(_)), None)
    );
    if file_id.is_empty() || file_id.contains('\\') || !single_normal {
        return Err(OperatorError::new(
            OperatorErrorKind::BrokenPackage,
            format!("ledger file id escapes staging: {file_id:?}"),
        ));
    }
    Ok(())
}

/// F03: truncate a refusal diagnostic to the caller's own byte ceiling so
/// error construction cannot fail (and panic) under small-but-admitted
/// limits.
fn fit_diagnostic(diagnostic: &[u8], limits: &RunLimits) -> Vec<u8> {
    let max = usize::try_from(limits.diagnostic_bytes()).unwrap_or(usize::MAX);
    diagnostic.iter().take(max).copied().collect()
}

/// F03: fit completed steps to the caller's step ceiling, deduplicated:
/// the step bound and the uniqueness rule both hold by construction.
fn fit_steps(completed: Vec<Label>, limits: &RunLimits) -> Vec<Label> {
    let max = usize::try_from(limits.steps_per_invocation()).unwrap_or(usize::MAX);
    let mut out = Vec::new();
    for step in completed {
        if out.len() >= max {
            break;
        }
        if !out.contains(&step) {
            out.push(step);
        }
    }
    out
}

impl ConformanceAdapter for DeliveryAdapter {
    fn subject(&self) -> SubjectBinding {
        self.subject.clone()
    }

    fn execute(
        &mut self,
        i: &CaseInvocation,
        f: &FixtureAccess<'_>,
    ) -> Result<Observation, CaseError> {
        let schema = i.script().schema_id().as_str().to_string();
        let (operation, kind): (String, String) =
            match Self::SCRIPT_DIALECT.iter().find(|t| t.0 == schema) {
                Some(triple) => (triple.1.to_string(), triple.2.to_string()),
                None => return Err(self.unsupported(i, b"unknown delivery schema")),
            };
        let mut values = Vec::new();
        let mut completed = Vec::new();
        for step in i.script().steps() {
            if step.operation().as_str() != operation
                || step.inputs().len() != 1
                || !step.parameters().is_empty()
            {
                return Err(self.unsupported(i, b"unknown delivery operation"));
            }
            let slot = &step.inputs()[0];
            let input = f.input(slot).ok_or_else(|| {
                self.failed(
                    i,
                    CaseErrorCategory::Unavailable,
                    Some(step.step_id().clone()),
                    completed.clone(),
                    format!("missing input slot {}", slot.as_str()).as_bytes(),
                )
            })?;
            let value = match operation.as_str() {
                "sha256-hex" => Digest256::of_bytes(input).as_str(),
                _ => std::str::from_utf8(input)
                    .map_err(|_| {
                        self.failed(
                            i,
                            CaseErrorCategory::InvalidOutput,
                            Some(step.step_id().clone()),
                            completed.clone(),
                            b"coords input is not UTF-8",
                        )
                    })?
                    .to_string(),
            };
            values.push(serde_json::json!({"step_id": step.step_id().as_str(), "value": value}));
            completed.push(step.step_id().clone());
        }
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "kind": kind,
            "steps": values,
        }))
        // RB4: serializing an adapter-built JSON value to a Vec is
        // infallible (no floats, no maps with non-string keys, and Vec
        // writes never fail); the value is constructed above, not parsed.
        .expect("RB4:built JSON value serializes");
        Observation::new(
            ObservationValues {
                key: i.key().clone(),
                schema_id: i.observation_schema().id().clone(),
                schema_revision: *i.observation_schema().revision(),
                completed_steps: completed.clone(),
                bytes,
                effects: EffectBatch::empty(i.limits()),
            },
            i.limits(),
        )
        .map_err(|_| {
            self.failed(
                i,
                CaseErrorCategory::InvalidOutput,
                None,
                completed,
                b"observation exceeds bound",
            )
        })
    }

    fn retire(&mut self, r: &RetireRequest) -> RetirementReport {
        // RB4 (R02): the runner protocol guarantees a nonzero call id
        // (runner sequences from 1; RetireRequest is testkit-internal so
        // no downstream caller can inject 0). The clamp keeps this
        // infallible signature total even against a future producer bug.
        // The request carries no limits, so the adapter default (equal to
        // every maximum these echoed fields touch) is the only ceiling.
        let call_id = r.call_id().max(1);
        RetirementReport::new(
            RetirementReportValues {
                call_id,
                owner: r.owner(),
                scope: r.scope().clone(),
                discovered: vec![],
                transitions: vec![],
                pending_snapshot: r.known_pending().to_vec(),
                complete: true,
                diagnostic: None,
            },
            &RunLimits::default(),
        )
        .expect("RB4:clamped retirement echoes fit adapter limits")
    }
}

/// The literal delivery oracle: byte-exact step comparison.
pub struct DeliveryOracle {
    binding: OracleBinding,
    // RB4 (R02): verdict labels, parsed once at construction. The
    // judging path carries no Label::parse expect; verdicts are the
    // oracle's own fixed products under the default ceiling.
    check_id: Label,
    method: Label,
    evidence_expected: Label,
}

impl DeliveryOracle {
    /// R40: the exact (expected kind, observation kind) pairs this
    /// oracle's dialect admits, stated where the oracle judges — not
    /// in a distant helper. The expected vectors speak the
    /// `-expected` dialect, observations the `-observation` dialect;
    /// only the matched pairs pass.
    const KIND_PAIRS: [(&'static str, &'static str); 2] = [
        ("tt07-closure-v1-expected", "tt07-closure-v1-observation"),
        ("tt07-binding-v1-expected", "tt07-binding-v1-observation"),
    ];

    /// R40: the verdict requires the case's exact expected/actual
    /// kind pair. Missing, crossed or unadmitted kinds fail even
    /// with byte-identical steps.
    fn kinds_pair(expected: Option<&str>, actual: Option<&str>) -> bool {
        match (expected, actual) {
            (Some(want), Some(got)) => Self::KIND_PAIRS.contains(&(want, got)),
            _ => false,
        }
    }

    /// S40: a step list is valid only as a NON-EMPTY array of exact
    /// `{"step_id": <non-empty string>, "value": <string>}` records —
    /// the shape `DeliveryAdapter::execute` produces. Missing, null,
    /// scalar, empty, or malformed step fields fail on EITHER side,
    /// so malformed shapes can never pass by mutual equality
    /// (`None == None`, equal scalars, identical malformed arrays),
    /// and a pass always proves positive coverage: at least one
    /// valid step compared equal.
    fn valid_steps(steps: Option<&serde_json::Value>) -> Option<&Vec<serde_json::Value>> {
        let steps = steps?.as_array()?;
        if steps.is_empty() {
            return None;
        }
        for step in steps {
            let record = step.as_object()?;
            if record.len() != 2 {
                return None;
            }
            match record.get("step_id").and_then(|id| id.as_str()) {
                Some(id) if !id.is_empty() => {}
                _ => return None,
            }
            record.get("value").and_then(|v| v.as_str())?;
        }
        Some(steps)
    }
}

impl DeliveryOracle {
    /// Build the oracle with its pinned, measured identity.
    pub fn new() -> Result<Self, OperatorError> {
        let limits = RunLimits::default();
        let source = Digest256::of_bytes(ORACLE_SPEC.as_bytes());
        let exe = std::env::current_exe().map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::MissingInput,
                format!("cannot locate the running executable: {e}"),
            )
        })?;
        let exe_bytes = std::fs::read(&exe).map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::MissingInput,
                format!("cannot measure the running executable: {e}"),
            )
        })?;
        let binding = OracleBinding::new(
            OracleBindingValues {
                id: label("tt07-literal")?,
                revision: 1,
                schema_id: label("tt07-literal-v1")?,
                source_sha256: source,
                artifact_id: label("delivery-oracle-source")?,
                provenance: BindingProvenance::GeneratedBuild {
                    manifest_sha256: source,
                    measurement_sha256: Digest256::of_bytes(&exe_bytes),
                },
            },
            &limits,
        )
        .map_err(|e| engine_error(format!("oracle binding rejected: {e}")))?;
        Ok(Self {
            binding,
            check_id: label("value.equal")?,
            method: label("independent-literal")?,
            evidence_expected: label("expected")?,
        })
    }
}

impl CaseOracle for DeliveryOracle {
    fn identity(&self) -> OracleBinding {
        self.binding.clone()
    }

    fn evaluate(&self, _: &CaseSpec, e: &ExpectedEvidence, o: &CaseOutcome) -> AssertionVerdict {
        let l = RunLimits::default();
        let expected: serde_json::Value =
            serde_json::from_slice(e.expected_bytes()).unwrap_or(serde_json::Value::Null);
        let actual = match o {
            CaseOutcome::Observed(x) => serde_json::from_slice::<serde_json::Value>(x.bytes()).ok(),
            _ => None,
        };
        let preflight = matches!(o, CaseOutcome::OperationError(error) if *error.category() == CaseErrorCategory::UnsupportedSchema);
        let pass = actual.as_ref().is_some_and(|a| {
            a.get("schema_version") == Some(&serde_json::Value::from(1u64))
                && expected.get("schema_version") == Some(&serde_json::Value::from(1u64))
                && Self::valid_steps(expected.get("steps")).is_some_and(|want| {
                    Self::valid_steps(a.get("steps")).is_some_and(|got| got == want)
                })
                && Self::kinds_pair(
                    expected.get("kind").and_then(|k| k.as_str()),
                    a.get("kind").and_then(|k| k.as_str()),
                )
        });
        AssertionVerdict::new(
            AssertionVerdictValues {
                harness: HarnessValidity::Valid,
                checks: vec![AssertionCheck::new(
                    AssertionCheckValues {
                        id: self.check_id.clone(),
                        status: if preflight {
                            CheckStatus::NotJudged
                        } else if pass {
                            CheckStatus::Pass
                        } else {
                            CheckStatus::Fail
                        },
                        reason: None,
                    },
                    &l,
                )
                .expect("RB4:fixed literal check fits default limits")],
                capability: CapabilityEvidence::new(
                    CapabilityEvidenceValues {
                        state: if preflight {
                            CapabilityState::Unknown
                        } else {
                            CapabilityState::Supported
                        },
                        method: self.method.clone(),
                        context: "TT07 delivery literal comparison".into(),
                        evidence_ids: vec![self.evidence_expected.clone()],
                    },
                    &l,
                )
                .expect("RB4:fixed literal capability fits default limits"),
            },
            &l,
        )
        .expect("RB4:fixed literal verdict fits default limits")
    }
}

fn engine_error(detail: String) -> OperatorError {
    OperatorError::new(OperatorErrorKind::Engine, detail)
}

/// Inputs for one operator run.
pub struct RunRequest<'a> {
    /// Catalog document path (explicit; never repo-relative by default).
    pub catalog_path: PathBuf,
    /// Requested profile identifier.
    pub profile: String,
    /// Fixture root holding the verified closure.
    pub fixture_root: PathBuf,
    /// Closure manifest override (default: `<fixture-root>/fixture-manifest.json`).
    pub manifest_path: Option<PathBuf>,
    /// Contract template override (default: `<fixture-root>/contract-template.json`).
    pub template_path: Option<PathBuf>,
    /// Writable output directory for receipt, staging and run manifest.
    pub output_dir: PathBuf,
    /// Recorded mapping policy.
    pub mapping_policy: String,
    /// Linked subject adapter (reference or downstream).
    pub adapter: &'a mut dyn ConformanceAdapter,
    /// Linked truth oracle.
    pub oracle: &'a dyn CaseOracle,
}

/// The outcome of one operator run.
#[derive(Debug)]
pub struct RunOutcome {
    /// Engine qualification.
    pub qualification: Qualification,
    /// Fresh run identifier.
    pub run_id: String,
    /// Written receipt path.
    pub receipt_path: PathBuf,
}

/// S42: artifacts of the pre-effect run-input preflight.
///
/// Everything pure — ledger-template admission and rendering,
/// contract assembly and bound-contract loading, bundle-manifest
/// assembly and loading — is validated BEFORE the output dir is
/// acquired, so malformed template/contract inputs fail with no
/// run directory at all. Post-acquire failures (staging I/O, the
/// engine, the oracle) are covered by the creating-run manifest
/// written first thing after acquisition, which cleanup already
/// accepts (schema + run id): every failed run is either absent
/// or cleanable, never stranded.
struct PreflightArtifacts {
    /// Validated (file id, staged name, run-bound bytes) per ledger file.
    rendered: Vec<(String, CString, Vec<u8>)>,
    /// Assembled contract bytes (staged post-acquire).
    contract_bytes: Vec<u8>,
    /// Loaded bound contract.
    bound: RunContract,
    /// Assembled bundle-manifest bytes (staged post-acquire).
    manifest_bytes: Vec<u8>,
    /// Loaded vector manifest.
    bundle_manifest: VectorManifest,
}

/// Validate and render every pure run input before output acquisition.
///
/// No filesystem effect: reads go through the verified closure and
/// the in-memory template only. Any error here returns before the
/// output dir exists, so there is nothing to clean up.
#[allow(clippy::too_many_arguments)]
fn preflight_run_inputs(
    catalog: &CaseCatalog,
    plan: &ProfilePlan,
    closure: &closure::VerifiedClosure,
    template: &serde_json::Value,
    adapter: &dyn ConformanceAdapter,
    oracle: &dyn CaseOracle,
    run_id: &str,
) -> Result<PreflightArtifacts, OperatorError> {
    // Regenerate run-bound ledger vectors (rendered in memory; the
    // fixture root itself is never written and staging happens later).
    let layout = template.get("vector_layout").cloned().unwrap_or_default();
    let ledger_templates = template
        .get("ledger_templates")
        .cloned()
        .unwrap_or_default();
    let mut generated: std::collections::BTreeMap<String, (u64, String)> =
        std::collections::BTreeMap::new();
    let mut rendered: Vec<(String, CString, Vec<u8>)> = Vec::new();
    for (file_id, path_value) in ledger_templates.as_object().cloned().unwrap_or_default() {
        admit_ledger_file_id(&file_id)?;
        let rel = path_value.as_str().ok_or_else(|| {
            OperatorError::new(
                OperatorErrorKind::BrokenPackage,
                format!("ledger template path is not a string: {file_id}"),
            )
        })?;
        let raw = closure.read(rel)?;
        let text = std::str::from_utf8(&raw).map_err(|_| {
            OperatorError::new(
                OperatorErrorKind::BrokenPackage,
                format!("ledger template is not UTF-8: {rel}"),
            )
        })?;
        if !text.contains("@RUN_ID@") {
            return Err(OperatorError::new(
                OperatorErrorKind::BrokenPackage,
                format!("ledger template lacks a run-id slot: {rel}"),
            ));
        }
        let bytes = text.replace("@RUN_ID@", run_id).into_bytes();
        let staged_name = CString::new(format!("{file_id}.json")).map_err(|_| {
            OperatorError::new(
                OperatorErrorKind::BrokenPackage,
                format!("ledger file id is not a file name: {file_id:?}"),
            )
        })?;
        generated.insert(
            file_id.clone(),
            (bytes.len() as u64, Digest256::of_bytes(&bytes).as_str()),
        );
        rendered.push((file_id, staged_name, bytes));
    }

    // Assemble the bound contract from the template plus measured values.
    let mut contract = template.clone();
    // RB4: the profile pin above already proves the template is an
    // object, but the proof is implicit and far away; refuse loudly
    // instead of unwrapping on template-file input.
    let object = contract.as_object_mut().ok_or_else(|| {
        OperatorError::new(
            OperatorErrorKind::BrokenPackage,
            "contract template is not an object",
        )
    })?;
    for key in [
        "profile",
        "expected_coordinates",
        "vector_layout",
        "ledger_templates",
    ] {
        object.remove(key);
    }
    contract["run_id"] = run_id.to_string().into();
    contract["catalog_sha256"] = catalog.source_sha256().as_str().into();
    contract["catalog_revision"] = catalog.revision().into();
    contract["selection"] = selection_value(plan);
    contract["expected_subject"] = serde_json::to_value(adapter.subject()).unwrap();
    contract["expected_oracle"] = serde_json::to_value(oracle.identity()).unwrap();
    for artifact in contract
        .get_mut("artifacts")
        .and_then(|a| a.as_array_mut())
        .ok_or_else(|| {
            OperatorError::new(
                OperatorErrorKind::BrokenPackage,
                "contract template lacks artifacts",
            )
        })?
    {
        let id = artifact.get("id").and_then(|i| i.as_str()).unwrap_or("");
        if let Some((length, sha)) = generated.get(id) {
            artifact["length"] = length.to_string().into();
            artifact["sha256"] = sha.clone().into();
        }
    }
    let contract_bytes = serde_json::to_vec(&contract).unwrap();
    let bound = RunContract::load(catalog, plan, &contract_bytes, RunLimits::default())
        .map_err(|e| engine_error(format!("bound contract rejected: {e}")))?;

    // Assemble the vector manifest from the bound contract plus the layout.
    let manifest_value = bundle_manifest(&bound, &layout)?;
    let manifest_bytes = serde_json::to_vec(&manifest_value).unwrap();
    let bundle_manifest = VectorManifest::load(&bound, &manifest_bytes, bound.limits().clone())
        .map_err(|e| engine_error(format!("bundle manifest rejected: {e}")))?;

    Ok(PreflightArtifacts {
        rendered,
        contract_bytes,
        bound,
        manifest_bytes,
        bundle_manifest,
    })
}

/// Execute one profile through the real engine with a verified closure.
///
/// Refusals (missing input, broken package, subject mismatch, unbound
/// profile) return before any output is written.
pub fn run_delivery(request: RunRequest<'_>) -> Result<RunOutcome, OperatorError> {
    run_delivery_inner(request, None)
}

/// S36: phases of the test-only substitution hook.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryHookPhase {
    /// After one staged ledger write, before its descriptor is
    /// retained — the exact write-to-hold window.
    AfterStageWrite,
    /// After all staging writes, before any staged or closure
    /// vector is opened.
    AfterStaging,
}

/// S36: test-only entry point with a substitution hook.
///
/// The hook fires per staged write ([`DeliveryHookPhase::AfterStageWrite`])
/// and once after all staging ([`DeliveryHookPhase::AfterStaging`]) —
/// exactly the windows the FIFO-substitution controls plant in.
/// Production callers use [`run_delivery`]; the hook exists so the
/// interleaving is forced, not raced.
#[doc(hidden)]
pub fn run_delivery_with_hook(
    request: RunRequest<'_>,
    hook: Option<&dyn Fn(DeliveryHookPhase)>,
) -> Result<RunOutcome, OperatorError> {
    run_delivery_inner(request, hook)
}

#[allow(clippy::too_many_lines)]
fn run_delivery_inner(
    request: RunRequest<'_>,
    hook: Option<&dyn Fn(DeliveryHookPhase)>,
) -> Result<RunOutcome, OperatorError> {
    check_mapping_policy(&request.mapping_policy)?;
    // R35: an empty output path previously fell through the old
    // `read_dir` check (`NotFound` admitted) and wrote
    // staging/receipt files into the current directory. Reject it
    // before any I/O. (F11/R36: the output dir itself is acquired
    // exclusively after validation, below.)
    if request.output_dir.as_os_str().is_empty() {
        return Err(OperatorError::new(
            OperatorErrorKind::Usage,
            "output dir must name a directory",
        ));
    }
    // S39: the catalog admits through the bounded reader: an
    // oversized or non-regular catalog refuses here instead of
    // inflating or hanging the run before parser admission.
    let catalog_bytes = closure::read_bounded(&request.catalog_path, closure::MAX_CATALOG_BYTES)
        .map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::MissingInput,
                format!(
                    "cannot read catalog {}: {e}",
                    request.catalog_path.display()
                ),
            )
        })?;
    let catalog = CaseCatalog::load(&catalog_bytes, CatalogLimits::default()).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::MissingInput,
            format!("catalog rejected: {e}"),
        )
    })?;
    let profile_id = ProfileId::parse(&request.profile).map_err(|_| {
        OperatorError::new(
            OperatorErrorKind::UnknownProfile,
            format!("profile id rejected: {}", request.profile),
        )
    })?;
    let plan = ProfilePlan::select(&catalog, &profile_id).map_err(|_| {
        OperatorError::new(
            OperatorErrorKind::UnknownProfile,
            format!("profile is not in the catalog: {}", request.profile),
        )
    })?;
    if plan.required().is_empty() {
        return Err(OperatorError::new(
            OperatorErrorKind::NoBoundAdapter,
            format!("profile selects no required cells: {}", request.profile),
        ));
    }
    let manifest_path = request
        .manifest_path
        .clone()
        .unwrap_or_else(|| request.fixture_root.join(MANIFEST_FILE));
    let closure = closure::verify_closure(&request.fixture_root, &manifest_path)?;
    // F31: the default template is manifest-pinned, so read it through the
    // verified closure: the bytes are re-checked against the pin at use,
    // not just at verification time. An explicit override is caller-chosen
    // outside the closure; its bytes still bind the run because the staged
    // contract (hashed into the receipt) is derived from them.
    let template_bytes = match &request.template_path {
        None => closure.read(TEMPLATE_FILE)?,
        // S39: an explicit override admits through the bounded reader.
        // (Full path: `closure` here names the verified closure value.)
        Some(path) => crate::closure::read_bounded(path, crate::closure::MAX_TEMPLATE_BYTES)
            .map_err(|e| {
                OperatorError::new(
                    OperatorErrorKind::MissingInput,
                    format!("cannot read contract template {}: {e}", path.display()),
                )
            })?,
    };
    let template: serde_json::Value = serde_json::from_slice(&template_bytes).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::BrokenPackage,
            format!("contract template is not JSON: {e}"),
        )
    })?;
    if template.get("profile").and_then(|p| p.as_str()) != Some(request.profile.as_str()) {
        return Err(OperatorError::new(
            OperatorErrorKind::NoBoundAdapter,
            format!(
                "contract template does not bind profile {}",
                request.profile
            ),
        ));
    }
    check_coordinates(&template, request.adapter.subject())?;
    check_oracle_pins(&template, request.oracle.identity())?;

    // Fresh run identity: time, process, thread, sequence and
    // closure binding. Two concurrent runs in one process never mint
    // the same id even on a coarse clock.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let run_id = Digest256::of_bytes(
        format!(
            "tt07-run-v1:{}:{}:{:?}:{}:{}:{}",
            now,
            std::process::id(),
            std::thread::current().id(),
            RUN_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
            closure.manifest_sha256.as_str(),
            request.profile
        )
        .as_bytes(),
    )
    .as_str()[..32]
        .to_string();

    // S42: pre-effect preflight — every pure validation above the
    // acquisition, so malformed inputs fail with no run directory.
    let pre = preflight_run_inputs(
        &catalog,
        &plan,
        &closure,
        &template,
        &*request.adapter,
        request.oracle,
        &run_id,
    )?;

    // R36: acquire fresh run ownership exclusively (exactly one of
    // two concurrent runs wins) and hold it: every write below is
    // descriptor-relative to the acquired dir, never path-resolved.
    let acquired = acquire_output_dir(&request.output_dir)?;
    let staging_fd = rustix::fs::mkdirat(
        acquired.fd.as_fd(),
        c"staging",
        rustix::fs::Mode::from_bits_truncate(0o700),
    )
    .map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::Engine,
            format!("cannot create run staging: {e}"),
        )
    })
    .and_then(|()| {
        rustix::fs::openat(
            &acquired.fd,
            c"staging",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::Engine,
                format!("cannot open run staging: {e}"),
            )
        })
    })?;

    // S42: the creating-run manifest is the first post-acquire
    // effect, before any fallible staging write: a run that fails
    // later still owns a directory cleanup accepts (schema + run
    // id), so the failure is always retriable after cleanup. The
    // final manifest below overwrites it on success.
    let creating = serde_json::json!({
        "schema": "operator-run-manifest-v1",
        "run_id": run_id,
        "profile": request.profile,
        "operator": format!("{} {}", ADAPTER_PACKAGE, env!("CARGO_PKG_VERSION")),
        "mapping_policy": request.mapping_policy,
        "state": "creating",
    });
    write_sealed(
        acquired.fd.as_fd(),
        c"run-manifest.json",
        &serde_json::to_vec_pretty(&creating).unwrap(),
    )
    .map_err(|e| engine_error(format!("cannot write creating manifest: {e}")))?;

    // Stage the preflighted ledger vectors: validated and rendered
    // before acquisition, only the writes happen here.
    // S36: staged ledger files are held open from creation — the
    // creation descriptor itself is retained and rewound, never
    // reopened by name — so a post-write substitution at the staged
    // name (including a writer-less FIFO) cannot block or divert
    // the bundle read below.
    let mut staged: std::collections::BTreeMap<String, std::fs::File> =
        std::collections::BTreeMap::new();
    for (file_id, staged_name, bytes) in pre.rendered {
        let created = write_excl_readable(staging_fd.as_fd(), staged_name.as_c_str(), &bytes)
            .map_err(|e| {
                OperatorError::new(
                    OperatorErrorKind::Engine,
                    format!("cannot stage ledger {file_id}: {e}"),
                )
            })?;
        // S36: substitution-hook window — the bytes are written,
        // the descriptor not yet retained.
        if let Some(hook) = hook {
            hook(DeliveryHookPhase::AfterStageWrite);
        }
        let mut held_file = std::fs::File::from(created);
        std::io::Seek::seek(&mut held_file, std::io::SeekFrom::Start(0)).map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::Engine,
                format!("cannot rewind staged ledger {file_id}: {e}"),
            )
        })?;
        staged.insert(file_id, held_file);
    }

    // Stage the preflighted contract (bound before acquisition).
    write_excl(staging_fd.as_fd(), c"contract.json", &pre.contract_bytes).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::Engine,
            format!("cannot stage contract: {e}"),
        )
    })?;
    let bound = pre.bound;

    // Stage the preflighted bundle manifest (loaded before acquisition).
    write_excl(staging_fd.as_fd(), c"bundle.json", &pre.manifest_bytes).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::Engine,
            format!("cannot stage bundle manifest: {e}"),
        )
    })?;
    let bundle_manifest = pre.bundle_manifest;

    // S36: substitution-hook window — every staging write is done,
    // no staged or closure vector is opened yet.
    if let Some(hook) = hook {
        hook(DeliveryHookPhase::AfterStaging);
    }
    let vector_paths: std::collections::BTreeMap<String, PathBuf> =
        closure.vector_paths().into_iter().collect();
    let mut held: Vec<(Label, std::fs::File)> = Vec::new();
    for file in bundle_manifest.files() {
        let id = file.file_id().as_str().to_string();
        // S36: staged vectors come from the descriptors retained at
        // creation, never a reopened name. Closure vectors admit
        // through a nonblocking same-descriptor open: a
        // post-verification FIFO substitution refuses on the type
        // check instead of blocking, and substituted regular
        // content still fails the bundle measurement below, so a
        // swap fails the run without hanging it.
        let handle = if let Some(staged_file) = staged.remove(&id) {
            staged_file
        } else if let Some(path) = vector_paths.get(&id) {
            open_vector(path, &id)?
        } else {
            return Err(engine_error(format!(
                "vector file has no closure path: {id}"
            )));
        };
        held.push((file.file_id().clone(), handle));
    }
    let opened: Vec<OpenedVector<'_>> = held
        .iter()
        .map(|(id, f)| OpenedVector {
            file_id: id.clone(),
            file: f,
        })
        .collect::<Vec<_>>();
    let mut meter = ArtifactMeasurer::new(bound.run_id().clone(), bound.limits().clone())
        .map_err(|e| engine_error(format!("measurer rejected: {e}")))?;
    let bundle = VectorBundle::read(&bundle_manifest, &opened, &mut meter)
        .map_err(|e| engine_error(format!("bundle read rejected: {e}")))?;
    let mut session = VectorFixtureSession::new(bound.clone(), bundle)
        .map_err(|e| engine_error(format!("session rejected: {e}")))?;

    let report =
        scopebase_testkit::run_profile(&plan, request.adapter, &mut session, request.oracle)
            .map_err(|e| engine_error(format!("engine run rejected: {e}")))?;
    let qualification = report.qualification();

    // R36: the engine run above is long; confirm the output name
    // still addresses our acquired dir before publishing the
    // path-visible artifacts. The sealed writes below are atomic at
    // the name (temp + rename), so readers never see partial bytes.
    acquired.reverify()?;
    let envelope = receipt::build(
        &bound,
        &report,
        &closure,
        &catalog.source_sha256().as_str(),
        &request.profile,
        &request.mapping_policy,
        &run_id,
    )?;
    write_sealed(
        acquired.fd.as_fd(),
        c"receipt.json",
        &serde_json::to_vec_pretty(&envelope).unwrap(),
    )
    .map_err(|e| engine_error(format!("cannot write receipt: {e}")))?;
    let run_manifest = serde_json::json!({
        "schema": "operator-run-manifest-v1",
        "run_id": run_id,
        "profile": request.profile,
        "operator": format!("{} {}", ADAPTER_PACKAGE, env!("CARGO_PKG_VERSION")),
        "mapping_policy": request.mapping_policy,
        "receipt": "receipt.json",
    });
    write_sealed(
        acquired.fd.as_fd(),
        c"run-manifest.json",
        &serde_json::to_vec_pretty(&run_manifest).unwrap(),
    )
    .map_err(|e| engine_error(format!("cannot write run manifest: {e}")))?;
    acquired.reverify()?;

    Ok(RunOutcome {
        qualification,
        run_id,
        receipt_path: acquired.display.join("receipt.json"),
    })
}

/// R36: per-process run-id sequence; two threads minting in the same
/// clock tick still diverge.
static RUN_ID_COUNTER: AtomicU64 = AtomicU64::new(0);
/// R36: per-process sealed-write temp-name sequence.
static SEALED_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// R36: an exclusively acquired output directory. The parent is
/// pinned, the run dir is held open, and its identity was bound at
/// creation; every effect is descriptor-relative to these.
struct AcquiredDir {
    parent: OwnedFd,
    name: CString,
    fd: OwnedFd,
    id: (u64, u64),
    display: PathBuf,
}

impl AcquiredDir {
    /// Confirm the output name still addresses the acquired dir. A
    /// swap or removal refuses instead of publishing under a name
    /// that no longer means this run.
    fn reverify(&self) -> Result<(), OperatorError> {
        let live = rustix::fs::openat(
            &self.parent,
            self.name.as_c_str(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::Engine,
                format!("output dir lost during run: {e}"),
            )
        })?;
        let live_id = rustix::fs::fstat(&live)
            .map(|st| (st.st_dev, st.st_ino))
            .map_err(|e| {
                OperatorError::new(
                    OperatorErrorKind::Engine,
                    format!("output dir not statable: {e}"),
                )
            })?;
        if live_id != self.id {
            return Err(OperatorError::new(
                OperatorErrorKind::Engine,
                "output dir replaced during run",
            ));
        }
        Ok(())
    }
}

/// R36: acquire fresh run ownership. The run dir is created
/// exclusively (`mkdirat` without `EEXIST` tolerance), so two
/// concurrent runs racing the same output cannot both proceed: the
/// loser refuses with a usage error. An existing name of any kind
/// refuses — delivery never inherits another directory.
fn acquire_output_dir(raw: &Path) -> Result<AcquiredDir, OperatorError> {
    let name = raw
        .file_name()
        .filter(|n| *n != "." && *n != "..")
        .ok_or_else(|| {
            OperatorError::new(
                OperatorErrorKind::Usage,
                "output dir must name one directory",
            )
        })?;
    let parent = raw
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name_c = CString::new(name.as_bytes()).map_err(|_| {
        OperatorError::new(
            OperatorErrorKind::Usage,
            "output dir name is not a single component",
        )
    })?;
    std::fs::create_dir_all(parent).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::MissingInput,
            format!("cannot create output parent {}: {e}", parent.display()),
        )
    })?;
    let parent_fd = rustix::fs::open(
        parent,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::MissingInput,
            format!("cannot open output parent {}: {e}", parent.display()),
        )
    })?;
    match rustix::fs::mkdirat(
        &parent_fd,
        name_c.as_c_str(),
        rustix::fs::Mode::from_bits_truncate(0o700),
    ) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {
            return Err(OperatorError::new(
                OperatorErrorKind::Usage,
                format!(
                    "output dir already exists (remove it or choose another path): {}",
                    raw.display()
                ),
            ));
        }
        Err(e) => {
            return Err(OperatorError::new(
                OperatorErrorKind::MissingInput,
                format!("cannot create output dir {}: {e}", raw.display()),
            ));
        }
    }
    let fd = rustix::fs::openat(
        &parent_fd,
        name_c.as_c_str(),
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::Engine,
            format!("cannot open fresh output dir: {e}"),
        )
    })?;
    // Prove the opened dir is the one `mkdirat` created: fresh dirs
    // are empty, `0700`, and owned by us. (A same-uid actor swapping
    // in their own empty `0700` dir inside this window stays inside
    // the operator's trust boundary; every later effect is
    // fd-relative to this descriptor regardless.)
    let st = rustix::fs::fstat(&fd).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::Engine,
            format!("fresh output dir not statable: {e}"),
        )
    })?;
    if st.st_uid != rustix::process::getuid().as_raw() || st.st_mode & 0o777 != 0o700 {
        return Err(OperatorError::new(
            OperatorErrorKind::Engine,
            "fresh output dir ownership mismatch",
        ));
    }
    let mut entries = rustix::fs::Dir::read_from(fd.as_fd()).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::Engine,
            format!("fresh output dir not listable: {e}"),
        )
    })?;
    if entries.any(|entry| {
        entry
            .map(|e| {
                let name = e.file_name();
                name.to_bytes() != b"." && name.to_bytes() != b".."
            })
            .unwrap_or(true)
    }) {
        return Err(OperatorError::new(
            OperatorErrorKind::Engine,
            "fresh output dir is not empty",
        ));
    }
    Ok(AcquiredDir {
        parent: parent_fd,
        name: name_c,
        id: (st.st_dev, st.st_ino),
        fd,
        display: raw.to_path_buf(),
    })
}

/// R36: create one file exclusively under a held directory and write
/// its full bytes. `EXCL` refuses a second writer; `NOFOLLOW`
/// refuses links. Returns the open file for an optional fsync.
/// S36: nonblocking same-descriptor admission for one closure
/// vector. The open never blocks on a FIFO substituted after
/// verification, and the type check binds the regular-file
/// assumption to the descriptor read — not to a name that could be
/// swapped between a stat and an open. Bytes stay hash-pinned at
/// the bundle read, as before.
fn open_vector(path: &Path, id: &str) -> Result<std::fs::File, OperatorError> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| engine_error(format!("cannot open vector {id}: {e}")))?;
    let meta = rustix::fs::fstat(&fd)
        .map_err(|e| engine_error(format!("cannot stat vector {id}: {e}")))?;
    if rustix::fs::FileType::from_raw_mode(meta.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(engine_error(format!("vector {id} is not a regular file")));
    }
    Ok(std::fs::File::from(fd))
}

/// S36: exclusive create-and-write whose descriptor stays readable,
/// for staged files the run itself reads back. `write_excl` stays
/// write-only for publish paths; only the staging loop retains.
fn write_excl_readable(
    dir: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::CStr,
    bytes: &[u8],
) -> Result<OwnedFd, std::io::Error> {
    let fd = rustix::fs::openat(
        dir,
        name,
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )?;
    let mut written = 0;
    while written < bytes.len() {
        // `rustix::io::write` retries `EINTR`; loop for partial writes.
        let n = rustix::io::write(&fd, &bytes[written..])?;
        written += n;
    }
    Ok(fd)
}

fn write_excl(
    dir: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::CStr,
    bytes: &[u8],
) -> Result<OwnedFd, std::io::Error> {
    let fd = rustix::fs::openat(
        dir,
        name,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )?;
    let mut written = 0;
    while written < bytes.len() {
        // `rustix::io::write` retries `EINTR`; loop for partial writes.
        let n = rustix::io::write(&fd, &bytes[written..])?;
        written += n;
    }
    Ok(fd)
}

/// R36: publish one path-visible artifact atomically: exclusive temp
/// write, fsync, same-directory rename, directory fsync. Readers of
/// the final name never see partial bytes, and a crash leaves either
/// the old name or the complete new one (plus a run-owned temp the
/// failed run's cleanup accounts).
fn write_sealed(
    dir: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::CStr,
    bytes: &[u8],
) -> Result<(), std::io::Error> {
    let tmp = CString::new(format!(
        ".tmp-{}-{}",
        std::process::id(),
        SEALED_TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "sealed temp name"))?;
    let fd = write_excl(dir, tmp.as_c_str(), bytes)?;
    rustix::fs::fsync(&fd)?;
    drop(fd);
    if let Err(e) = rustix::fs::renameat(dir, tmp.as_c_str(), dir, name) {
        let _ = rustix::fs::unlinkat(dir, tmp.as_c_str(), rustix::fs::AtFlags::empty());
        return Err(e.into());
    }
    rustix::fs::fsync(dir)?;
    Ok(())
}

/// Refuse oracles whose pinned identity differs from the template.
///
/// Every field is pinned except the per-build measurement digest, which is
/// bound from the linked oracle after the pins pass.
fn check_oracle_pins(
    template: &serde_json::Value,
    identity: OracleBinding,
) -> Result<(), OperatorError> {
    let pinned = template.get("expected_oracle").ok_or_else(|| {
        OperatorError::new(
            OperatorErrorKind::BrokenPackage,
            "contract template lacks its oracle pins",
        )
    })?;
    let actual = serde_json::json!({
        "id": identity.id().as_str(),
        "revision": identity.revision(),
        "schema_id": identity.schema_id().as_str(),
        "source_sha256": identity.source_sha256().as_str(),
        "artifact_id": identity.artifact_id().as_str(),
        "provenance": {
            "kind": "generated_build",
            "manifest_sha256": match identity.provenance() {
                BindingProvenance::GeneratedBuild { manifest_sha256, .. } => {
                    manifest_sha256.as_str()
                }
                BindingProvenance::SelfReported { .. } => String::new(),
            },
        },
    });
    for field in [
        "id",
        "revision",
        "schema_id",
        "source_sha256",
        "artifact_id",
    ] {
        if pinned.get(field) != actual.get(field) {
            return Err(OperatorError::new(
                OperatorErrorKind::SubjectMismatch,
                format!("linked oracle {field} does not match the template pin"),
            ));
        }
    }
    let pinned_provenance = pinned.get("provenance").ok_or_else(|| {
        OperatorError::new(
            OperatorErrorKind::BrokenPackage,
            "contract template lacks oracle provenance pins",
        )
    })?;
    if pinned_provenance.get("kind").and_then(|k| k.as_str()) != Some("generated_build")
        || pinned_provenance.get("manifest_sha256") != actual["provenance"].get("manifest_sha256")
    {
        return Err(OperatorError::new(
            OperatorErrorKind::SubjectMismatch,
            "linked oracle provenance does not match the template pin",
        ));
    }
    Ok(())
}

/// Render the selection binding the engine expects for this plan.
///
/// Mirrors the engine's internal plan binding field-for-field (requested,
/// profiles, extensions, required cells, open owners, completeness) so the
/// generated contract carries the exact selection under test.
fn selection_value(plan: &ProfilePlan) -> serde_json::Value {
    let required: Vec<serde_json::Value> = plan
        .required()
        .iter()
        .map(|cell| {
            serde_json::json!({
                "case_id": cell.case_id().as_str(),
                "case_version": cell.case_version(),
                "cell_id": cell.cell_id(),
                "tier": serde_json::to_value(cell.tier()).unwrap(),
                "implementation_status": serde_json::to_value(cell.implementation_status()).unwrap(),
                "required_by": serde_json::to_value(cell.required_by()).unwrap(),
            })
        })
        .collect();
    serde_json::json!({
        "requested": plan.requested().as_str(),
        "profiles": plan.profiles().iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        "extensions": plan.extensions().iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        "required": required,
        "open_owners": plan.open_owners(),
        "definition_complete": plan.definition_complete(),
    })
}

/// Refuse adapters whose coordinates differ from the template pins.
fn check_coordinates(
    template: &serde_json::Value,
    subject: SubjectBinding,
) -> Result<(), OperatorError> {
    let coords = template.get("expected_coordinates").ok_or_else(|| {
        OperatorError::new(
            OperatorErrorKind::BrokenPackage,
            "contract template lacks expected coordinates",
        )
    })?;
    let actual: [(&str, String); 4] = [
        ("package_name", subject.package_name().clone()),
        ("package_version", subject.package_version().clone()),
        ("source_sha256", subject.source_sha256().as_str()),
        ("consumer", subject.consumer().name().clone()),
    ];
    for (field, value) in actual {
        if coords.get(field).and_then(|v| v.as_str()) != Some(value.as_str()) {
            return Err(OperatorError::new(
                OperatorErrorKind::SubjectMismatch,
                format!("linked subject {field} does not match the template pin"),
            ));
        }
    }
    Ok(())
}

fn bundle_manifest(
    contract: &RunContract,
    layout: &serde_json::Value,
) -> Result<serde_json::Value, OperatorError> {
    let mut files = Vec::new();
    for artifact in contract.artifacts() {
        let role = match artifact.role() {
            ArtifactRole::FixtureInput => "input",
            ArtifactRole::ExpectedVector => "expected",
            ArtifactRole::FixtureLedger => "ledger",
            _ => continue,
        };
        files.push(serde_json::json!({
            "file_id": artifact.id().as_str(),
            "role": role,
            "length": artifact.length().to_string(),
            "sha256": artifact.sha256().as_str(),
        }));
    }
    files.sort_by(|a, b| a["file_id"].as_str().cmp(&b["file_id"].as_str()));
    let mut invocations = Vec::new();
    for key in contract.schedule() {
        let case_id = key.case_key().case_id().as_str().to_string();
        let row = layout.get(&case_id).ok_or_else(|| {
            OperatorError::new(
                OperatorErrorKind::BrokenPackage,
                format!("vector layout lacks case {case_id}"),
            )
        })?;
        let rule = contract
            .case_rules()
            .iter()
            .find(|r| r.case_key() == key.case_key())
            .ok_or_else(|| engine_error(format!("schedule key has no rule: {case_id}")))?;
        let inputs_map = row
            .get("inputs")
            .and_then(|i| i.as_object())
            .ok_or_else(|| {
                OperatorError::new(
                    OperatorErrorKind::BrokenPackage,
                    format!("vector layout lacks inputs for {case_id}"),
                )
            })?;
        let mut inputs = Vec::new();
        for step in rule.script().steps() {
            for slot in step.inputs() {
                let file_id = inputs_map
                    .get(slot.as_str())
                    .and_then(|f| f.as_str())
                    .ok_or_else(|| {
                        OperatorError::new(
                            OperatorErrorKind::BrokenPackage,
                            format!("vector layout lacks slot {}", slot.as_str()),
                        )
                    })?;
                inputs.push(serde_json::json!({"slot": slot.as_str(), "file_id": file_id}));
            }
        }
        inputs.sort_by(|a, b| a["slot"].as_str().cmp(&b["slot"].as_str()));
        let expected_file = row
            .get("expected")
            .and_then(|e| e.as_str())
            .ok_or_else(|| {
                OperatorError::new(
                    OperatorErrorKind::BrokenPackage,
                    format!("vector layout lacks expected for {case_id}"),
                )
            })?;
        let ledger_file = row.get("ledger").and_then(|e| e.as_str()).ok_or_else(|| {
            OperatorError::new(
                OperatorErrorKind::BrokenPackage,
                format!("vector layout lacks ledger for {case_id}"),
            )
        })?;
        invocations.push(serde_json::json!({
            "key": serde_json::to_value(key).unwrap(),
            "inputs": inputs,
            "expected_file": expected_file,
            "ledger_file": ledger_file,
        }));
    }
    Ok(serde_json::json!({
        "schema_version": 1,
        "kind": "tt02-vector-bundle",
        "run_contract_sha256": contract.sha256().as_str(),
        "run_id": contract.run_id().as_str(),
        "files": files,
        "invocations": invocations,
    }))
}

/// Map an engine qualification to its CLI exit code.
pub fn exit_for_qualification(qualification: Qualification) -> i32 {
    match qualification {
        Qualification::Qualified => crate::error::EXIT_OK,
        Qualification::Failed | Qualification::Invalid => crate::error::EXIT_FAILURE,
        Qualification::Incomplete => crate::error::EXIT_INCOMPLETE,
    }
}
