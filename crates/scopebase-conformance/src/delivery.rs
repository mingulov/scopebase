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
    CapabilityState, CaseCatalog, CaseError, CaseErrorCategory, CaseErrorValues,
    CaseInvocation, CaseOracle, CaseOutcome, CaseSpec, CatalogLimits, CheckStatus, ConformanceAdapter,
    ConsumerBinding, ConsumerBindingValues, Digest256, EffectBatch, EvidenceTier, ExpectedEvidence,
    FixtureAccess, HarnessValidity, Label, Observation, ObservationValues,
    OpenedVector, OracleBinding, OracleBindingValues, ProfileId, ProfilePlan, Qualification,
    RefusalCause, RefusalEvidence, RefusalEvidenceValues, RetireRequest, RetirementReport,
    RetirementReportValues, RunContract, RunLimits, SubjectBinding,
    SubjectBindingValues, VectorBundle, VectorFixtureSession, VectorManifest,
};
use std::path::PathBuf;

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
    /// Measure the linked delivery subject.
    pub fn new() -> Result<Self, OperatorError> {
        let limits = RunLimits::default();
        let source = Digest256::of_bytes(ADAPTER_SPEC.as_bytes());
        let build_inputs =
            Digest256::of_bytes(format!("tt07-delivery-build-inputs-v1:{}", source.as_str()).as_bytes());
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
        let (operation, kind): (String, String) = match schema.as_str() {
            "tt07-closure-v1" => ("sha256-hex".into(), "tt07-closure-v1-observation".into()),
            "tt07-binding-v1" => ("subject-coords".into(), "tt07-binding-v1-observation".into()),
            _ => return Err(self.unsupported(i, b"unknown delivery schema")),
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

    fn evaluate(
        &self,
        _: &CaseSpec,
        e: &ExpectedEvidence,
        o: &CaseOutcome,
    ) -> AssertionVerdict {
        let l = RunLimits::default();
        let expected: serde_json::Value =
            serde_json::from_slice(e.expected_bytes()).unwrap_or(serde_json::Value::Null);
        let actual = match o {
            CaseOutcome::Observed(x) => {
                serde_json::from_slice::<serde_json::Value>(x.bytes()).ok()
            }
            _ => None,
        };
        let preflight = matches!(o, CaseOutcome::OperationError(error) if *error.category() == CaseErrorCategory::UnsupportedSchema);
        let pass = actual.as_ref().is_some_and(|a| {
            a.get("schema_version") == Some(&serde_json::Value::from(1u64))
                && expected.get("schema_version") == Some(&serde_json::Value::from(1u64))
                && a.get("steps") == expected.get("steps")
                && kinds_pair(a.get("kind").and_then(|k| k.as_str()))
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

fn kinds_pair(kind: Option<&str>) -> bool {
    matches!(
        kind,
        Some("tt07-closure-v1-observation") | Some("tt07-binding-v1-observation")
    )
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

/// Execute one profile through the real engine with a verified closure.
///
/// Refusals (missing input, broken package, subject mismatch, unbound
/// profile) return before any output is written.
#[allow(clippy::too_many_lines)]
pub fn run_delivery(request: RunRequest<'_>) -> Result<RunOutcome, OperatorError> {
    check_mapping_policy(&request.mapping_policy)?;
    // F11: fresh-run discipline. Cleanup deletes the whole run dir once a
    // run manifest marks it, so delivery only runs into a missing or empty
    // directory: everything under it is then run-owned, and a second run
    // can neither inherit nor orphan another run's files.
    match std::fs::read_dir(&request.output_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(OperatorError::new(
                OperatorErrorKind::MissingInput,
                format!(
                    "cannot inspect output dir {}: {error}",
                    request.output_dir.display()
                ),
            ));
        }
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(OperatorError::new(
                    OperatorErrorKind::Usage,
                    format!(
                        "output dir is not empty (clean it up first): {}",
                        request.output_dir.display()
                    ),
                ));
            }
        }
    }
    let catalog_bytes = std::fs::read(&request.catalog_path).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::MissingInput,
            format!(
                "cannot read catalog {}: {e}",
                request.catalog_path.display()
            ),
        )
    })?;
    let catalog =
        CaseCatalog::load(&catalog_bytes, CatalogLimits::default()).map_err(|e| {
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
        Some(path) => std::fs::read(path).map_err(|e| {
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

    // Fresh run identity: time, process and closure binding.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let run_id = Digest256::of_bytes(
        format!(
            "tt07-run-v1:{}:{}:{}:{}",
            now,
            std::process::id(),
            closure.manifest_sha256.as_str(),
            request.profile
        )
        .as_bytes(),
    )
    .as_str()[..32]
        .to_string();

    let staging = request.output_dir.join("staging");
    std::fs::create_dir_all(&staging).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::MissingInput,
            format!(
                "cannot create output dir {}: {e}",
                request.output_dir.display()
            ),
        )
    })?;

    // Regenerate run-bound ledger vectors under the writable output dir; the
    // fixture root itself is never written.
    let layout = template.get("vector_layout").cloned().unwrap_or_default();
    let ledger_templates = template.get("ledger_templates").cloned().unwrap_or_default();
    let mut generated: std::collections::BTreeMap<String, (PathBuf, u64, String)> =
        std::collections::BTreeMap::new();
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
        let bytes = text.replace("@RUN_ID@", &run_id).into_bytes();
        let staged = staging.join(format!("{file_id}.json"));
        std::fs::write(&staged, &bytes).map_err(|e| {
            OperatorError::new(
                OperatorErrorKind::Engine,
                format!("cannot stage ledger {file_id}: {e}"),
            )
        })?;
        generated.insert(
            file_id,
            (
                staged,
                bytes.len() as u64,
                Digest256::of_bytes(&bytes).as_str(),
            ),
        );
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
    for key in ["profile", "expected_coordinates", "vector_layout", "ledger_templates"] {
        object.remove(key);
    }
    contract["run_id"] = run_id.clone().into();
    contract["catalog_sha256"] = catalog.source_sha256().as_str().into();
    contract["catalog_revision"] = catalog.revision().into();
    contract["selection"] = selection_value(&plan);
    contract["expected_subject"] = serde_json::to_value(request.adapter.subject()).unwrap();
    contract["expected_oracle"] = serde_json::to_value(request.oracle.identity()).unwrap();
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
        if let Some((_, length, sha)) = generated.get(id) {
            artifact["length"] = length.to_string().into();
            artifact["sha256"] = sha.clone().into();
        }
    }
    let contract_bytes = serde_json::to_vec(&contract).unwrap();
    std::fs::write(staging.join("contract.json"), &contract_bytes).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::Engine,
            format!("cannot stage contract: {e}"),
        )
    })?;
    let bound = RunContract::load(&catalog, &plan, &contract_bytes, RunLimits::default())
        .map_err(|e| engine_error(format!("bound contract rejected: {e}")))?;

    // Assemble the vector manifest from the bound contract plus the layout.
    let manifest_value = bundle_manifest(&bound, &layout)?;
    let manifest_bytes = serde_json::to_vec(&manifest_value).unwrap();
    std::fs::write(staging.join("bundle.json"), &manifest_bytes).map_err(|e| {
        OperatorError::new(
            OperatorErrorKind::Engine,
            format!("cannot stage bundle manifest: {e}"),
        )
    })?;
    let bundle_manifest =
        VectorManifest::load(&bound, &manifest_bytes, bound.limits().clone())
            .map_err(|e| engine_error(format!("bundle manifest rejected: {e}")))?;

    let vector_paths: std::collections::BTreeMap<String, PathBuf> =
        closure.vector_paths().into_iter().collect();
    let mut held: Vec<(Label, std::fs::File)> = Vec::new();
    for file in bundle_manifest.files() {
        let id = file.file_id().as_str().to_string();
        let path = if let Some((staged, _, _)) = generated.get(&id) {
            staged.clone()
        } else {
            vector_paths.get(&id).cloned().ok_or_else(|| {
                engine_error(format!("vector file has no closure path: {id}"))
            })?
        };
        let handle = std::fs::File::open(&path)
            .map_err(|e| engine_error(format!("cannot open vector {id}: {e}")))?;
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

    let report = scopebase_testkit::run_profile(&plan, request.adapter, &mut session, request.oracle)
        .map_err(|e| engine_error(format!("engine run rejected: {e}")))?;
    let qualification = report.qualification();

    let receipt_path = request.output_dir.join("receipt.json");
    let envelope = receipt::build(
        &bound,
        &report,
        &closure,
        &catalog.source_sha256().as_str(),
        &request.profile,
        &request.mapping_policy,
        &run_id,
    )?;
    std::fs::write(&receipt_path, serde_json::to_vec_pretty(&envelope).unwrap())
        .map_err(|e| engine_error(format!("cannot write receipt: {e}")))?;
    let run_manifest = serde_json::json!({
        "schema": "operator-run-manifest-v1",
        "run_id": run_id,
        "profile": request.profile,
        "operator": format!("{} {}", ADAPTER_PACKAGE, env!("CARGO_PKG_VERSION")),
        "mapping_policy": request.mapping_policy,
        "receipt": "receipt.json",
    });
    std::fs::write(
        request.output_dir.join("run-manifest.json"),
        serde_json::to_vec_pretty(&run_manifest).unwrap(),
    )
    .map_err(|e| engine_error(format!("cannot write run manifest: {e}")))?;

    Ok(RunOutcome {
        qualification,
        run_id,
        receipt_path,
    })
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
    for field in ["id", "revision", "schema_id", "source_sha256", "artifact_id"] {
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
        let inputs_map = row.get("inputs").and_then(|i| i.as_object()).ok_or_else(|| {
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
