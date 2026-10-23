// SPDX-License-Identifier: Apache-2.0
//! TT03 fixture manifest admission: closed keys, exact scenario scripts and
//! closed control pairings. Normative: contract-data.json manifest/scenarios/
//! controls sections.
use super::wire::{Action, Actor};
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestError {
    detail: String,
}
impl ManifestError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
    pub fn detail(&self) -> &str {
        &self.detail
    }
}
impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "manifest: {}", self.detail)
    }
}
impl std::error::Error for ManifestError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scenario {
    LeaderLifecycle,
    TrickyComm,
    ExecAba,
    ExecFailure,
    ThreadLifecycle,
    FileReplacement,
    DescriptorInventory,
}
impl Scenario {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "leader-lifecycle" => Self::LeaderLifecycle,
            "tricky-comm" => Self::TrickyComm,
            "exec-aba" => Self::ExecAba,
            "exec-failure" => Self::ExecFailure,
            "thread-lifecycle" => Self::ThreadLifecycle,
            "file-replacement" => Self::FileReplacement,
            "descriptor-inventory" => Self::DescriptorInventory,
            _ => return None,
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LeaderLifecycle => "leader-lifecycle",
            Self::TrickyComm => "tricky-comm",
            Self::ExecAba => "exec-aba",
            Self::ExecFailure => "exec-failure",
            Self::ThreadLifecycle => "thread-lifecycle",
            Self::FileReplacement => "file-replacement",
            Self::DescriptorInventory => "descriptor-inventory",
        }
    }
    pub fn steps(self) -> &'static [ScenarioStep] {
        match self {
            Self::LeaderLifecycle => LEADER_LIFECYCLE,
            Self::TrickyComm => TRICKY_COMM_STEPS,
            Self::ExecAba => EXEC_ABA_STEPS,
            Self::ExecFailure => EXEC_FAILURE_STEPS,
            Self::ThreadLifecycle => THREAD_LIFECYCLE_STEPS,
            Self::FileReplacement => FILE_REPLACEMENT_STEPS,
            Self::DescriptorInventory => DESCRIPTOR_INVENTORY_STEPS,
        }
    }
    pub fn prepare_prefix_len(self) -> usize {
        match self {
            Self::LeaderLifecycle
            | Self::ExecAba
            | Self::ExecFailure
            | Self::ThreadLifecycle => 1,
            Self::TrickyComm => 2,
            Self::FileReplacement | Self::DescriptorInventory => 3,
        }
    }
    pub fn successful_execs(self) -> u32 {
        match self {
            Self::ExecAba => 2,
            _ => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScenarioStep {
    pub id: &'static str,
    pub action: Action,
    pub actor: Actor,
}

use Action as ActionConst;
use Actor as ActorConst;
const fn step(id: &'static str, action: ActionConst, actor: ActorConst) -> ScenarioStep {
    ScenarioStep { id, action, actor }
}
const LEADER_LIFECYCLE: &[ScenarioStep] = &[
    step("s01-ready", ActionConst::Ready, ActorConst::A),
    step("s02-live", ActionConst::CaptureRaw, ActorConst::A),
    step("s03-exit", ActionConst::ParentExit, ActorConst::Parent),
    step("s04-zombie", ActionConst::CaptureRaw, ActorConst::A),
    step("s05-reap", ActionConst::ParentReap, ActorConst::Parent),
    step("s06-reaped", ActionConst::CaptureRaw, ActorConst::A),
    step("s07-close", ActionConst::Close, ActorConst::Parent),
];
const TRICKY_COMM_STEPS: &[ScenarioStep] = &[
    step("s01-ready", ActionConst::Ready, ActorConst::A),
    step("s02-comm", ActionConst::SetTrickyComm, ActorConst::A),
    step("s03-live", ActionConst::CaptureRaw, ActorConst::A),
    step("s04-exit", ActionConst::ParentExit, ActorConst::Parent),
    step("s05-zombie", ActionConst::CaptureRaw, ActorConst::A),
    step("s06-reap", ActionConst::ParentReap, ActorConst::Parent),
    step("s07-reaped", ActionConst::CaptureRaw, ActorConst::A),
    step("s08-close", ActionConst::Close, ActorConst::Parent),
];
const EXEC_ABA_STEPS: &[ScenarioStep] = &[
    step("s01-ready", ActionConst::Ready, ActorConst::A),
    step("s02-a", ActionConst::CaptureRaw, ActorConst::A),
    step("s03-exec-b", ActionConst::ExecB, ActorConst::A),
    step("s04-b", ActionConst::CaptureRaw, ActorConst::A),
    step("s05-exec-a", ActionConst::ExecA, ActorConst::A),
    step("s06-a2", ActionConst::CaptureRaw, ActorConst::A),
    step("s07-close", ActionConst::Close, ActorConst::Parent),
];
const EXEC_FAILURE_STEPS: &[ScenarioStep] = &[
    step("s01-ready", ActionConst::Ready, ActorConst::A),
    step("s02-before", ActionConst::CaptureRaw, ActorConst::A),
    step("s03-missing", ActionConst::ExecMissing, ActorConst::A),
    step("s04-after", ActionConst::CaptureRaw, ActorConst::A),
    step("s05-close", ActionConst::Close, ActorConst::Parent),
];
const THREAD_LIFECYCLE_STEPS: &[ScenarioStep] = &[
    step("s01-ready", ActionConst::Ready, ActorConst::A),
    step("s02-start-sibling", ActionConst::StartSibling, ActorConst::A),
    step("s03-sibling", ActionConst::CaptureRaw, ActorConst::A),
    step("s04-exit-leader", ActionConst::ExitLeader, ActorConst::A),
    step("s05-leader-exited", ActionConst::CaptureRaw, ActorConst::A),
    step("s06-missing", ActionConst::ExecMissing, ActorConst::A),
    step("s07-still-sibling", ActionConst::CaptureRaw, ActorConst::A),
    step("s08-exec-sibling", ActionConst::ExecFromSibling, ActorConst::A),
    step("s09-new-image", ActionConst::CaptureRaw, ActorConst::A),
    step("s10-close", ActionConst::Close, ActorConst::Parent),
];
const FILE_REPLACEMENT_STEPS: &[ScenarioStep] = &[
    step("s01-ready", ActionConst::Ready, ActorConst::A),
    step("s02-create-files", ActionConst::CreateFiles, ActorConst::A),
    step("s03-offer-files", ActionConst::OfferFiles, ActorConst::Parent),
    step("s04-original", ActionConst::CaptureRaw, ActorConst::A),
    step("s05-replace", ActionConst::ReplaceFileA, ActorConst::A),
    step("s06-replaced", ActionConst::CaptureRaw, ActorConst::A),
    step("s07-unlink", ActionConst::UnlinkOriginalA, ActorConst::A),
    step("s08-mutate", ActionConst::MutateFileA, ActorConst::A),
    step("s09-mutated", ActionConst::CaptureRaw, ActorConst::A),
    step("s10-close", ActionConst::Close, ActorConst::Parent),
];
const DESCRIPTOR_INVENTORY_STEPS: &[ScenarioStep] = &[
    step("s01-ready", ActionConst::Ready, ActorConst::A),
    step("s02-create-files", ActionConst::CreateFiles, ActorConst::A),
    step("s03-offer-files", ActionConst::OfferFiles, ActorConst::Parent),
    step("s04-inventory", ActionConst::Inventory, ActorConst::Parent),
    step("s05-responding-ab", ActionConst::CaptureRaw, ActorConst::A),
    step("s06-close", ActionConst::Close, ActorConst::Parent),
];

/// Closed outage-injection triple, consumed by the TT02 prepare wiring and
/// the developer driver. Pairing validity is checked by
/// [`control_pairing_applies`] before any native effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Control {
    pub kind: String,
    pub step_id: String,
    pub point: String,
}

fn malformed_kinds() -> &'static [&'static str] {
    &[
        "wrong_run",
        "wrong_operation",
        "wrong_sequence",
        "wrong_step",
        "unknown_major",
        "extra_fd",
        "truncated_payload",
        "truncated_ancillary",
    ]
}

fn cancel_after_actions() -> &'static [&'static str] {
    &[
        "ready",
        "capture_raw",
        "set_tricky_comm",
        "exec_b",
        "exec_a",
        "exec_missing",
        "start_sibling",
        "exit_leader",
        "exec_from_sibling",
        "create_files",
        "replace_file_a",
        "unlink_original_a",
        "mutate_file_a",
    ]
}

fn control_applies(kind: &str, step: &ScenarioStep, point: &str, scenario: Scenario) -> bool {
    let at = |id: &str, action: Action, point_name: &str| {
        step.id == id && step.action == action && point == point_name
    };
    match kind {
        "parent_failure_after_register" => {
            step.id == "s01-ready"
                && step.action == Action::Ready
                && matches!(
                    point,
                    "after_case_root_register" | "after_child_register" | "after_pidfd_register"
                )
        }
        "worker_exit" => {
            at("s01-ready", Action::Ready, "after_root_grant")
                || at("s02-create-files", Action::CreateFiles, "after_file_register")
        }
        "partial_file_write" => {
            scenario == Scenario::FileReplacement
                && at("s08-mutate", Action::MutateFileA, "before_ack")
        }
        "inherit_canary" => {
            scenario == Scenario::DescriptorInventory
                && at("s04-inventory", Action::Inventory, "before_inventory_exec")
        }
        "cancel_before_create" => at("s01-ready", Action::Ready, "before_first_creation"),
        "cancel_after_ack" => {
            point == "immediately_after_ack"
                && cancel_after_actions().contains(&step.action.as_str())
        }
        k if malformed_kinds().contains(&k) => {
            at("s01-ready", Action::Ready, "before_ack") && step.actor == Actor::A
        }
        _ => false,
    }
}

/// Public pairing check for driver/worker arming: the named step must be in
/// the scenario script and the closed (kind, step, point) pairing must apply.
/// This is the same predicate manifest admission uses; driver and worker
/// re-check it before any native effect so a directly constructed [`Control`]
/// cannot arm an inapplicable outage.
pub fn control_pairing_applies(
    kind: &str,
    step_id: &str,
    point: &str,
    scenario: Scenario,
) -> bool {
    match scenario.steps().iter().find(|s| s.id == step_id) {
        Some(step) => control_applies(kind, step, point, scenario),
        None => false,
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct AdmittedInvocation {
    pub operation_id: u64,
    pub scenario: Scenario,
    pub key_bytes: Vec<u8>,
    pub control: Option<Control>,
    pub expected_file_a_hex: Option<Vec<u8>>,
    pub expected_file_b_hex: Option<Vec<u8>>,
    pub mutation_hex: Option<Vec<u8>>,
    pub driver_schedule: Option<Vec<u8>>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct AdmittedManifest {
    pub run_hex: String,
    pub image_a_artifact: String,
    pub image_b_artifact: String,
    pub limits: Vec<(String, u64)>,
    pub invocations: Vec<AdmittedInvocation>,
}

fn closed_keys(value: &serde_json::Value, keys: &[&str], what: &str) -> Result<(), ManifestError> {
    let map = value
        .as_object()
        .ok_or_else(|| ManifestError::new(format!("{what} must be an object")))?;
    if map.len() != keys.len() || keys.iter().any(|k| !map.contains_key(*k)) {
        return Err(ManifestError::new(format!("{what} keys must be exactly closed")));
    }
    Ok(())
}

fn decode_hex_field(value: &serde_json::Value, name: &str) -> Result<Option<Vec<u8>>, ManifestError> {
    if value.is_null() {
        return Ok(None);
    }
    let s = value
        .as_str()
        .ok_or_else(|| ManifestError::new(format!("{name} must be hex or null")))?;
    if s.len() % 2 != 0
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ManifestError::new(format!("{name} must be lowercase hex")));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| ManifestError::new(format!("{name} hex decode")))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

pub fn admit_manifest(bytes: &[u8], expected_run_hex: &str) -> Result<AdmittedManifest, ManifestError> {
    if bytes.len() > 6_569_984 {
        return Err(ManifestError::new("manifest exceeds encoded ceiling"));
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ManifestError::new("manifest is not JSON"))?;
    closed_keys(
        &value,
        &[
            "schema_version",
            "kind",
            "run_id",
            "image_a_artifact",
            "image_b_artifact",
            "limits",
            "invocations",
        ],
        "manifest",
    )?;
    if value["schema_version"] != 1 || value["kind"] != "tt03-linux-fixture" {
        return Err(ManifestError::new("manifest schema or kind"));
    }
    let run_hex = value["run_id"].as_str().unwrap_or("").to_string();
    if run_hex.len() != 32
        || !run_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ManifestError::new("run_id must be 32 lowercase hex"));
    }
    if run_hex != expected_run_hex {
        return Err(ManifestError::new("manifest run_id must equal contract"));
    }
    for key in ["image_a_artifact", "image_b_artifact"] {
        match value[key].as_str() {
            Some(s) if !s.is_empty() && s.len() <= 96 => {}
            _ => return Err(ManifestError::new("image artifact label")),
        }
    }
    let limits_map = value["limits"]
        .as_object()
        .ok_or_else(|| ManifestError::new("limits must be an object"))?;
    let mut limits = Vec::with_capacity(limits_map.len());
    for (k, v) in limits_map {
        let n = v
            .as_u64()
            .ok_or_else(|| ManifestError::new("limits values must be u64"))?;
        limits.push((k.clone(), n));
    }
    let raw_invocations = value["invocations"]
        .as_array()
        .ok_or_else(|| ManifestError::new("invocations must be an array"))?;
    if raw_invocations.is_empty() || raw_invocations.len() > 16 {
        return Err(ManifestError::new("invocation count must be 1..16"));
    }
    let mut invocations = Vec::with_capacity(raw_invocations.len());
    let mut seen_ops = std::collections::BTreeSet::new();
    for raw in raw_invocations {
        closed_keys(
            raw,
            &[
                "key",
                "scenario",
                "steps",
                "control",
                "expected_file_a_hex",
                "expected_file_b_hex",
                "mutation_hex",
                "driver_schedule",
            ],
            "invocation",
        )?;
        let scenario = Scenario::parse(raw["scenario"].as_str().unwrap_or(""))
            .ok_or_else(|| ManifestError::new("unknown scenario"))?;
        let steps = raw["steps"]
            .as_array()
            .ok_or_else(|| ManifestError::new("steps must be an array"))?;
        let script = scenario.steps();
        if steps.len() != script.len() {
            return Err(ManifestError::new("steps must equal the exact scenario script"));
        }
        for (got, want) in steps.iter().zip(script.iter()) {
            closed_keys(got, &["id", "action", "actor"], "step")?;
            if got["id"] != want.id
                || got["action"] != want.action.as_str()
                || got["actor"] != want.actor.as_str()
            {
                return Err(ManifestError::new("steps must equal the exact scenario script"));
            }
        }
        let key = &raw["key"];
        closed_keys(
            key,
            &["run_id", "case_key", "attempt", "operation_id"],
            "invocation key",
        )?;
        if key["run_id"] != run_hex {
            return Err(ManifestError::new("invocation run must equal manifest"));
        }
        let case_key = &key["case_key"];
        closed_keys(case_key, &["case_id", "case_version", "cell_id"], "case key")?;
        match case_key["case_id"].as_str() {
            Some(s) if !s.is_empty() && s.len() <= 96 && s.is_ascii() => {}
            _ => return Err(ManifestError::new("case_id must be ASCII 1..96")),
        }
        match case_key["case_version"].as_u64() {
            Some(n) if n >= 1 => {}
            _ => return Err(ManifestError::new("case_version must be positive")),
        }
        match case_key["cell_id"].as_str() {
            Some(s) if !s.is_empty() && s.len() <= 65536 => {}
            _ => return Err(ManifestError::new("cell_id must be nonempty")),
        }
        match key["attempt"].as_u64() {
            Some(n) if n >= 1 => {}
            _ => return Err(ManifestError::new("attempt must be positive")),
        }
        let operation_id = key["operation_id"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n >= 1 && key["operation_id"].as_str().unwrap() == n.to_string())
            .ok_or_else(|| ManifestError::new("operation_id must be canonical positive decimal"))?;
        if !seen_ops.insert(operation_id) {
            return Err(ManifestError::new("duplicate operation id"));
        }
        let control = if raw["control"].is_null() {
            None
        } else {
            let c = &raw["control"];
            closed_keys(c, &["kind", "step_id", "point"], "control")?;
            let kind = c["kind"].as_str().unwrap_or("");
            let step_id = c["step_id"].as_str().unwrap_or("");
            let point = c["point"].as_str().unwrap_or("");
            let step = script
                .iter()
                .find(|s| s.id == step_id)
                .ok_or_else(|| ManifestError::new("control step must be in script"))?;
            if !control_applies(kind, step, point, scenario) {
                return Err(ManifestError::new("control pairing is not applicable"));
            }
            Some(Control {
                kind: kind.to_string(),
                step_id: step_id.to_string(),
                point: point.to_string(),
            })
        };
        let expected_file_a_hex = decode_hex_field(&raw["expected_file_a_hex"], "expected_file_a_hex")?;
        let expected_file_b_hex = decode_hex_field(&raw["expected_file_b_hex"], "expected_file_b_hex")?;
        let mutation_hex = decode_hex_field(&raw["mutation_hex"], "mutation_hex")?;
        let driver_schedule = if raw["driver_schedule"].is_null() {
            None
        } else {
            let s = &raw["driver_schedule"];
            closed_keys(
                s,
                &[
                    "kind",
                    "scenario",
                    "step_id",
                    "execution_ms",
                    "maximum_hold_ms",
                    "fixed_outer_ms",
                ],
                "driver schedule",
            )?;
            if s["kind"] != "runner_deadline_after_ack" {
                return Err(ManifestError::new("driver schedule kind"));
            }
            Some(serde_json::to_vec(s).unwrap())
        };
        let key_bytes = serde_json::to_vec(key).unwrap();
        if key_bytes.len() > 16384 {
            return Err(ManifestError::new("invocation key exceeds 16384"));
        }
        invocations.push(AdmittedInvocation {
            operation_id,
            scenario,
            key_bytes,
            control,
            expected_file_a_hex,
            expected_file_b_hex,
            mutation_hex,
            driver_schedule,
        });
    }
    Ok(AdmittedManifest {
        run_hex,
        image_a_artifact: value["image_a_artifact"].as_str().unwrap().to_string(),
        image_b_artifact: value["image_b_artifact"].as_str().unwrap().to_string(),
        limits,
        invocations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_for(scenario: &str, control: serde_json::Value) -> Vec<u8> {
        let run_hex = "ab".repeat(16);
        let steps: Vec<serde_json::Value> = Scenario::parse(scenario)
            .unwrap()
            .steps()
            .iter()
            .map(|s| {
                serde_json::json!({"id": s.id, "action": s.action.as_str(), "actor": s.actor.as_str()})
            })
            .collect();
        serde_json::json!({
            "schema_version": 1,
            "kind": "tt03-linux-fixture",
            "run_id": run_hex,
            "image_a_artifact": "a",
            "image_b_artifact": "b",
            "limits": {"datagrams": 568},
            "invocations": [{
                "key": {
                    "run_id": run_hex,
                    "case_key": {"case_id": "TT03.x", "case_version": 1, "cell_id": "host"},
                    "attempt": 1,
                    "operation_id": "3",
                },
                "scenario": scenario,
                "steps": steps,
                "control": control,
                "expected_file_a_hex": null,
                "expected_file_b_hex": null,
                "mutation_hex": null,
                "driver_schedule": null,
            }],
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn admits_all_scenarios_with_null_control() {
        for s in [
            "leader-lifecycle",
            "tricky-comm",
            "exec-aba",
            "exec-failure",
            "thread-lifecycle",
            "file-replacement",
            "descriptor-inventory",
        ] {
            let m = admit_manifest(&manifest_for(s, serde_json::Value::Null), &"ab".repeat(16))
                .unwrap();
            assert_eq!(m.invocations.len(), 1);
            assert_eq!(m.invocations[0].operation_id, 3);
        }
        assert_eq!(Scenario::LeaderLifecycle.prepare_prefix_len(), 1);
        assert_eq!(Scenario::TrickyComm.prepare_prefix_len(), 2);
        assert_eq!(Scenario::FileReplacement.prepare_prefix_len(), 3);
        assert_eq!(Scenario::ExecAba.successful_execs(), 2);
    }

    #[test]
    fn refuses_shape_mutants() {
        let run = "ab".repeat(16);
        let good = manifest_for("leader-lifecycle", serde_json::Value::Null);
        assert!(admit_manifest(&good, &run).is_ok());
        assert!(admit_manifest(b"nope", &run).is_err());
        assert!(admit_manifest(&good, &"00".repeat(16)).is_err());
        let mut v: serde_json::Value = serde_json::from_slice(&good).unwrap();
        v["invocations"][0]["steps"][1]["id"] = serde_json::json!("s02-WRONG");
        assert!(admit_manifest(&serde_json::to_vec(&v).unwrap(), &run).is_err());
        let mut v: serde_json::Value = serde_json::from_slice(&good).unwrap();
        v["invocations"][0]["key"]["operation_id"] = serde_json::json!("03");
        assert!(admit_manifest(&serde_json::to_vec(&v).unwrap(), &run).is_err());
        let mut v: serde_json::Value = serde_json::from_slice(&good).unwrap();
        v["schema_version"] = serde_json::json!(2);
        assert!(admit_manifest(&serde_json::to_vec(&v).unwrap(), &run).is_err());
    }

    #[test]
    fn control_pairings() {
        let run = "ab".repeat(16);
        let yes = |scenario: &str, kind: &str, step: &str, point: &str| {
            admit_manifest(
                &manifest_for(
                    scenario,
                    serde_json::json!({"kind": kind, "step_id": step, "point": point}),
                ),
                &run,
            )
            .unwrap();
        };
        let no = |scenario: &str, kind: &str, step: &str, point: &str| {
            assert!(
                admit_manifest(
                    &manifest_for(
                        scenario,
                        serde_json::json!({"kind": kind, "step_id": step, "point": point}),
                    ),
                    &run,
                )
                .is_err(),
                "{kind} at {step}/{point} must not apply"
            );
        };
        yes("leader-lifecycle", "cancel_before_create", "s01-ready", "before_first_creation");
        yes("leader-lifecycle", "wrong_run", "s01-ready", "before_ack");
        yes("leader-lifecycle", "cancel_after_ack", "s02-live", "immediately_after_ack");
        yes("file-replacement", "partial_file_write", "s08-mutate", "before_ack");
        yes("descriptor-inventory", "inherit_canary", "s04-inventory", "before_inventory_exec");
        yes("file-replacement", "worker_exit", "s02-create-files", "after_file_register");
        yes("leader-lifecycle", "worker_exit", "s01-ready", "after_root_grant");
        yes("exec-aba", "worker_exit", "s01-ready", "after_root_grant");
        yes(
            "leader-lifecycle",
            "parent_failure_after_register",
            "s01-ready",
            "after_case_root_register",
        );
        yes(
            "leader-lifecycle",
            "parent_failure_after_register",
            "s01-ready",
            "after_child_register",
        );
        yes(
            "leader-lifecycle",
            "parent_failure_after_register",
            "s01-ready",
            "after_pidfd_register",
        );
        no("leader-lifecycle", "partial_file_write", "s01-ready", "before_ack");
        no("leader-lifecycle", "inherit_canary", "s01-ready", "before_ack");
        no("leader-lifecycle", "cancel_after_ack", "s03-exit", "immediately_after_ack");
        no("leader-lifecycle", "bogus_kind", "s01-ready", "before_ack");
        no("leader-lifecycle", "wrong_run", "s02-live", "before_ack");
        no("leader-lifecycle", "worker_exit", "s02-live", "after_root_grant");
        no("leader-lifecycle", "worker_exit", "s01-ready", "after_file_register");
        no(
            "file-replacement",
            "parent_failure_after_register",
            "s02-create-files",
            "after_child_register",
        );
        no("exec-failure", "partial_file_write", "s03-missing", "before_ack");
    }

    #[test]
    fn public_pairing_check_matches_admission() {
        assert!(control_pairing_applies(
            "worker_exit",
            "s01-ready",
            "after_root_grant",
            Scenario::LeaderLifecycle
        ));
        assert!(control_pairing_applies(
            "parent_failure_after_register",
            "s01-ready",
            "after_pidfd_register",
            Scenario::ExecAba
        ));
        assert!(control_pairing_applies(
            "partial_file_write",
            "s08-mutate",
            "before_ack",
            Scenario::FileReplacement
        ));
        assert!(!control_pairing_applies(
            "partial_file_write",
            "s08-mutate",
            "before_ack",
            Scenario::LeaderLifecycle
        ));
        assert!(!control_pairing_applies(
            "worker_exit",
            "s99-nope",
            "after_root_grant",
            Scenario::LeaderLifecycle
        ));
        assert!(!control_pairing_applies(
            "bogus_kind",
            "s01-ready",
            "before_ack",
            Scenario::LeaderLifecycle
        ));
    }
}
