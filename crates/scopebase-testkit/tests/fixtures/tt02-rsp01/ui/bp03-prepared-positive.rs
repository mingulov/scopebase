// SPDX-License-Identifier: Apache-2.0
//! UI fixture: valid prepared-only BP03 use. EXPECT: PASS (compiles).
//!
//! The strict adapter admits a response through `prepare_response` and
//! consumes the opaque call exactly once through
//! `PreparedExecution::execute`. The call borrows the exact adapter and the
//! exact invocation; both stay alive for the whole call.

use scopebase_testkit::bpf::{BpfHostAdapter, BpfPreparedCall};
use scopebase_testkit::{
    BindingProvenance, CaseInvocation, CaseInvocationValues, ConsumerBinding,
    ConsumerBindingValues, Digest256, EffectBatch, FixtureAccess, FixtureInput, InvocationKey,
    InvocationKeyValues, Label, OperationScript, PreparedExecution, ResponsePreparedAdapter,
    RunLimits, SchemaBinding, SchemaBindingValues, SubjectBinding, SubjectBindingValues,
};
use scopebase_testkit::{CaseId, CaseKey, CaseKeyValues, RunId};

fn label(s: &str) -> Label {
    Label::parse(s).unwrap()
}

fn main() {
    let l = RunLimits::default();
    let d = Digest256::of_bytes(b"bp03 ui positive");
    let subject = SubjectBinding::new(
        SubjectBindingValues {
            package_name: "scopebase-bpf".into(),
            package_version: "0.1.0".into(),
            source_sha256: d,
            build_inputs_sha256: d,
            features: vec![],
            backend: None,
            host: "x".into(),
            target: "x".into(),
            consumer: ConsumerBinding::new(
                ConsumerBindingValues {
                    name: "ui".into(),
                    build_inputs_sha256: d,
                    executable_sha256: d,
                },
                &l,
            )
            .unwrap(),
            objects: vec![],
            provenance: BindingProvenance::SelfReported {
                reason: "ui".into(),
            },
        },
        &l,
    )
    .unwrap();
    let mut adapter = BpfHostAdapter::new(
        subject,
        scopebase_bpf::Limits {
            input_bytes: 131072,
            retained_bytes: 262144,
            work_steps: 8388608,
            sites: 0,
            live_links: 0,
            pending_retirements: 0,
        },
        l.clone(),
    )
    .unwrap();
    let script = serde_json::json!({"schema_version":1,"kind":"steps-v1","schema_id":"bp03-host-v1","steps":[{"step_id":"only-step","operation":"assess-filter","inputs":["counts"],"parameters":[]}]});
    let invocation = CaseInvocation::new(
        CaseInvocationValues {
            key: InvocationKey::new(
                InvocationKeyValues {
                    run_id: RunId::parse("0123456789abcdef0123456789abcdef").unwrap(),
                    case_key: CaseKey::new(
                        CaseKeyValues {
                            case_id: CaseId::parse("H22.model-filter").unwrap(),
                            case_version: 1,
                            cell_id: "model".into(),
                        },
                        &l,
                    )
                    .unwrap(),
                    attempt: 1,
                    operation_id: 1,
                },
                &l,
            )
            .unwrap(),
            observation_schema: SchemaBinding::new(
                SchemaBindingValues {
                    id: label("bp03-model-result"),
                    revision: 1,
                },
                &l,
            )
            .unwrap(),
            fixture_schema: SchemaBinding::new(
                SchemaBindingValues {
                    id: label("bp03-fixed-input"),
                    revision: 1,
                },
                &l,
            )
            .unwrap(),
            script: OperationScript::load(&serde_json::to_vec(&script).unwrap(), &l).unwrap(),
            limits: l.clone(),
        },
        &l,
    )
    .unwrap();
    let refs = [FixtureInput::new(label("counts"), b"2\n2\n1\n0\n")];
    let fixture = FixtureAccess::new(&refs, &[], EffectBatch::empty(&l), &l).unwrap();
    let call: BpfPreparedCall<'_> = adapter.prepare_response(&invocation).unwrap();
    let observation = call.execute(&fixture).unwrap();
    assert_eq!(observation.bytes(), b"supported");
}
